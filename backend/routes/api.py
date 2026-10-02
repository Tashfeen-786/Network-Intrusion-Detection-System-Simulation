"""All version-one REST endpoints documented by the project specification."""
from __future__ import annotations
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from ids.correlation import correlate_alerts
from backend.auth import require_user, require_analyst
from backend.schemas import FlowIn, NoteIn, RuleUpdate, StatusUpdate
from backend.services.ids_service import DuplicateFlowError

router=APIRouter()
def state(request: Request): return request.app.state.ids,request.app.state.db

@router.post("/api/flows",status_code=201)
@router.post("/score",status_code=201,include_in_schema=True)
def create_flow(payload: FlowIn,request:Request,user=Depends(require_user)):
    require_analyst(user); service,db=state(request)
    try: result=service.process(payload.normalized())
    except DuplicateFlowError as exc: raise HTTPException(409,f"duplicate flow_id: {exc}")
    db.audit(user["name"],"CREATE_FLOW",result["flow_id"],result["classification"]); return result

@router.get("/api/flows")
def list_flows(request:Request,protocol:str|None=None,classification:str|None=None,limit:int=Query(100,ge=1,le=1000),offset:int=Query(0,ge=0),user=Depends(require_user)):
    _,db=state(request); where=[]; params=[]
    if protocol: where.append("protocol=?"); params.append(protocol.upper())
    if classification: where.append("classification=?"); params.append(classification.upper())
    sql="SELECT * FROM network_flows"+(" WHERE "+" AND ".join(where) if where else "")+" ORDER BY timestamp DESC LIMIT ? OFFSET ?"; params.extend([limit,offset])
    return {"items":db.all(sql,params),"limit":limit,"offset":offset}

@router.get("/api/flows/{flow_id}")
def get_flow(flow_id:str,request:Request,user=Depends(require_user)):
    _,db=state(request); item=db.one("SELECT * FROM network_flows WHERE flow_id=?",(flow_id,))
    if not item: raise HTTPException(404,"flow not found")
    item["model_results"]=db.all("SELECT * FROM model_results WHERE flow_id=?",(flow_id,)); return item

def _alert_filters(severity,protocol,alert_type,status,time_range):
    where=[]; params=[]
    for column,value in (("severity",severity),("protocol",protocol),("alert_type",alert_type),("status",status)):
        if value: where.append(f"{column}=?"); params.append(value.upper() if column in {"severity","protocol","status"} else value)
    if time_range:
        hours={"1h":1,"24h":24,"7d":168,"30d":720}.get(time_range)
        if hours is None: raise HTTPException(422,"time_range must be 1h, 24h, 7d, or 30d")
        where.append("julianday(created_at) >= julianday('now', ?)"); params.append(f"-{hours} hours")
    return where,params

@router.get("/api/alerts")
def list_alerts(request:Request,severity:str|None=None,protocol:str|None=None,alert_type:str|None=None,status:str|None=None,time_range:str|None=None,limit:int=Query(100,ge=1,le=1000),offset:int=Query(0,ge=0),user=Depends(require_user)):
    _,db=state(request); where,params=_alert_filters(severity,protocol,alert_type,status,time_range); sql="SELECT * FROM alerts"+(" WHERE "+" AND ".join(where) if where else "")+" ORDER BY created_at DESC LIMIT ? OFFSET ?"; params.extend([limit,offset]); return {"items":db.all(sql,params),"limit":limit,"offset":offset}

@router.get("/api/alerts/{alert_id}")
def get_alert(alert_id:str,request:Request,user=Depends(require_user)):
    _,db=state(request); alert=db.one("SELECT * FROM alerts WHERE alert_id=?",(alert_id,))
    if not alert: raise HTTPException(404,"alert not found")
    alert["notes"]=db.all("SELECT * FROM incident_notes WHERE alert_id=? ORDER BY created_at",(alert_id,)); alert["flow"]=db.one("SELECT * FROM network_flows WHERE flow_id=?",(alert["flow_id"],)); alert["model_results"]=db.all("SELECT * FROM model_results WHERE flow_id=?",(alert["flow_id"],))
    timeline=[{"timestamp":alert["created_at"],"event":"Alert created","detail":alert["alert_type"]}]
    if alert.get("investigation_timestamp"): timeline.append({"timestamp":alert["investigation_timestamp"],"event":"Investigation started","detail":"Status changed to INVESTIGATING"})
    timeline.extend({"timestamp":n["created_at"],"event":"Analyst note","detail":n["note"]} for n in alert["notes"])
    if alert["status"] in {"RESOLVED","FALSE_POSITIVE"}: timeline.append({"timestamp":alert["updated_at"],"event":alert["status"].replace("_"," ").title(),"detail":alert.get("resolution_notes") or "Case closed by analyst."})
    alert["timeline"]=sorted(timeline,key=lambda e:e["timestamp"]); return alert

@router.put("/api/alerts/{alert_id}/status")
def update_status(alert_id:str,payload:StatusUpdate,request:Request,user=Depends(require_user)):
    require_analyst(user); _,db=state(request); alert=db.one("SELECT * FROM alerts WHERE alert_id=?",(alert_id,))
    if not alert: raise HTTPException(404,"alert not found")
    allowed={"NEW":{"NEW","INVESTIGATING","RESOLVED","FALSE_POSITIVE"},"INVESTIGATING":{"INVESTIGATING","RESOLVED","FALSE_POSITIVE"},"RESOLVED":{"RESOLVED"},"FALSE_POSITIVE":{"FALSE_POSITIVE"}}
    if payload.status not in allowed[alert["status"]]: raise HTTPException(409,f"invalid transition {alert['status']} -> {payload.status}")
    now=datetime.now(timezone.utc).isoformat(); investigation=now if payload.status=="INVESTIGATING" and not alert.get("investigation_timestamp") else alert.get("investigation_timestamp")
    db.execute("UPDATE alerts SET status=?,updated_at=?,investigation_timestamp=?,resolution_notes=COALESCE(?,resolution_notes) WHERE alert_id=?",(payload.status,now,investigation,payload.resolution_notes,alert_id)); db.audit(user["name"],"UPDATE_ALERT_STATUS",alert_id,payload.status)
    return db.one("SELECT * FROM alerts WHERE alert_id=?",(alert_id,))

@router.post("/api/alerts/{alert_id}/notes",status_code=201)
def add_note(alert_id:str,payload:NoteIn,request:Request,user=Depends(require_user)):
    require_analyst(user); _,db=state(request)
    if not db.one("SELECT alert_id FROM alerts WHERE alert_id=?",(alert_id,)): raise HTTPException(404,"alert not found")
    now=datetime.now(timezone.utc).isoformat(); clean=payload.note.strip(); db.execute("INSERT INTO incident_notes(alert_id,note,created_at) VALUES(?,?,?)",(alert_id,clean,now))
    note=db.one("SELECT * FROM incident_notes WHERE alert_id=? ORDER BY note_id DESC LIMIT 1",(alert_id,)); db.audit(user["name"],"ADD_NOTE",alert_id); return note

@router.get("/api/incidents")
def incidents(request:Request,window_seconds:int=Query(60,ge=1,le=86400),user=Depends(require_user)):
    _,db=state(request); alerts=db.all("SELECT * FROM alerts ORDER BY created_at");
    for a in alerts: a["timestamp"]=a["created_at"]
    return {"items":correlate_alerts(alerts,window_seconds)}

@router.get("/api/dashboard/stats")
@router.get("/stats")
def dashboard_stats(request:Request,user=Depends(require_user)):
    _,db=state(request)
    flows=db.one("SELECT COUNT(*) total,SUM(CASE WHEN classification='NORMAL' THEN 1 ELSE 0 END) normal,SUM(CASE WHEN classification<>'NORMAL' THEN 1 ELSE 0 END) suspicious,AVG(risk_score) average_risk FROM network_flows")
    alerts=db.one("SELECT SUM(CASE WHEN status IN ('NEW','INVESTIGATING') THEN 1 ELSE 0 END) open_alerts,SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) critical_alerts,COUNT(*) total_alerts FROM alerts")
    return {**{k:(round(v,2) if isinstance(v,float) else (v or 0)) for k,v in flows.items()},**{k:(v or 0) for k,v in alerts.items()},"ml_enabled":request.app.state.ids.ml.enabled}

@router.get("/api/dashboard/traffic")
def dashboard_traffic(request:Request,user=Depends(require_user)):
    _,db=state(request)
    timeline=db.all("SELECT substr(timestamp,1,16) bucket,COUNT(*) flows,SUM(packets_per_second) packets_per_second,SUM(bytes_per_second) bytes_per_second,SUM(connection_count) connections,SUM(failed_connection_count) failed_connections,AVG(risk_score) average_risk FROM network_flows GROUP BY bucket ORDER BY bucket DESC LIMIT 60")
    protocols=db.all("SELECT protocol label,COUNT(*) value FROM network_flows GROUP BY protocol ORDER BY value DESC"); ports=db.all("SELECT destination_port label,COUNT(*) value FROM network_flows GROUP BY destination_port ORDER BY value DESC LIMIT 12"); classification=db.all("SELECT classification label,COUNT(*) value FROM network_flows GROUP BY classification")
    return {"timeline":list(reversed(timeline)),"protocol_distribution":protocols,"port_distribution":ports,"classification_distribution":classification}

@router.get("/api/dashboard/alerts")
def dashboard_alerts(request:Request,user=Depends(require_user)):
    _,db=state(request)
    return {"severity_distribution":db.all("SELECT severity label,COUNT(*) value FROM alerts GROUP BY severity"),"top_alert_types":db.all("SELECT alert_type label,COUNT(*) value FROM alerts GROUP BY alert_type ORDER BY value DESC LIMIT 10"),"top_sources":db.all("SELECT source_ip label,COUNT(*) value FROM alerts GROUP BY source_ip ORDER BY value DESC LIMIT 10"),"risk_distribution":db.all("SELECT CASE WHEN risk_score<=20 THEN '0-20' WHEN risk_score<=40 THEN '21-40' WHEN risk_score<=60 THEN '41-60' WHEN risk_score<=80 THEN '61-80' ELSE '81-100' END label,COUNT(*) value FROM alerts GROUP BY label"),"timeline":db.all("SELECT substr(created_at,1,16) bucket,COUNT(*) alerts,AVG(risk_score) average_risk FROM alerts GROUP BY bucket ORDER BY bucket DESC LIMIT 60")}

@router.get("/api/rules")
def rules(request:Request,user=Depends(require_user)): return {"items":state(request)[1].all("SELECT * FROM rules ORDER BY rule_id")}
@router.put("/api/rules/{rule_id}")
def update_rule(rule_id:str,payload:RuleUpdate,request:Request,user=Depends(require_user)):
    require_analyst(user); service,db=state(request)
    try: result=service.update_rule(rule_id,payload.model_dump())
    except KeyError: raise HTTPException(404,"rule not found")
    except ValueError as exc: raise HTTPException(422,str(exc))
    db.audit(user["name"],"UPDATE_RULE",rule_id); return result
