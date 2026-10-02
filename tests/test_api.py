from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from backend.app import create_app

@pytest.fixture
def client(tmp_path):
    root=Path(__file__).resolve().parents[1]
    app=create_app(db_path=tmp_path/"test.db",dataset_path=root/"data/network_traffic.csv",model_path=root/"models/ids_rf.joblib",ml_enabled=True)
    with TestClient(app,raise_server_exceptions=True) as c: yield c
@pytest.fixture
def headers(): return {"X-API-Key":"dev-analyst-key","X-Role":"analyst"}
def payload(fid="API-001"):
    return {"flow_id":fid,"timestamp":"2026-09-29T10:00:00+00:00","source_ip":"192.0.2.15","destination_ip":"198.51.100.20","source_port":49152,"destination_port":443,"protocol":"TCP","packet_count":800,"byte_count":900000,"duration_seconds":2,"connection_count":200,"failed_connection_count":15,"syn_count":100,"rst_count":3,"unique_destination_ports":30,"unique_destination_ips":10,"scenario_type":"HIGH_CONNECTION_RATE"}
def test_35_health_endpoint(client): assert client.get("/health").json()["mode"]=="defensive-synthetic-only"
def test_36_api_authentication_required(client): assert client.get("/api/flows").status_code==401
def test_37_post_flow_and_alert(client,headers):
    r=client.post("/api/flows",json=payload(),headers=headers); assert r.status_code==201 and r.json()["alert"]
def test_38_duplicate_event_handling(client,headers):
    client.post("/api/flows",json=payload("DUP-1"),headers=headers); assert client.post("/api/flows",json=payload("DUP-1"),headers=headers).status_code==409
def test_39_api_validation(client,headers):
    bad=payload("BAD-1"); bad["source_port"]=70000; assert client.post("/api/flows",json=bad,headers=headers).status_code==422
def create_alert(client,headers,fid="ALERT-1"):
    return client.post("/api/flows",json=payload(fid),headers=headers).json()["alert"]["alert_id"]
def test_40_database_storage(client,headers):
    client.post("/api/flows",json=payload("STORE-1"),headers=headers); assert client.get("/api/flows/STORE-1",headers=headers).status_code==200
def test_41_dashboard_statistics(client,headers):
    client.post("/api/flows",json=payload("STAT-1"),headers=headers); stats=client.get("/api/dashboard/stats",headers=headers).json(); assert stats["total"]==1 and stats["open_alerts"]==1
def test_42_alert_status_update(client,headers):
    aid=create_alert(client,headers,"STATUS-1"); r=client.put(f"/api/alerts/{aid}/status",json={"status":"INVESTIGATING"},headers=headers); assert r.json()["status"]=="INVESTIGATING" and r.json()["investigation_timestamp"]
def test_43_analyst_note(client,headers):
    aid=create_alert(client,headers,"NOTE-1"); r=client.post(f"/api/alerts/{aid}/notes",json={"note":"Reviewed authorized firewall logs."},headers=headers); assert r.status_code==201 and "firewall" in r.json()["note"]
def test_44_viewer_cannot_modify(client,headers):
    aid=create_alert(client,headers,"VIEW-1"); viewer={**headers,"X-Role":"viewer"}; assert client.put(f"/api/alerts/{aid}/status",json={"status":"RESOLVED"},headers=viewer).status_code==403
def test_45_rules_list_and_update(client,headers):
    assert len(client.get("/api/rules",headers=headers).json()["items"])==7; r=client.put("/api/rules/IDS-001",json={"threshold":30},headers=headers); assert r.json()["threshold"]==30
def test_46_alert_filters(client,headers):
    create_alert(client,headers,"FILTER-1"); data=client.get("/api/alerts?severity=CRITICAL",headers=headers).json()["items"]; assert all(a["severity"]=="CRITICAL" for a in data)
def test_47_alert_detail_has_context(client,headers):
    aid=create_alert(client,headers,"DETAIL-1"); detail=client.get(f"/api/alerts/{aid}",headers=headers).json(); assert detail["flow"]["flow_id"]=="DETAIL-1" and "recommended_steps" in detail and detail["timeline"][0]["event"]=="Alert created"
def test_48_alert_correlation_api(client,headers):
    create_alert(client,headers,"INC-1"); data=client.get("/api/incidents",headers=headers).json(); assert data["items"]
def test_49_dashboard_chart_endpoints(client,headers):
    client.post("/api/flows",json=payload("CHART-1"),headers=headers); assert "timeline" in client.get("/api/dashboard/traffic",headers=headers).json() and "severity_distribution" in client.get("/api/dashboard/alerts",headers=headers).json()
def test_50_ml_prediction(client,headers):
    result=client.post("/api/flows",json=payload("ML-1"),headers=headers).json(); assert (result["ml"] is None) or (0<=result["ml"]["probability"]<=1)
def test_51_invalid_terminal_transition(client,headers):
    aid=create_alert(client,headers,"TRANS-1"); client.put(f"/api/alerts/{aid}/status",json={"status":"RESOLVED"},headers=headers); assert client.put(f"/api/alerts/{aid}/status",json={"status":"INVESTIGATING"},headers=headers).status_code==409
def test_52_score_compatibility_endpoint(client,headers): assert client.post("/score",json=payload("SCORE-1"),headers=headers).status_code==201
