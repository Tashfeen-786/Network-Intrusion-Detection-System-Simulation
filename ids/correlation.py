"""Basic alert-to-incident grouping by source, type and time window."""
from __future__ import annotations
from datetime import datetime
from typing import Iterable, Mapping, Any

def _epoch(value: Any) -> float:
    if isinstance(value,(int,float)): return float(value)
    return datetime.fromisoformat(str(value).replace("Z","+00:00")).timestamp()

def correlate_alerts(alerts: Iterable[Mapping[str,Any]], window_seconds: int = 60) -> list[dict[str,Any]]:
    groups: list[dict[str,Any]] = []
    ordered = sorted((dict(a) for a in alerts), key=lambda a:_epoch(a["timestamp"]))
    for alert in ordered:
        ts = _epoch(alert["timestamp"])
        target = next((g for g in reversed(groups) if g["source_ip"]==alert["source_ip"] and g["alert_type"]==alert["alert_type"] and ts-g["last_epoch"]<=window_seconds),None)
        if target is None:
            target={"incident_id":f"INC-{len(groups)+1:05d}","source_ip":alert["source_ip"],"alert_type":alert["alert_type"],"first_seen":alert["timestamp"],"last_seen":alert["timestamp"],"last_epoch":ts,"alert_ids":[],"alert_count":0,"max_risk":0.0,"status":"NEW"}
            groups.append(target)
        target["last_seen"],target["last_epoch"]=alert["timestamp"],ts
        target["alert_ids"].append(alert["alert_id"]); target["alert_count"]+=1
        target["max_risk"]=max(target["max_risk"],float(alert.get("risk_score",0)))
    for group in groups: group.pop("last_epoch",None)
    return groups
