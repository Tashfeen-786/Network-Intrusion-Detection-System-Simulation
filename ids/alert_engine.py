"""SOC-style alert construction."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Mapping, Any
from uuid import uuid4

ALERT_STATUSES = {"NEW","INVESTIGATING","RESOLVED","FALSE_POSITIVE"}

def generate_alert(flow: Mapping[str,Any], risk: Mapping[str,Any], rule_matches: list[Mapping[str,Any]], anomaly_score: float, ml_score: float | None = None) -> dict[str,Any]:
    primary = rule_matches[0] if rule_matches else None
    alert_type = primary["name"] if primary else "Statistical Anomaly"
    description = primary["description"] if primary else "Flow behavior deviated from the learned normal synthetic baseline."
    return {
        "alert_id":f"ALT-{uuid4().hex[:10].upper()}",
        "flow_id":flow.get("flow_id"),
        "timestamp":flow.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "source_ip":flow["source_ip"],"destination_ip":flow["destination_ip"],
        "protocol":flow["protocol"],"source_port":int(flow["source_port"]),"destination_port":int(flow["destination_port"]),
        "rule_id":primary["rule_id"] if primary else "ANOMALY",
        "alert_type":alert_type,"severity":risk["severity"],"risk_score":risk["risk_score"],
        "description":description,"status":"NEW","anomaly_score":anomaly_score,"ml_score":ml_score,
        "matched_rules":[m["rule_id"] for m in rule_matches],
        "recommended_steps":["Review related network and application logs.","Confirm whether the source and destination are known assets.","Compare the activity with the historical baseline.","Review authorized firewall, authentication, and endpoint telemetry.","Determine whether the activity is expected before escalation."],
    }
