"""Orchestrates validation, feature extraction, hybrid detection, persistence and alerting."""
from __future__ import annotations
import csv, json, sqlite3
from pathlib import Path
from uuid import uuid4
from ids.feature_extractor import extract_network_features, validate_flow
from ids.rule_engine import RuleEngine, DEFAULT_RULES
from ids.anomaly_detector import StatisticalAnomalyDetector
from ids.risk_engine import calculate_rule_risk, calculate_risk_score
from ids.alert_engine import generate_alert
from ml.predict import MLPredictor

class DuplicateFlowError(ValueError): pass

def configured_weights(ml_enabled: bool):
    """Read optional comma-separated weights while preserving the documented defaults."""
    import os
    key = "HYBRID_WEIGHTS_ML" if ml_enabled else "HYBRID_WEIGHTS_NO_ML"
    default = "0.40,0.30,0.30" if ml_enabled else "0.60,0.40"
    values = [float(v.strip()) for v in os.getenv(key, default).split(",")]
    names = ["rule", "anomaly", "ml"] if ml_enabled else ["rule", "anomaly"]
    if len(values) != len(names):
        raise ValueError(f"{key} must contain {len(names)} comma-separated weights")
    return dict(zip(names, values))

class IDSService:
    def __init__(self,db,dataset_path="data/network_traffic.csv",model_path="models/ids_rf.joblib",ml_enabled=True):
        self.db=db; self.rule_engine=RuleEngine(); self._seed_rules(); self._load_rules(); self.anomaly=StatisticalAnomalyDetector().fit(self._baseline(dataset_path)); self.ml=MLPredictor(model_path) if ml_enabled else MLPredictor("__disabled__")
    def _seed_rules(self):
        from datetime import datetime,timezone
        with self.db.transaction() as c:
            for r in DEFAULT_RULES:
                c.execute("INSERT OR IGNORE INTO rules VALUES(?,?,?,?,?,?,?)",(r["rule_id"],r["name"],r["description"],r["severity"],json.dumps(r["threshold"]),int(r["enabled"]),datetime.now(timezone.utc).isoformat()))
    def _load_rules(self):
        stored={r["rule_id"]:r for r in self.db.all("SELECT * FROM rules")}
        for r in self.rule_engine.rules:
            if r["rule_id"] in stored:
                s=stored[r["rule_id"]]; r["threshold"],r["enabled"],r["severity"]=s["threshold"],s["enabled"],s["severity"]
    def _baseline(self,path):
        rows=[]; p=Path(path)
        if p.exists():
            with p.open(encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    if row.get("label")=="NORMAL":
                        row.update(unique_destination_ports=1,unique_destination_ips=1)
                        try: rows.append(extract_network_features(row))
                        except ValueError: pass
                        if len(rows)>=2000: break
        if not rows:
            base={"source_ip":"192.0.2.10","destination_ip":"198.51.100.20","source_port":50000,"destination_port":443,"protocol":"TCP","packet_count":40,"byte_count":30000,"duration_seconds":4,"connection_count":3,"failed_connection_count":0,"syn_count":2,"rst_count":0,"unique_destination_ports":1,"unique_destination_ips":1}
            for i in range(40):
                item={**base,"packet_count":35+i%12,"byte_count":25000+i*120,"duration_seconds":3+i%5,"connection_count":2+i%4}; rows.append(extract_network_features(item))
        return rows
    def process(self,input_flow):
        flow=validate_flow(input_flow); flow["flow_id"]=flow.get("flow_id") or "FLOW-"+uuid4().hex[:12].upper()
        if self.db.one("SELECT flow_id FROM network_flows WHERE flow_id=?",(flow["flow_id"],)): raise DuplicateFlowError(flow["flow_id"])
        features=extract_network_features(flow); matches=self.rule_engine.analyze_flow(flow,features); anomaly,details=self.anomaly.calculate_anomaly_score(features,update_history=not matches)
        prediction=self.ml.predict(flow,features); ml_probability=prediction["probability"] if prediction else None
        risk=calculate_risk_score(calculate_rule_risk(matches),anomaly,ml_probability,configured_weights(prediction is not None))
        try: self.db.insert_flow(flow,features,risk)
        except sqlite3.IntegrityError as exc: raise DuplicateFlowError(flow["flow_id"]) from exc
        if prediction:
            from datetime import datetime,timezone
            self.db.execute("INSERT INTO model_results(flow_id,model_name,prediction,score,created_at) VALUES(?,?,?,?,?)",(flow["flow_id"],prediction["model_name"],prediction["prediction"],prediction["probability"],datetime.now(timezone.utc).isoformat()))
        alert=None
        if matches or risk["risk_score"]>40:
            alert=generate_alert(flow,risk,matches,anomaly,ml_probability); self.db.insert_alert(alert)
        return {"flow_id":flow["flow_id"],"classification":risk["classification"],"severity":risk["severity"],"risk_score":risk["risk_score"],"features":features,"rule_matches":matches,"anomaly_score":anomaly,"anomaly_details":details,"ml":prediction,"alert":alert}
    def update_rule(self,rule_id,changes):
        result=self.rule_engine.update_rule(rule_id,{k:v for k,v in changes.items() if v is not None})
        import json; from datetime import datetime,timezone
        self.db.execute("UPDATE rules SET severity=?,threshold=?,enabled=?,updated_at=? WHERE rule_id=?",(result["severity"],json.dumps(result["threshold"]),int(result["enabled"]),datetime.now(timezone.utc).isoformat(),rule_id)); return result
