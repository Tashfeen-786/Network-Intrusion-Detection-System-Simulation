"""Thread-safe SQLite repository and schema for flows, alerts, rules, notes and ML results."""
from __future__ import annotations
import json, sqlite3, threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA="""
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS network_flows(
 flow_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source_ip TEXT NOT NULL, destination_ip TEXT NOT NULL,
 source_port INTEGER NOT NULL, destination_port INTEGER NOT NULL, protocol TEXT NOT NULL,
 packet_count REAL NOT NULL, byte_count REAL NOT NULL, duration REAL NOT NULL,
 connection_count REAL NOT NULL, failed_connection_count REAL NOT NULL, syn_count REAL NOT NULL, rst_count REAL NOT NULL,
 average_packet_size REAL NOT NULL, packets_per_second REAL NOT NULL, bytes_per_second REAL NOT NULL,
 risk_score REAL NOT NULL CHECK(risk_score BETWEEN 0 AND 100), classification TEXT NOT NULL,
 scenario_type TEXT, raw_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts(
 alert_id TEXT PRIMARY KEY, flow_id TEXT NOT NULL, rule_id TEXT NOT NULL, alert_type TEXT NOT NULL,
 severity TEXT NOT NULL, description TEXT NOT NULL, risk_score REAL NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
 anomaly_score REAL NOT NULL, ml_score REAL, status TEXT NOT NULL DEFAULT 'NEW',
 source_ip TEXT NOT NULL, destination_ip TEXT NOT NULL, source_port INTEGER NOT NULL, destination_port INTEGER NOT NULL,
 protocol TEXT NOT NULL, matched_rules TEXT NOT NULL, recommended_steps TEXT NOT NULL,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, investigation_timestamp TEXT, resolution_notes TEXT,
 FOREIGN KEY(flow_id) REFERENCES network_flows(flow_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS rules(
 rule_id TEXT PRIMARY KEY, rule_name TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL,
 threshold TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_notes(
 note_id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS model_results(
 result_id INTEGER PRIMARY KEY AUTOINCREMENT, flow_id TEXT NOT NULL, model_name TEXT NOT NULL,
 prediction TEXT NOT NULL, score REAL NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(flow_id) REFERENCES network_flows(flow_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS audit_logs(
 audit_id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, entity_id TEXT,
 detail TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON network_flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_flows_source ON network_flows(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_status_created ON alerts(status,created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_source_type ON alerts(source_ip,alert_type);
CREATE INDEX IF NOT EXISTS idx_notes_alert ON incident_notes(alert_id,created_at);
CREATE INDEX IF NOT EXISTS idx_model_flow ON model_results(flow_id);
"""

class Database:
    def __init__(self,path="data/ids.db"):
        self.path=str(path); Path(self.path).parent.mkdir(parents=True,exist_ok=True); self.lock=threading.RLock(); self.initialize()
    def connect(self):
        conn=sqlite3.connect(self.path,check_same_thread=False,timeout=15); conn.row_factory=sqlite3.Row; conn.execute("PRAGMA foreign_keys=ON"); return conn
    @contextmanager
    def transaction(self):
        with self.lock:
            conn=self.connect()
            try: yield conn; conn.commit()
            except Exception: conn.rollback(); raise
            finally: conn.close()
    def initialize(self):
        with self.transaction() as c: c.executescript(SCHEMA)
    def execute(self,sql,params=()):
        with self.transaction() as c: return c.execute(sql,params).rowcount
    def one(self,sql,params=()):
        with self.connect() as c:
            row=c.execute(sql,params).fetchone(); return self._decode(row) if row else None
    def all(self,sql,params=()):
        with self.connect() as c: return [self._decode(r) for r in c.execute(sql,params).fetchall()]
    @staticmethod
    def _decode(row):
        d=dict(row)
        for key in ("matched_rules","recommended_steps","raw_json","threshold"):
            if key in d and isinstance(d[key],str):
                try: d[key]=json.loads(d[key])
                except json.JSONDecodeError: pass
        if "enabled" in d: d["enabled"]=bool(d["enabled"])
        return d
    def insert_flow(self,flow,features,risk):
        now=datetime.now(timezone.utc).isoformat()
        values=(flow["flow_id"],flow["timestamp"],flow["source_ip"],flow["destination_ip"],flow["source_port"],flow["destination_port"],flow["protocol"],features["packet_count"],features["byte_count"],features["duration"],features["connection_count"],features["failed_connection_count"],features["syn_count"],features["rst_count"],features["average_packet_size"],features["packets_per_second"],features["bytes_per_second"],risk["risk_score"],risk["classification"],flow.get("scenario_type"),json.dumps(dict(flow),sort_keys=True),now)
        with self.transaction() as c: c.execute("INSERT INTO network_flows VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",values)
    def insert_alert(self,a):
        now=datetime.now(timezone.utc).isoformat()
        with self.transaction() as c: c.execute("""INSERT INTO alerts(alert_id,flow_id,rule_id,alert_type,severity,description,risk_score,anomaly_score,ml_score,status,source_ip,destination_ip,source_port,destination_port,protocol,matched_rules,recommended_steps,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",(a["alert_id"],a["flow_id"],a["rule_id"],a["alert_type"],a["severity"],a["description"],a["risk_score"],a["anomaly_score"],a.get("ml_score"),a["status"],a["source_ip"],a["destination_ip"],a["source_port"],a["destination_port"],a["protocol"],json.dumps(a["matched_rules"]),json.dumps(a["recommended_steps"]),a["timestamp"],now))
    def audit(self,actor,action,entity_id=None,detail=None):
        self.execute("INSERT INTO audit_logs(actor,action,entity_id,detail,created_at) VALUES(?,?,?,?,?)",(actor,action,entity_id,detail,datetime.now(timezone.utc).isoformat()))
