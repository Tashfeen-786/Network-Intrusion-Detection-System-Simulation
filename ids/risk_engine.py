"""Configurable hybrid risk scoring."""
from __future__ import annotations
from typing import Mapping, Any

SEVERITY_RULE_SCORE = {"INFO":10,"LOW":25,"MEDIUM":50,"HIGH":75,"CRITICAL":95}

def classification_for(score: float) -> str:
    if score <= 20: return "NORMAL"
    if score <= 40: return "LOW RISK"
    if score <= 60: return "SUSPICIOUS"
    if score <= 80: return "HIGH RISK"
    return "CRITICAL INVESTIGATION"

def severity_for(score: float) -> str:
    if score <= 20: return "INFO"
    if score <= 40: return "LOW"
    if score <= 60: return "MEDIUM"
    if score <= 80: return "HIGH"
    return "CRITICAL"

def calculate_rule_risk(matches: list[Mapping[str, Any]]) -> float:
    if not matches: return 0.0
    maximum = max(SEVERITY_RULE_SCORE.get(str(m.get("severity","INFO")),10) for m in matches)
    return min(100.0, maximum + 4.0*(len(matches)-1))

def calculate_risk_score(rule_risk: float, anomaly_score: float, ml_probability: float | None = None, weights: Mapping[str,float] | None = None) -> dict[str, Any]:
    values = {"rule":max(0,min(100,float(rule_risk))),"anomaly":max(0,min(100,float(anomaly_score)))}
    if ml_probability is None:
        w = dict(weights or {"rule":0.60,"anomaly":0.40})
    else:
        values["ml"] = max(0,min(100,float(ml_probability)*100 if float(ml_probability)<=1 else float(ml_probability)))
        w = dict(weights or {"rule":0.40,"anomaly":0.30,"ml":0.30})
    if set(w) != set(values) or abs(sum(w.values())-1.0) > 1e-6 or any(v < 0 for v in w.values()):
        raise ValueError("weights must match enabled detectors, be non-negative, and sum to 1")
    score = round(sum(values[k]*w[k] for k in values),2)
    return {"risk_score":score,"classification":classification_for(score),"severity":severity_for(score),"components":values,"weights":w}
