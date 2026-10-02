"""Reusable inference wrapper; safely degrades when optional ML is absent."""
from __future__ import annotations
from pathlib import Path
from typing import Mapping, Any
import joblib, pandas as pd

class MLPredictor:
    def __init__(self, model_path="models/ids_rf.joblib"):
        self.path=Path(model_path); self.bundle=joblib.load(self.path) if self.path.exists() else None
    @property
    def enabled(self): return self.bundle is not None
    def predict(self, flow: Mapping[str,Any], features: Mapping[str,float]) -> dict[str,Any] | None:
        if not self.bundle: return None
        values={"packet_count":features["packet_count"],"byte_count":features["byte_count"],"duration_seconds":features["duration"],"bytes_per_second":features["bytes_per_second"],"packets_per_second":features["packets_per_second"],"connection_count":features["connection_count"],"failed_connection_count":features["failed_connection_count"],"syn_count":features["syn_count"],"rst_count":features["rst_count"],"average_packet_size":features["average_packet_size"]}
        X=pd.DataFrame([[values[n] for n in self.bundle["feature_names"]]],columns=self.bundle["feature_names"])
        probability=float(self.bundle["model"].predict_proba(X)[0,1]); threshold=float(self.bundle.get("threshold",.5))
        return {"model_name":self.bundle.get("model_name","classifier"),"probability":round(probability,6),"prediction":"SUSPICIOUS" if probability>=threshold else "NORMAL","threshold":threshold}
