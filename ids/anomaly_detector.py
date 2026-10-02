"""Transparent statistical anomaly detector using Z-score, IQR and moving means."""
from __future__ import annotations
from collections import deque
from typing import Iterable, Mapping, Any
import math
import statistics

ANOMALY_FEATURES = (
    "packets_per_second", "bytes_per_second", "connection_rate",
    "failure_ratio", "unique_destination_ports",
)

class StatisticalAnomalyDetector:
    def __init__(self, history_size: int = 100):
        self.baseline: dict[str, dict[str, float]] = {}
        self.history = {name: deque(maxlen=history_size) for name in ANOMALY_FEATURES}

    def fit(self, feature_rows: Iterable[Mapping[str, float]]) -> "StatisticalAnomalyDetector":
        rows = list(feature_rows)
        if not rows:
            raise ValueError("cannot create baseline from an empty dataset")
        for name in ANOMALY_FEATURES:
            values = sorted(float(row.get(name, 0.0)) for row in rows)
            mean = statistics.fmean(values)
            std = statistics.pstdev(values) or max(abs(mean) * 0.05, 0.001)
            n = len(values)
            q1 = values[int((n - 1) * 0.25)]
            q3 = values[int((n - 1) * 0.75)]
            self.baseline[name] = {"mean":mean,"std":std,"q1":q1,"q3":q3,"iqr":max(q3-q1,0.001)}
            self.history[name].extend(values[-self.history[name].maxlen:])
        return self

    def calculate_anomaly_score(self, features: Mapping[str, float], update_history: bool = False) -> tuple[float, dict[str, Any]]:
        if not self.baseline:
            raise RuntimeError("anomaly detector has not been fitted")
        components, explanations = [], {}
        for name in ANOMALY_FEATURES:
            value = float(features.get(name, 0.0))
            b = self.baseline[name]
            z = abs(value - b["mean"]) / b["std"]
            lower, upper = b["q1"] - 1.5*b["iqr"], b["q3"] + 1.5*b["iqr"]
            iqr_distance = 0.0 if lower <= value <= upper else min(abs(value-(upper if value>upper else lower))/b["iqr"], 10.0)
            moving_mean = statistics.fmean(self.history[name]) if self.history[name] else b["mean"]
            moving_z = abs(value-moving_mean)/b["std"]
            component = min(100.0, (0.55*z + 0.25*iqr_distance + 0.20*moving_z) * 14.0)
            components.append(component)
            explanations[name] = {"value":round(value,4),"z_score":round(z,3),"iqr_distance":round(iqr_distance,3),"component":round(component,2)}
            if update_history:
                self.history[name].append(value)
        # Emphasize the strongest deviations while retaining multi-feature context.
        ordered = sorted(components, reverse=True)
        score = min(100.0, 0.60*ordered[0] + 0.25*ordered[1] + 0.15*statistics.fmean(components))
        return round(score, 2), explanations


def calculate_anomaly_score(features: Mapping[str, float], baseline_rows: Iterable[Mapping[str, float]]) -> float:
    return StatisticalAnomalyDetector().fit(baseline_rows).calculate_anomaly_score(features)[0]
