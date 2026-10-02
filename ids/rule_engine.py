"""Configurable and explainable defensive signatures over flow statistics."""
from __future__ import annotations
from copy import deepcopy
from typing import Any, Mapping

DEFAULT_RULES = [
    {"rule_id":"IDS-001","name":"High Connection Rate","severity":"HIGH","description":"Connection rate exceeded the configured baseline.","feature":"connection_rate","operator":">=","threshold":25.0,"enabled":True},
    {"rule_id":"IDS-002","name":"Repeated Failed Connections","severity":"HIGH","description":"Repeated failed connection records require authentication and firewall-log review.","feature":"failed_connection_count","operator":">=","threshold":12.0,"enabled":True},
    {"rule_id":"IDS-003","name":"Multi-Port Probing-Like Pattern","severity":"HIGH","description":"One synthetic source contacted an unusually large number of destination ports.","feature":"unique_destination_ports","operator":">=","threshold":20.0,"enabled":True},
    {"rule_id":"IDS-004","name":"SYN-Heavy Statistical Pattern","severity":"CRITICAL","description":"SYN ratio and SYN count are unusually high for a flow record.","feature":"syn_ratio","operator":">=","threshold":0.75,"secondary_feature":"syn_count","secondary_threshold":40.0,"enabled":True},
    {"rule_id":"IDS-005","name":"Unusual Service-Port Activity","severity":"MEDIUM","description":"Traffic used a service port outside the documented allow-list for this simulation.","feature":"destination_port","operator":"NOT_IN","threshold":[22,25,53,80,110,143,443,465,587,993,995,3306,5432],"enabled":True},
    {"rule_id":"IDS-006","name":"Abnormally High Traffic Volume","severity":"HIGH","description":"Byte volume exceeded the configured per-flow threshold.","feature":"byte_count","operator":">=","threshold":5_000_000.0,"enabled":True},
    {"rule_id":"IDS-007","name":"High DNS Query Rate","severity":"MEDIUM","description":"Synthetic UDP/53 query-rate statistics exceeded the baseline; this is not proof of DNS tunneling.","feature":"dns_query_rate","operator":">=","threshold":40.0,"enabled":True},
]

class RuleEngine:
    def __init__(self, rules: list[dict[str, Any]] | None = None):
        self.rules = deepcopy(rules or DEFAULT_RULES)

    def analyze_flow(self, flow: Mapping[str, Any], features: Mapping[str, float]) -> list[dict[str, Any]]:
        """Return all matching rules; a match is evidence to investigate, not proof."""
        context = {**flow, **features}
        matches: list[dict[str, Any]] = []
        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            value = context.get(rule["feature"], 0)
            threshold = rule["threshold"]
            if rule["operator"] == ">=":
                hit = float(value) >= float(threshold)
            elif rule["operator"] == "NOT_IN":
                hit = int(value) not in set(int(x) for x in threshold)
            else:
                hit = False
            if hit and rule.get("secondary_feature"):
                hit = float(context.get(rule["secondary_feature"], 0)) >= float(rule["secondary_threshold"])
            if hit:
                match = deepcopy(rule)
                match["observed_value"] = value
                matches.append(match)
        return matches

    def update_rule(self, rule_id: str, changes: Mapping[str, Any]) -> dict[str, Any]:
        for rule in self.rules:
            if rule["rule_id"] == rule_id:
                if "threshold" in changes:
                    value = changes["threshold"]
                    if isinstance(rule["threshold"], list):
                        if not isinstance(value, list) or not value:
                            raise ValueError("threshold must be a non-empty port list")
                        rule["threshold"] = [int(v) for v in value]
                    else:
                        value = float(value)
                        if value < 0:
                            raise ValueError("threshold cannot be negative")
                        rule["threshold"] = value
                if "enabled" in changes:
                    rule["enabled"] = bool(changes["enabled"])
                if "severity" in changes:
                    severity = str(changes["severity"]).upper()
                    if severity not in {"INFO","LOW","MEDIUM","HIGH","CRITICAL"}:
                        raise ValueError("invalid severity")
                    rule["severity"] = severity
                return deepcopy(rule)
        raise KeyError(rule_id)


def analyze_flow(flow: Mapping[str, Any], features: Mapping[str, float], rules=None):
    return RuleEngine(rules).analyze_flow(flow, features)
