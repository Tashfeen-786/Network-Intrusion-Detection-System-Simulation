import math
import pytest
from ids.feature_extractor import extract_network_features,validate_flow,FlowValidationError
from ids.rule_engine import RuleEngine
from ids.anomaly_detector import StatisticalAnomalyDetector
from ids.risk_engine import calculate_rule_risk,calculate_risk_score,classification_for,severity_for
from ids.alert_engine import generate_alert
from ids.correlation import correlate_alerts

def features(flow): return extract_network_features(flow)
def matches(flow): return RuleEngine().analyze_flow(flow,features(flow))

def test_01_normal_tcp_flow(normal_flow): assert matches(normal_flow)==[]
def test_02_normal_udp_flow(normal_flow):
    flow={**normal_flow,"protocol":"UDP","destination_port":53,"packet_count":3,"syn_count":0}; assert matches(flow)==[]
def test_03_normal_dns_flow(normal_flow):
    flow={**normal_flow,"protocol":"UDP","destination_port":53,"packet_count":2,"byte_count":240,"duration_seconds":.2,"syn_count":0}; assert features(flow)["average_packet_size"]==120
def test_04_normal_https_flow(normal_flow): assert validate_flow(normal_flow)["destination_port"]==443
def test_05_high_connection_rate(normal_flow):
    flow={**normal_flow,"connection_count":200,"duration_seconds":2}; assert "IDS-001" in [m["rule_id"] for m in matches(flow)]
def test_06_repeated_failed_connections(normal_flow):
    flow={**normal_flow,"connection_count":30,"failed_connection_count":15,"duration_seconds":10}; assert "IDS-002" in [m["rule_id"] for m in matches(flow)]
def test_07_multi_port_pattern(normal_flow):
    flow={**normal_flow,"unique_destination_ports":35}; assert "IDS-003" in [m["rule_id"] for m in matches(flow)]
def test_08_syn_heavy_pattern(normal_flow):
    flow={**normal_flow,"packet_count":100,"syn_count":85}; assert "IDS-004" in [m["rule_id"] for m in matches(flow)]
def test_09_high_traffic_volume(normal_flow):
    flow={**normal_flow,"byte_count":7_000_000}; assert "IDS-006" in [m["rule_id"] for m in matches(flow)]
def test_10_invalid_source_ip(normal_flow):
    with pytest.raises(FlowValidationError): validate_flow({**normal_flow,"source_ip":"999.1.1.1"})
def test_11_invalid_destination_ip(normal_flow):
    with pytest.raises(FlowValidationError): validate_flow({**normal_flow,"destination_ip":"not-an-ip"})
def test_12_invalid_source_port(normal_flow):
    with pytest.raises(FlowValidationError): validate_flow({**normal_flow,"source_port":70000})
def test_13_invalid_destination_port(normal_flow):
    with pytest.raises(FlowValidationError): validate_flow({**normal_flow,"destination_port":-1})
def test_14_unsupported_protocol(normal_flow):
    with pytest.raises(FlowValidationError): validate_flow({**normal_flow,"protocol":"SCTP"})
def test_15_missing_packet_count_is_handled(normal_flow):
    flow=dict(normal_flow); del flow["packet_count"]; assert features(flow)["packet_count"]==0
def test_16_zero_duration_is_safe(normal_flow):
    result=features({**normal_flow,"duration_seconds":0}); assert math.isfinite(result["bytes_per_second"])
def test_17_feature_extraction_rates(normal_flow):
    f=features(normal_flow); assert f["bytes_per_second"]==6000 and f["packets_per_second"]==8 and f["failure_ratio"]==0
def test_18_rule_detection_multiple(normal_flow):
    flow={**normal_flow,"connection_count":200,"duration_seconds":2,"byte_count":8_000_000}; assert len(matches(flow))>=2
def baseline(normal_flow):
    return [features({**normal_flow,"packet_count":35+i%7,"byte_count":26000+i*100,"duration_seconds":4+i%3,"connection_count":2+i%3}) for i in range(40)]
def test_19_anomaly_score(normal_flow):
    detector=StatisticalAnomalyDetector().fit(baseline(normal_flow)); score,_=detector.calculate_anomaly_score(features({**normal_flow,"packet_count":5000,"byte_count":20_000_000,"duration_seconds":1,"connection_count":500,"failed_connection_count":100,"unique_destination_ports":60})); assert score>80
def test_20_risk_score():
    r=calculate_risk_score(75,50,None); assert r["risk_score"]==65 and r["classification"]=="HIGH RISK"
def test_21_alert_creation(normal_flow):
    risk=calculate_risk_score(75,50,None); rule=matches({**normal_flow,"connection_count":200,"duration_seconds":2})
    alert=generate_alert(normal_flow,risk,rule,50); assert alert["status"]=="NEW" and alert["alert_id"].startswith("ALT-")
def test_22_alert_correlation():
    alerts=[{"alert_id":"A1","timestamp":"2026-01-01T00:00:00+00:00","source_ip":"192.0.2.1","alert_type":"High Rate","risk_score":70},{"alert_id":"A2","timestamp":"2026-01-01T00:00:30+00:00","source_ip":"192.0.2.1","alert_type":"High Rate","risk_score":80}]
    incidents=correlate_alerts(alerts,60); assert len(incidents)==1 and incidents[0]["alert_count"]==2 and incidents[0]["max_risk"]==80
def test_23_correlation_window_separates():
    alerts=[{"alert_id":"A1","timestamp":"2026-01-01T00:00:00+00:00","source_ip":"192.0.2.1","alert_type":"X","risk_score":1},{"alert_id":"A2","timestamp":"2026-01-01T00:02:00+00:00","source_ip":"192.0.2.1","alert_type":"X","risk_score":1}]; assert len(correlate_alerts(alerts,60))==2
def test_24_empty_dataset_rejected():
    with pytest.raises(ValueError): StatisticalAnomalyDetector().fit([])
def test_25_classification_boundaries(): assert [classification_for(x) for x in [20,40,60,80,100]]==["NORMAL","LOW RISK","SUSPICIOUS","HIGH RISK","CRITICAL INVESTIGATION"]
def test_26_severity_boundaries(): assert [severity_for(x) for x in [20,40,60,80,100]]==["INFO","LOW","MEDIUM","HIGH","CRITICAL"]
def test_27_ml_weighted_risk():
    result=calculate_risk_score(70,60,.78); assert result["risk_score"]==69.4 and result["weights"]["ml"]==.3
def test_28_invalid_weights_rejected():
    with pytest.raises(ValueError): calculate_risk_score(10,20,None,{"rule":.7,"anomaly":.4})
def test_29_unusual_service_port(normal_flow): assert "IDS-005" in [m["rule_id"] for m in matches({**normal_flow,"destination_port":4444})]
def test_30_rule_can_be_disabled(normal_flow):
    engine=RuleEngine(); engine.update_rule("IDS-001",{"enabled":False}); flow={**normal_flow,"connection_count":200,"duration_seconds":2}; assert "IDS-001" not in [m["rule_id"] for m in engine.analyze_flow(flow,features(flow))]
def test_31_failure_count_consistency(normal_flow):
    with pytest.raises(FlowValidationError): validate_flow({**normal_flow,"connection_count":2,"failed_connection_count":3})
def test_32_rule_risk_uses_severity(): assert calculate_rule_risk([{"severity":"CRITICAL"}])==95
def test_33_anomaly_requires_fit(normal_flow):
    with pytest.raises(RuntimeError): StatisticalAnomalyDetector().calculate_anomaly_score(features(normal_flow))
def test_34_malformed_timestamp(normal_flow):
    with pytest.raises(FlowValidationError): validate_flow({**normal_flow,"timestamp":"yesterday"})
def test_35_high_dns_query_rate_is_safe_metadata_rule(normal_flow):
    flow={**normal_flow,"protocol":"UDP","destination_port":53,"packet_count":500,"byte_count":100000,"duration_seconds":2,"connection_count":80,"syn_count":0}
    assert "IDS-007" in [m["rule_id"] for m in matches(flow)]
