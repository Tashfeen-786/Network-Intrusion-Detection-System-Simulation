# MITRE ATT&CK and SIEM Integration

## ATT&CK at a high level

When sufficient corroborating evidence exists, organizations can map network detections to current ATT&CK tactics/techniques for consistent documentation, investigation, hunting, coverage analysis, and reporting. A probing-like pattern may provide Discovery context; repeated remote-service failures may be relevant to Credential Access or Lateral Movement investigations; unusual outbound transfer volume may provide Exfiltration context. **A statistical anomaly alone does not establish a technique, tactic, actor, or malicious intent.** Analysts should require protocol/application, asset, identity, endpoint, and temporal evidence and record confidence.

## SIEM integration

```text
IDS → JSON alert → authenticated log forwarder/API → SIEM
→ cross-source correlation → SOC analyst
```

Safe example:

```json
{
  "alert_id": "ALT-1001",
  "source_ip": "192.0.2.15",
  "destination_ip": "198.51.100.20",
  "severity": "HIGH",
  "rule": "High Connection Rate",
  "risk_score": 78
}
```

A commercial SIEM is not required to demonstrate the concept. An authorized forwarder could tail structured application logs or call a secured export endpoint, normalize fields, preserve timestamps/IDs, use TLS and retry/backoff, and avoid duplicate ingestion. In production, sign or authenticate transport, buffer outages, redact unnecessary fields, restrict indexes, and monitor forwarding health.
