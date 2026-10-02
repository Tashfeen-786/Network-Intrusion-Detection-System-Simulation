# Project Report: Network Intrusion Detection System (IDS) Simulation

## Abstract

This project implements a complete defensive Network Intrusion Detection System simulation for students without access to network infrastructure. It generates 5,000 or more labeled synthetic flow records with documentation-only IP ranges, extracts explainable statistical features, and combines configurable signature rules, normal-baseline anomaly scoring, and optional machine learning. A FastAPI and SQLite backend performs validation, scoring, alerting, persistence, correlation, authentication, authorization, and analyst workflow. A React dashboard displays near-real-time SOC metrics and investigation detail. Logistic Regression, Random Forest, and Isolation Forest are evaluated from held-out data, and 53 automated tests cover normal, suspicious, malformed, persistence, API, ML, and workflow behavior. The simulator produces only data records and contains no packet transmission, scanning, exploitation, denial-of-service, credential, evasion, or blocking capability.

## Introduction

Network monitoring helps security teams identify behavior that may justify investigation. Real IDS products process large and sensitive streams and are difficult to reproduce safely in a student lab. This project models the essential defensive data path—from flow collection through analyst documentation—while protecting third parties and keeping every experiment deterministic and local.

An Intrusion Detection System detects and alerts; an Intrusion Prevention System may additionally take inline action. A Network IDS observes network telemetry while a Host IDS observes one host. This implementation is intentionally a network-based hybrid IDS: it analyzes flow-level endpoint, protocol, service, rate, failure, volume, flag, and diversity metadata and combines known-pattern and behavioral methods.

## Problem Statement

Signature-only monitoring can miss unmodeled behavior, while anomaly and ML systems can overwhelm analysts with legitimate deviations. Students need to demonstrate the trade-off, build trustworthy evidence, and support a SOC decision without generating harmful traffic. The system must be modular, explainable, reproducible, testable, usable without a lab, and honest about model results.

## Objectives

1. Generate at least 5,000 safe normal and suspicious synthetic flows.
2. Engineer defensible packet, byte, duration, rate, ratio, connection, flag, and diversity features.
3. Implement seven configurable signatures and a statistical anomaly score.
4. Train and genuinely evaluate supervised and unsupervised ML models.
5. Fuse enabled evidence into a calibrated 0–100 risk score and severity.
6. Generate/correlate alerts, persist evidence, and support SOC triage.
7. Deliver a professional real-time dashboard, documented REST API, test suite, report, career proof, and ethical safeguards.

## Network Security Background

A packet is a network transmission unit; traffic is aggregate communication; a flow summarizes related communications; an event is an observation; an alert is a detection requiring attention; and an incident is related evidence requiring coordinated work. Flow monitoring reduces payload privacy exposure and data volume but loses application content. Endpoint identities, ports, timing, rates, and volume still reveal sensitive architecture and must be protected.

SOC teams in banks, cloud providers, enterprises, data centers, government, universities, e-commerce, and managed security providers use IDS/NDR and SIEM context to prioritize investigations. Relevant roles include SOC, Network Security, Cybersecurity, Incident Response, and Threat Detection analysts/engineers.

## Intrusion Detection Systems

Signature detection evaluates explicit predicates and produces highly readable reasons. Anomaly detection establishes normal behavior and scores deviations, potentially finding unseen behavior but also normal change. Supervised ML learns labeled boundaries; unsupervised ML finds observations unlike the learned population. A hybrid design uses their complementary strengths but never treats detector agreement as conclusive attribution.

IDS alerts and IPS may prevent. This project does not block because synthetic baselines are not a safe basis for availability-impacting action. Its controls are analyst-in-the-loop.

## Existing Approaches

Snort and Suricata provide high-performance network signatures and protocol analysis. Zeek creates rich structured network logs. NDR and UEBA products add analytics, entity baselines, enrichment, and workflow; SIEMs correlate many log sources. This project does not replicate their depth or performance. It demonstrates the architecture with pure synthetic flows, seven readable rules, statistical detection, scikit-learn models, an API, persistence, and a lightweight SOC interface.

## Proposed System

The synthetic generator feeds validated flow objects to FastAPI. A framework-independent service derives features and fans out to the rule, anomaly, and optional ML engines. The risk engine combines evidence with documented weights. Every flow and optional model result is stored; rule or elevated-risk events create alerts. Alerts can be filtered, investigated, correlated, annotated, and moved through controlled states. Dashboard polling every five seconds provides a simple beginner-friendly near-real-time path.

## Architecture

```text
Synthetic flow data → collector → validation/features
                                 ├→ rules
                                 ├→ statistical anomaly
                                 └→ optional ML
                     → hybrid risk → alert/correlation → SQLite
                     → analytics API → React dashboard → analyst
```

Detailed responsibilities, relationships, indexes, and trust boundaries are in `docs/architecture.md`.

## Synthetic Dataset

The deterministic generator uses seed 42 and RFC 5737 addresses. Required columns include flow/time/endpoints/ports/protocol, packets/bytes/duration, connection/failure/SYN/RST counts, average size, `NORMAL|SUSPICIOUS` label, and scenario. Normal scenarios are web, DNS, SSH, email, and database. Suspicious records represent high connection rate, repeated failures, multi-port probing-like statistics, SYN-heavy statistics, unusual services, high volume, high DNS query rate, and generic C2-like metadata. The class mix is 72% normal and 28% suspicious. These records describe patterns; they do not create them on a network.

## Traffic Simulation

`traffic_simulator.py` supports normal or mixed data and slow or fast intervals. It can print records or submit them to localhost with an API key. A count of zero runs continuously. No raw socket, frame construction, external target, scan loop, credential operation, or high-rate packet routine exists.

## Feature Engineering

The system derives packets/second, bytes/second, average packet size, failure ratio, SYN ratio, and connection rate, and retains raw counts and unique destination ports/IPs. It defaults missing optional counts, clamps only denominators for zero duration, and rejects malformed IP, invalid port/protocol/time, negative/non-finite values, and inconsistent failure count. Each feature's defensive meaning is documented in `docs/feature_guide.md`.

## Signature Detection

IDS-001 through IDS-006 detect connection rate, failures, destination-port diversity, SYN-heavy behavior, unusual service port, and byte volume. Rules have ID/name/description/severity/threshold/enabled state. Thresholds and severity are persisted and safely updateable. Matches are observable conditions and not proof of attack.

## Anomaly Detection

The baseline uses normal rows and stores mean, standard deviation, Q1, Q3 and IQR for packet rate, byte rate, connection rate, failure ratio, and port diversity. Each observation receives absolute Z-score, Tukey-fence distance, and moving-mean deviation per feature. Weighted components emphasize the strongest deviations but include multi-feature context. Output is capped at 100 and component detail remains visible for explainability.

## Machine Learning

The specified ten numeric features train Logistic Regression and Random Forest on a stratified 80/20 split. Isolation Forest trains only on normal training rows. Reproducible seed 42 and actual inference outputs are used. Evaluation calculates accuracy, precision, recall, F1, ROC-AUC, and confusion matrix. Random Forest is saved as the API classifier; comparison bundles and JSON metrics are retained. Accuracy is not enough: precision reflects alert fidelity, recall reflects missed suspicious rows, and F1 balances them.

## Hybrid Detection

With ML: 40% rule, 30% anomaly, 30% ML. Without ML: 60% rule, 40% anomaly. Rule score reflects maximum matched severity plus limited additional-match context. Inputs and weights are clamped/validated. Hybrid coverage can capture defined and unusual behavior, but calibration and analyst judgment remain essential.

## Risk Scoring

Risk maps to NORMAL (0–20), LOW RISK (21–40), SUSPICIOUS (41–60), HIGH RISK (61–80), or CRITICAL INVESTIGATION (81–100). Severity maps to INFO, LOW, MEDIUM, HIGH, or CRITICAL at the same boundaries. These are project assumptions and must be calibrated per asset criticality, environment and acceptable alert volume.

## Alert Generation

A match or risk above 40 creates an ID, source flow relation, timestamp, endpoints/protocol/ports, primary rule/type, severity/risk, anomaly/ML evidence, description, matched rules, recommendations, and `NEW` state. Recommended actions include reviewing authorized logs, validating assets, comparing history, and deciding expectedness.

## Alert Correlation

Related alerts are grouped by source IP, alert type, and default 60-second window. An incident object tracks first/last seen, underlying IDs/count, maximum risk and state, reducing repetitive queue items without deleting evidence.

## Dashboard

Six cards and fourteen visual analyses cover totals, class/risk, flow/packet/byte/connection/failure rates, protocols, ports, alert volume/severity/types/sources, and risk. The alert table filters severity, protocol, exact type, status, and time. Dependency-light SVG charts keep the code readable.

## SOC Workflow

An analyst receives an alert, triages scope and severity, reviews related authorized logs and asset context, compares the baseline, changes status, adds notes, then escalates, resolves, or marks false positive. Terminal states do not reopen in version 1. Audit entries preserve modifications. Tier 1 responsibilities and interview demonstration are in `docs/soc_workflow.md`.

## Database and API

SQLite tables represent flows, alerts, rules, notes, model results and audit logs with foreign keys and targeted indexes. API key authentication, analyst/viewer authorization, rate limiting, validation, parameterized SQL and generic failures protect the demonstration. Required flow/alert/status/note/dashboard/rule endpoints and `/score`/`/stats` compatibility aliases are documented in `docs/api.md`.

## Testing

The 53 automated tests exceed the required 30 and map to every listed category: normal TCP/UDP/DNS/HTTPS; connection/failure/port/SYN/volume patterns; source/destination IP and port errors; unsupported protocol; missing packets; zero duration; feature/rule/anomaly/risk/alert/correlation; status/note/storage/dashboard/ML/API behavior; empty baseline; and duplicate IDs. Additional tests cover auth, viewer restrictions, transitions, charts, weights, boundaries, correlation windows and disabled rules. Actual output is retained in `reports/test_results.md`.

## Security and Privacy

Synthetic metadata and no payload reduce harm, but IDS data remains sensitive. Implemented safeguards include validation, parameterized SQL, role checks, rate limits, CORS, escaped React rendering, environment secrets, audit records, and generic 500 responses. A production version requires TLS, SSO/RBAC, secret rotation, encrypted storage/backups, durable distributed limits, CSP, centralized logging, retention policy, least privilege and patching.

## Results

The execution produces `data/network_traffic.csv`, three model bundles, held-out `ml_metrics.json`, selected-model `evaluation.json`, a threshold sweep CSV, confusion matrix image, SQLite runtime records, a built frontend, and passing automated tests. The selected Random Forest measured 0.966 accuracy, 0.992 precision, 0.885714 recall, 0.935849 F1 and 0.97277 ROC-AUC on 1,000 held-out rows; its confusion matrix was `[[718, 2], [32, 248]]`. These metrics are machine-generated and not fabricated.

## False Positives

Authorized backups, vulnerability management, maintenance, onboarding, failover, and popular shared services may exceed a baseline. Per-asset/time baselines, context, allow-lists with governance, threshold tuning, and analyst feedback can reduce noise without blindly disabling detections.

## False Negatives

Slow/low activity, feature mimicry, insufficient telemetry, stale rules/models, encrypted application context, and synthetic-real domain gap can hide suspicious behavior. Diverse telemetry, broader correlation, robust feature validation, periodic red/blue authorized evaluation, recall monitoring, and drift detection can reduce misses.

## Limitations

The data is synthetic, labels are generated from scenario logic, and the scale is educational. No packet/application payload, actual enterprise identity/asset inventory, dynamic entity model, distributed stream, production database, commercial SIEM, inline prevention, or real-world generalization claim is provided. Model performance on generated data cannot be assumed for operational networks.

## Future Scope

Authorized PCAP/NetFlow/cloud-flow ingestion; Zeek/Suricata; SIEM; threat intelligence; asset/identity enrichment; behavioral per-entity baselines; stronger graph/session correlation; rule tuning; UEBA; cloud/container operation; Kafka and backpressure; PostgreSQL/analytics storage; central logs; model drift; explanations; ONNX/batching; enterprise SSO; and carefully governed response playbooks. Improvements remain defensive and authorized.

## Conclusion

The project demonstrates an end-to-end, safe hybrid NIDS lifecycle: synthetic collection, validated feature engineering, signature/anomaly/ML evidence, calibrated risk, alerts, persistence, correlation, analytics, SOC investigation, testing, and documentation. Its strongest design property is not a particular score; it is transparent evidence plus explicit analyst judgment within an ethical boundary.
