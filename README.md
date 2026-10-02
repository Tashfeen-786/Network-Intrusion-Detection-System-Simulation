# Network Intrusion Detection System (IDS) Simulation

> A defensive, industry-oriented Network-Based Hybrid IDS that processes **synthetic flow records only**, combines signatures, statistical anomaly detection, and optional machine learning, then exposes SOC triage workflows through a FastAPI service and React dashboard.

[![Safety: synthetic only](https://img.shields.io/badge/safety-synthetic%20flows%20only-4de2c5)](#ethical-disclaimer) [![Tests](https://img.shields.io/badge/tests-53%20automated-56b4ff)](reports/test_results.md) [![Python](https://img.shields.io/badge/python-3.10%2B-f9b84b)](requirements.txt)

## Overview

SentinelFlow simulates the data path of a modern NIDS without capturing or transmitting packets. A generator creates realistic statistical records using RFC 5737 documentation addresses. The hybrid engine validates each flow, derives explainable features, applies seven configurable rules, measures deviation from a learned normal baseline, optionally obtains a Random Forest probability, calculates a 0–100 risk score, persists evidence, correlates alerts, and provides an analyst dashboard.

**Simple explanation:** it is a safe practice SOC. It creates rows that *describe* normal and unusual network behavior and shows why unusual rows deserve review.

**Technical explanation:** it is a modular flow-analytics pipeline with deterministic data generation, statistical and supervised detection, SQLite persistence, authenticated REST endpoints, periodic frontend polling, stateful incident handling, and testable framework-independent detection functions.

## Problem Statement

Organizations must find suspicious network behavior among large volumes of legitimate traffic. A signature can explain a known pattern but may miss novel behavior; anomaly and ML methods can widen coverage but can increase false positives. Students also need a legal, infrastructure-independent way to demonstrate detection engineering. This project solves both learning problems with synthetic telemetry and analyst-in-the-loop decisions.

## Objectives

- Generate at least 5,000 safe, labeled synthetic flow records.
- Monitor source/destination, port, protocol, volume, rates, flags, failures, and diversity.
- Combine signature, anomaly, and optional ML detections with configurable weights.
- Produce risk, classification, severity, alerts, correlation, charts, and incident records.
- Support status changes, investigation timestamps, notes, resolution notes, and audit events.
- Provide authenticated APIs, an auto-refreshing SOC dashboard, tests, proof artifacts, and documentation.

## Cybersecurity Relevance

SOC and NOC teams use IDS/NDR telemetry to triage scanning-like behavior, repeated connection failures, bursts, command-and-control indicators, DNS anomalies, and possible exfiltration. Banks, cloud providers, enterprises, data centers, government organizations, universities, e-commerce organizations, and MSSPs all need explainable monitoring. This implementation demonstrates skills relevant to SOC Analyst, Network Security Analyst, Cybersecurity Analyst, Security Engineer, Incident Response Analyst, and Threat Detection Engineer roles: flow analysis, detection logic, baselining, risk scoring, API design, secure coding, evidence handling, and incident documentation.

## IDS Concepts

- **Packet:** one formatted unit transmitted on a network. This simulation never sends or captures one.
- **Network traffic:** the communication activity produced by systems.
- **Flow:** summarized metadata for related communication, such as endpoints, protocol, counts, and duration.
- **Security event:** an individual observable record.
- **Alert:** a detection requiring analyst attention.
- **Incident:** related alerts and evidence requiring coordinated investigation.
- **NIDS:** observes network telemetry. **HIDS:** observes one host's activity.
- **IDS:** detects and alerts. **IPS:** can sit inline and take preventive action. This project intentionally does not block traffic because analyst validation is safer and better aligned to its educational scope.

| Method | Detects | Advantages | Limitations |
|---|---|---|---|
| Signature | Configured known patterns | Fast, explainable, lower false-positive rate for precise rules | Can miss unknown patterns |
| Anomaly | Deviation from a normal baseline | Can reveal unusual or unseen behavior | Baseline changes can create false positives |
| Hybrid | Evidence from multiple methods | Broader, contextual coverage | Requires tuning and clear weighting |

This is primarily a **Network-Based Hybrid IDS** because it evaluates network-flow metadata and fuses multiple detectors.

## Architecture

```text
Synthetic Traffic Generator
          ↓
     Flow Collector (API)
          ↓
Feature Extractor + Validation
          ↓
 ┌────────┼──────────┐
 ↓        ↓          ↓
Rules   Statistical  Optional ML
Engine  Anomaly      Models
 └────────┼──────────┘
          ↓
Hybrid Risk Engine (0–100)
          ↓
 Alert Engine → Correlation
          ↓
SQLite Security Database
          ↓
FastAPI Analytics API
          ↓  polling every 5 seconds
React SOC Dashboard → Analyst
```

1. The generator emits data objects only. 2. FastAPI validates requests. 3. Feature engineering safely handles zero duration and missing counts. 4. rules provide known reasons; Z-score/IQR/moving-mean statistics provide deviation evidence; ML provides an optional probability. 5. The risk engine uses 40/30/30 weights with ML and 60/40 without it. 6. Alerts and evidence are committed to related tables. 7. The dashboard polls because polling is the most beginner-friendly reliable option; SSE/WebSockets are future alternatives.

See [architecture details](docs/architecture.md) and `screenshots/02_ids_architecture.svg`.

## Technology Stack

- Python 3.10+, pandas, NumPy, scikit-learn, joblib
- FastAPI + Pydantic + Uvicorn
- SQLite with foreign keys and indexes
- React + Vite + dependency-light SVG visualization
- Pytest + FastAPI TestClient
- Matplotlib for the evaluated confusion matrix proof

## Project Structure

```text
Network-Intrusion-Detection-System-Simulation/
├── simulator/            # Dataset generator and continuous safe flow-data feeder
├── ids/                  # Features, rules, anomaly, risk, alert, correlation
├── ml/                   # Train, predict, evaluate, and threshold tuning
├── backend/              # FastAPI app, routes, schemas, auth, services, database
├── frontend/             # React/Vite dashboard, chart components, pages, API service
├── data/                 # Generated CSV; local SQLite database at runtime
├── models/               # Reproducible trained model bundles
├── tests/                # 53 automated unit and API tests
├── screenshots/          # Professional proof artifacts and checklist guide
├── docs/                 # Concepts, API, security, scenarios, SOC/GitHub guidance
├── reports/              # Evaluation, test evidence, report, career proof
├── README.md
├── requirements.txt
├── .env.example
└── .gitignore
```

## Synthetic Dataset

`simulator/generate_dataset.py` writes `data/network_traffic.csv` with 5,000+ rows and the specified columns: identifiers/time, reserved source and destination addresses, ports/protocol, counts, duration, connection/failure/SYN/RST statistics, average packet size, label, and scenario. Labels are `NORMAL` and `SUSPICIOUS`. Scenarios cover normal web, DNS, SSH, email and database use plus high connection rate, repeated failures, multi-port probing-like statistics, SYN-heavy statistics, unusual services, high volume, high DNS query rate, and generic C2-like metadata.

All addresses belong to `192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`. They are documentation ranges—not real targets.

```bash
python -m simulator.generate_dataset --count 5000 --output data/network_traffic.csv --seed 42
```

## Traffic Simulator

The simulator continuously constructs JSON/CSV-equivalent flow **records**. HTTP is used only to submit those records to the local analysis API; it never creates network attack packets, raw sockets, scans, or floods.

```bash
# Data-only preview
python -m simulator.traffic_simulator --mode normal --speed slow --count 5 --stdout-only
# Mixed near-real-time demo posted to local backend
python -m simulator.traffic_simulator --mode mixed --speed fast --count 30
```

`--count 0` means continuous operation. `Ctrl+C` stops safely.

## Feature Engineering

`extract_network_features()` derives packet/byte rates, average packet size, failure and SYN ratios, connection rate, unique destination ports/IPs, and preserves raw counts. It rejects malformed IP addresses, out-of-range ports, unsupported protocols, negative/non-finite values, inconsistent failure counts, and malformed timestamps. Durations are clamped to 0.001 only for division, preventing division by zero without altering stored evidence. See [feature guide](docs/feature_guide.md).

## Signature-Based Detection

Seven configurable rules cover: excessive connection rate, repeated failed connections, high destination-port diversity, SYN-heavy behavior, unusual service ports, abnormal byte volume, and high synthetic DNS query rate. Thresholds, enabled state, and severity can be updated through `/api/rules/{id}`. A match indicates suspicious behavior requiring investigation; it does **not** prove malicious activity.

## Anomaly Detection

A normal-only baseline records means, standard deviations, quartiles/IQRs, and moving values for packet rate, byte rate, connection rate, failure ratio, and destination-port diversity. `calculate_anomaly_score()` combines Z-score, IQR distance, and moving-baseline deviation into 0–100. This can reveal unseen patterns, but backups, maintenance, and changing workloads may also be anomalous.

## Machine Learning

The optional training pipeline genuinely fits and evaluates:

- Logistic Regression (supervised)
- Random Forest (supervised and selected for API probability)
- Isolation Forest (unsupervised; fit on normal training records)

The ten specified numerical features are used. A stratified 80/20 split uses seed 42. Accuracy, precision, recall, F1, ROC-AUC, and confusion matrix are calculated from the held-out split; no result is hard-coded. Accuracy alone is insufficient because class imbalance can hide missed suspicious records. Security teams closely monitor recall to reduce missed detections while managing precision to control alert fatigue.

```bash
python -m ml.train_model
python -m ml.evaluate
python -m ml.tune
cat reports/ml_metrics.json
```

## Hybrid Detection

With ML enabled: `rule × 0.40 + anomaly × 0.30 + ML × 0.30`. Without ML: `rule × 0.60 + anomaly × 0.40`. The API response exposes components and reasons. The methods complement rather than automatically validate one another.

## Risk Scoring

- 0–20: `NORMAL`
- 21–40: `LOW RISK`
- 41–60: `SUSPICIOUS`
- 61–80: `HIGH RISK`
- 81–100: `CRITICAL INVESTIGATION`

Alert severity uses `INFO`, `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`. These thresholds are project assumptions and must be calibrated to assets, baselines, business context, and analyst feedback in a real SOC.

## Alert Generation

Alerts contain ID/time/endpoints/protocol/ports, rule and type, severity/risk, description, anomaly and optional ML score, status, matched rules, and recommended defensive steps. Statuses are `NEW`, `INVESTIGATING`, `RESOLVED`, and `FALSE_POSITIVE`.

## Alert Correlation

`correlate_alerts()` groups alerts with the same source and alert type inside a configurable 60-second window. This turns repeated observations into analyst-friendly incidents while retaining every underlying alert ID and maximum risk.

## SOC Dashboard

Top cards show total flows, normal, suspicious, open/critical alerts, and average risk. Charts cover traffic over time, normal versus suspicious, severity, top types, protocols, destination ports, top sources, risk bands, packet/byte rates, connections, failures, alert timeline, and risk timeline. Filters cover severity, protocol, type, status, and time range.

## Incident Investigation

Selecting an alert opens endpoint/time/protocol/port and traffic statistics, matched rule, anomaly/ML/final risk, reason, recommended investigation, status, analyst notes, and timestamps. Suggested action is defensive: review authorized logs, verify assets, compare history, and decide whether activity is expected. Status transitions and notes are audit logged.

## API Documentation

Interactive OpenAPI: `http://127.0.0.1:8000/docs`. Development requests include `X-API-Key: dev-analyst-key`; modifying calls also need `X-Role: analyst`. Viewers have read-only access. See [complete API contract](docs/api.md).

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/flows` | Validate, analyze, store a synthetic flow |
| GET | `/api/flows`, `/api/flows/{id}` | List/detail flows |
| GET | `/api/alerts`, `/api/alerts/{id}` | Filter/list/investigate alerts |
| PUT | `/api/alerts/{id}/status` | Controlled status transition |
| POST | `/api/alerts/{id}/notes` | Add analyst note |
| GET | `/api/incidents` | Correlated alert groups |
| GET | `/api/dashboard/stats` | Cards |
| GET | `/api/dashboard/traffic` | Traffic/chart series |
| GET | `/api/dashboard/alerts` | Alert/chart series |
| GET/PUT | `/api/rules`, `/api/rules/{id}` | View/tune signatures |
| POST | `/score` | Compatible scoring alias |
| GET | `/stats` | Compatible summary alias |

## Installation

```bash
git clone https://github.com/<username>/Network-Intrusion-Detection-System-Simulation.git
cd Network-Intrusion-Detection-System-Simulation
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python -m simulator.generate_dataset
python -m ml.train_model
cd frontend && npm install && cd ..
```

## Usage

Open three terminals from the repository root:

```bash
# Terminal 1
uvicorn backend.app:app --host 0.0.0.0 --port 8000
# Terminal 2
cd frontend && npm run dev -- --host 0.0.0.0
# Terminal 3
python -m simulator.traffic_simulator --mode mixed --speed fast --count 30
```

Visit `http://127.0.0.1:5173`. The complete 12-step normal/suspicious/investigate/resolve walkthrough is in [docs/demo_runbook.md](docs/demo_runbook.md).

## Testing

```bash
pytest -q
```

The suite includes 53 automated checks and covers all 30 mandated categories: normal TCP/UDP/DNS/HTTPS, six suspicious patterns, malformed IP/port/protocol, missing packets, zero duration, features, rules, anomaly/risk/alerts/correlation, status/notes/database/stats/ML/API validation, empty baseline, and duplicates. [Test plan and actual run](reports/test_results.md).

## Security

The project uses synthetic metadata and stores no payload. It validates all input, relies on Pydantic and parameterized SQL, escapes dashboard values through React, applies API key + role checks, rate limits per key, keeps secrets in environment variables, protects notes with authorization, records audit actions, and documents TLS/least-privilege requirements for deployment. IDS data is sensitive because endpoints, services, timing, vulnerabilities, and investigation notes can reveal an organization's architecture. See [security and privacy](docs/security.md).

## Results

The reproducible outputs are `reports/ml_metrics.json`, `reports/evaluation.json`, `reports/threshold_sweep.csv`, `reports/test_results.md`, generated dataset/model files, SQLite records, and proof images. On the included deterministic held-out split, the selected Random Forest measured **96.6% accuracy, 99.2% precision, 88.57% recall, 93.58% F1, and 0.97277 ROC-AUC** with confusion matrix `[[718, 2], [32, 248]]`. These values came from execution rather than being invented.

## False Positives & False Negatives

A false positive flags legitimate activity (for example, an authorized backup burst). A false negative misses genuinely suspicious activity. Too many false positives create fatigue; false negatives leave risk unseen. Better behavioral baselines, detector diversity, tuned thresholds, analyst feedback, asset/identity context, and periodic model review improve the trade-off.

Confusion matrix terms: **TP** suspicious correctly detected; **TN** normal correctly rejected; **FP** normal incorrectly alerted; **FN** suspicious missed. Precision is TP/(TP+FP), recall is TP/(TP+FN), and F1 is their harmonic mean.

## Limitations

This is synthetic, flow-level, small-scale evidence. It has no packet payload, live capture, automatic blocking, production identity system, distributed stream, threat-intelligence feed, or guarantee that generated label separability matches an operational network. Statistical matches are investigative signals, not attribution.

## Future Improvements

Authorized PCAP/NetFlow ingestion; live flow pipelines; Zeek/Suricata and SIEM integration; threat-intelligence enrichment; dynamic behavioral baselines; stronger alert correlation; rule tuning; UEBA; cloud/container deployment; centralized logging; model-drift monitoring; Kafka backpressure; explainability; asset tags; minimal Suricata-rule import; batch/ONNX inference; and role-based enterprise identity. All extensions must remain defensive and authorized.

## Screenshots

The `screenshots/` directory includes generated proof artifacts and `README.md` gives professional names for all 27 required captures. Repository/commit captures require the student's own GitHub account and are deliberately marked as external evidence rather than fabricated.

## Learning Outcomes

Network security fundamentals; NIDS/HIDS/IDS/IPS distinctions; flow feature engineering; signature and statistical detection; supervised/unsupervised ML; evaluation and threshold tuning; hybrid risk; REST/relational design; secure coding; visualization; triage; incident documentation; test automation; Git/GitHub communication.

## Ethical Disclaimer

**This project is designed exclusively for defensive cybersecurity education. All suspicious network behavior is represented using synthetic data or authorized isolated lab environments.**

Do not use it to scan, probe, exploit, disrupt, flood, steal from, bypass, or attack public or third-party systems. The included simulator produces data records, not packets. It contains no exploit, DDoS, credential-theft, evasion, or automatic-blocking functionality.

## Author

Student cybersecurity portfolio project. Replace this line with your name, institution, and professional profile before publishing.
