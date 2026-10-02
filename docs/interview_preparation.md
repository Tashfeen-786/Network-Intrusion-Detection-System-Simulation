# Interview Preparation — Exactly 10 Questions and Answers

## 1. Explain your project.

I developed a defensive Network Intrusion Detection System simulation that analyzes synthetic network-flow records rather than sending attack traffic. The pipeline validates data, derives rate/ratio/diversity features, applies seven explainable signatures, compares behavior with a normal statistical baseline, and optionally uses a genuinely trained Random Forest. It combines those signals into a configurable 0–100 risk score, stores flows and alerts in SQLite, and exposes a FastAPI/React SOC dashboard. An analyst can filter and investigate an alert, review evidence, add notes, and move it through new, investigating, resolved, or false-positive states. I generated 5,000 records, evaluated three ML approaches, and ran 53 automated tests.

## 2. What is an IDS, and how does it differ from an IPS?

An IDS monitors telemetry, identifies potentially suspicious behavior, and alerts people or downstream systems. An IPS can sit inline and automatically take preventive action. I intentionally built an IDS because this project focuses on evidence, explainability, triage, and safe analyst judgment rather than blocking traffic. Automatic action based on a student baseline could disrupt legitimate activity.

## 3. Why did you combine signature and anomaly detection?

Signatures are fast and explainable for configured patterns but can miss behavior outside the rules. Anomaly detection can highlight unusual or unseen behavior but may produce false positives when legitimate workloads change. My hybrid design preserves the matched rule reason and statistical context, then combines them with optional ML. Multiple methods broaden coverage, but agreement is still not proof of malicious intent.

## 4. Which network features did you engineer and why?

I used packet/byte counts, duration, packets and bytes per second, average packet size, connection and failure counts, failure ratio, SYN/RST counts, SYN ratio, destination-port/IP diversity, and connection rate. Rates make differently sized windows comparable; ratios normalize failures and SYN behavior; diversity captures fan-out; raw counts preserve volume context. I explicitly handled zero duration, missing counts, invalid ports/protocols, malformed IPs, and non-finite values.

## 5. How does your anomaly detector work?

I fit a baseline from normal synthetic rows for packet rate, byte rate, connection rate, failure ratio, and destination-port diversity. For each new flow I calculate absolute Z-score, IQR distance, and moving-mean deviation, scale those per feature, and combine the strongest deviations into a 0–100 anomaly score. The API returns component explanations. This can detect unusual patterns, but a backup or maintenance burst may also be anomalous, so an analyst must validate context.

## 6. How do risk scoring and alert generation work?

A rule risk comes from matched-rule severity and count. With ML enabled I weight rule, anomaly, and ML scores 40%, 30%, and 30%; without ML I use 60% and 40%. The score maps to normal, low risk, suspicious, high risk, or critical investigation and to alert severity. A matching rule or risk above 40 creates an alert with endpoints, reason, scores, rule IDs, recommendations, and status. The weights and thresholds are transparent project assumptions that a real SOC must calibrate.

## 7. How did you use and evaluate machine learning?

I trained supervised Logistic Regression and Random Forest models on ten numerical flow features with a stratified 80/20 split. I also fit an unsupervised Isolation Forest on normal training rows. The scripts calculate accuracy, precision, recall, F1, ROC-AUC, and confusion matrices from the held-out split and save the results; nothing is hard-coded. I selected Random Forest for API probability but retained the other bundles for comparison. Accuracy alone is misleading under imbalance, so I pay close attention to recall and false-positive-driving precision.

## 8. What are false positives and false negatives, and how would you reduce them?

A false positive flags legitimate activity, such as an authorized backup, while a false negative misses genuinely suspicious behavior. Excessive false positives cause alert fatigue; false negatives leave activity unseen. I would improve the balance through per-asset/time baselines, threshold sweeps, contextual enrichment, tuned signatures, detector diversity, analyst feedback, and periodic validation for drift. I would choose operating points based on business impact, not only a global metric.

## 9. How did you test the project safely and thoroughly?

I generated rows representing normal TCP, UDP, DNS and HTTPS plus high connections, repeated failures, destination-port diversity, SYN-heavy statistics, unusual ports, and high volume. No raw socket or packet-generation code exists. My 53 automated tests cover validation boundaries, feature math, every rule, anomaly/risk behavior, alerts and correlation, database storage, API authentication/authorization, status transitions, notes, dashboard statistics, ML probability range, empty baselines, and duplicates. I also built the frontend and preserved actual test/evaluation reports.

## 10. How would you improve it for a real SOC?

I would ingest only authorized NetFlow, cloud flow logs, Zeek, Suricata, or approved PCAP-derived telemetry; move to a streamed queue and PostgreSQL/analytics store; integrate SSO/RBAC, TLS, secrets management, centralized audit logs, and SIEM forwarding; add asset, identity, threat-intelligence and change-window context; build dynamic per-entity baselines; measure drift; improve correlation and explainability; and tune rules with analyst outcomes. I would retain the rule that anomalies are evidence, not automatic attribution or blocking decisions.
