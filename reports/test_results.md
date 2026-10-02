# Automated Test Strategy and Actual Results

**Execution date:** 2026-09-29  
**Command:** `pytest -q`  
**Actual result:** **53 passed, 1 dependency deprecation warning in 4.42 seconds**. The warning is from FastAPI TestClient's transitional httpx compatibility and does not indicate a failed assertion.

## Required 30-case traceability

| Test ID | Scenario | Input | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| T01 | Normal TCP flow | TCP/443 normal rates | No signature | No matches | PASS |
| T02 | Normal UDP flow | UDP/53, no SYN | No signature | No matches | PASS |
| T03 | Normal DNS flow | 2 packets, 240 B | Average packet = 120 B | 120 B | PASS |
| T04 | Normal HTTPS flow | destination 443 | Valid normalized flow | Port 443 retained | PASS |
| T05 | High connection rate | 200 connections / 2 s | IDS-001 | IDS-001 matched | PASS |
| T06 | Repeated failed connections | 15 failures / 30 | IDS-002 | IDS-002 matched | PASS |
| T07 | Multi-port pattern | 35 unique ports | IDS-003 | IDS-003 matched | PASS |
| T08 | SYN-heavy pattern | 85 SYN / 100 packets | IDS-004 | IDS-004 matched | PASS |
| T09 | High traffic volume | 7,000,000 bytes | IDS-006 | IDS-006 matched | PASS |
| T10 | Invalid source IP | `999.1.1.1` | Validation error | `FlowValidationError` | PASS |
| T11 | Invalid destination IP | `not-an-ip` | Validation error | `FlowValidationError` | PASS |
| T12 | Invalid source port | 70000 | Validation error | `FlowValidationError` | PASS |
| T13 | Invalid destination port | -1 | Validation error | `FlowValidationError` | PASS |
| T14 | Unsupported protocol | SCTP | Validation error | `FlowValidationError` | PASS |
| T15 | Missing packet count | field absent | Default safely to 0 | 0 | PASS |
| T16 | Zero duration | duration 0 | Finite rate/no crash | Finite clamped rate | PASS |
| T17 | Feature extraction | 30 KB / 5 s, 40 packets | 6,000 B/s, 8 pkt/s | Exact values | PASS |
| T18 | Rule detection | rate + 8 MB | Multiple rules | ≥2 matches | PASS |
| T19 | Anomaly score | extreme five-feature row | Score >80 | Score exceeded 80 | PASS |
| T20 | Risk score | rule 75, anomaly 50, no ML | 65 / HIGH RISK | Exact result | PASS |
| T21 | Alert creation | high-rate match | NEW `ALT-*` alert | Correct ID/state | PASS |
| T22 | Alert correlation | same source/type, 30 s | One incident, two alerts | Exact group/max risk | PASS |
| T23 | Alert status update | NEW → INVESTIGATING | State/time saved | API returned state/time | PASS |
| T24 | Analyst note | defensive note | Persist and return | Note stored | PASS |
| T25 | Database storage | POST `STORE-1` | GET same flow | HTTP 200 and same ID | PASS |
| T26 | Dashboard statistics | one stored alert flow | totals/open = 1 | Exact totals | PASS |
| T27 | ML prediction | suspicious test flow | Absent if disabled or probability 0–1 | Probability contract met | PASS |
| T28 | API validation | source port 70000 | HTTP 422 | HTTP 422 | PASS |
| T29 | Empty dataset | no baseline rows | Reject fit | `ValueError` | PASS |
| T30 | Duplicate event handling | same `flow_id` twice | HTTP 409 | HTTP 409 | PASS |

## Additional automated coverage

Tests T31–T53 verify failure-count consistency, severity-derived rule risk, use-before-fit protection, malformed timestamp, health, missing authentication, alert creation, chart endpoints, read-only viewer restrictions, rule updates, filters, alert context, incident API, ML probability, terminal transition enforcement, `/score` compatibility, classification/severity boundaries, explicit ML weights, invalid weights, unusual ports, disabled rules, and correlation windows.

## Scope of test levels

- **Unit:** validation, feature arithmetic, rules, anomaly, risk, alert and correlation.
- **Integration:** SQLite relations, model inference, application service.
- **API:** authentication/authorization, validation/status codes, CRUD-like workflow, dashboard aggregations.
- **Build verification:** `npm run build` completed successfully (1,572 modules transformed).

Raw console proof is in `reports/pytest_console.txt`; a visual proof is `screenshots/22_automated_tests.png`.
