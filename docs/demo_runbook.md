# Complete Virtual Simulation Runbook

This demonstration needs no network lab. It sends JSON data to localhost; it does not generate network packets.

## One-time setup

```bash
python -m venv .venv
source .venv/bin/activate                 # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m simulator.generate_dataset --count 5000 --output data/network_traffic.csv --seed 42
python -m ml.train_model
cd frontend && npm install && cd ..
```

## Step 1 — Generate the synthetic dataset

```bash
python -m simulator.generate_dataset
```

Expected: `Generated 5000 synthetic flow records: data/network_traffic.csv`.

## Step 2 — Start the backend

```bash
uvicorn backend.app:app --host 0.0.0.0 --port 8000
```

Verify: `curl http://127.0.0.1:8000/health`.

## Step 3 — Start the frontend

```bash
cd frontend
npm run dev -- --host 0.0.0.0
```

Open `http://127.0.0.1:5173`.

## Step 4 — Start the flow-data simulator

In the repository root:

```bash
python -m simulator.traffic_simulator --mode mixed --speed fast --count 30
```

## Step 5 — Send a normal HTTPS flow

```bash
curl -s -X POST http://127.0.0.1:8000/api/flows \
  -H 'Content-Type: application/json' -H 'X-API-Key: dev-analyst-key' -H 'X-Role: analyst' \
  -d '{"flow_id":"DEMO-NORMAL-001","source_ip":"192.0.2.10","destination_ip":"198.51.100.20","source_port":51000,"destination_port":443,"protocol":"TCP","packet_count":40,"byte_count":30000,"duration_seconds":5,"connection_count":3,"failed_connection_count":0,"syn_count":2,"rst_count":0,"unique_destination_ports":1,"unique_destination_ips":1,"scenario_type":"NORMAL_WEB"}'
```

Expected: `NORMAL`, no signature match, typically no alert.

## Step 6 — Send a high-connection/failure data record

```bash
curl -s -X POST http://127.0.0.1:8000/api/flows \
  -H 'Content-Type: application/json' -H 'X-API-Key: dev-analyst-key' -H 'X-Role: analyst' \
  -d '{"flow_id":"DEMO-ABNORMAL-001","source_ip":"192.0.2.15","destination_ip":"198.51.100.20","source_port":49152,"destination_port":443,"protocol":"TCP","packet_count":800,"byte_count":900000,"duration_seconds":2,"connection_count":200,"failed_connection_count":15,"syn_count":100,"rst_count":3,"unique_destination_ports":1,"unique_destination_ips":10,"scenario_type":"HIGH_CONNECTION_RATE"}'
```

Expected: `SUSPICIOUS`/`HIGH RISK`/`CRITICAL INVESTIGATION` depending on calculated anomaly and ML evidence; IDS-001 and IDS-002 match.

## Step 7 — Send a multi-port summarized pattern

```bash
curl -s -X POST http://127.0.0.1:8000/api/flows \
  -H 'Content-Type: application/json' -H 'X-API-Key: dev-analyst-key' -H 'X-Role: analyst' \
  -d '{"flow_id":"DEMO-MULTIPORT-001","source_ip":"192.0.2.44","destination_ip":"203.0.113.25","source_port":53000,"destination_port":443,"protocol":"TCP","packet_count":120,"byte_count":50000,"duration_seconds":3,"connection_count":50,"failed_connection_count":2,"syn_count":35,"rst_count":5,"unique_destination_ports":35,"unique_destination_ips":8,"scenario_type":"MULTI_PORT_PROBING_PATTERN"}'
```

Expected: IDS-003 is triggered. This is only a summarized record—not a scan.

## Step 8 — Verify the dashboard

Wait at most five seconds. Confirm cards, timelines, severity/type/protocol/port/source/risk charts, and alert table update.

## Step 9 — Open an alert

Choose **Alerts → Investigate**. Verify ID, endpoints, protocol/ports, traffic rates, matched rule, anomaly score, ML score, final risk, reason, and recommendations.

## Step 10 — Move `NEW → INVESTIGATING`

Use the investigation status control, or replace `$ALERT_ID` below:

```bash
curl -s -X PUT "http://127.0.0.1:8000/api/alerts/$ALERT_ID/status" \
  -H 'Content-Type: application/json' -H 'X-API-Key: dev-analyst-key' -H 'X-Role: analyst' \
  -d '{"status":"INVESTIGATING"}'
```

## Step 11 — Add an analyst note

```bash
curl -s -X POST "http://127.0.0.1:8000/api/alerts/$ALERT_ID/notes" \
  -H 'Content-Type: application/json' -H 'X-API-Key: dev-analyst-key' -H 'X-Role: analyst' \
  -d '{"note":"Compared with the synthetic baseline and reviewed related authorized logs; documenting for demonstration."}'
```

## Step 12 — Resolve or mark false positive

```bash
curl -s -X PUT "http://127.0.0.1:8000/api/alerts/$ALERT_ID/status" \
  -H 'Content-Type: application/json' -H 'X-API-Key: dev-analyst-key' -H 'X-Role: analyst' \
  -d '{"status":"RESOLVED","resolution_notes":"Synthetic demonstration reviewed and closed."}'
```

Use `FALSE_POSITIVE` instead only when evidence indicates expected behavior. Never treat the score alone as proof.
