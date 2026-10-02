# REST API Contract

Base URL: `http://127.0.0.1:8000`. All `/api` calls require `X-API-Key`; modifying calls require `X-Role: analyst`. `viewer` is read-only. JSON validation failures return 422, invalid credentials 401, insufficient role 403, missing object 404, duplicate/invalid transition 409, rate limit 429, and sanitized server failure 500. OpenAPI is at `/docs`.

## Common flow request

```json
{
  "flow_id": "DEMO-001",
  "timestamp": "2026-09-29T10:00:00+00:00",
  "source_ip": "192.0.2.15",
  "destination_ip": "198.51.100.20",
  "source_port": 49152,
  "destination_port": 443,
  "protocol": "TCP",
  "packet_count": 40,
  "byte_count": 30000,
  "duration_seconds": 5,
  "connection_count": 3,
  "failed_connection_count": 0,
  "syn_count": 2,
  "rst_count": 0,
  "unique_destination_ports": 1,
  "unique_destination_ips": 1,
  "scenario_type": "NORMAL_WEB"
}
```

IP, port, protocol, count/range/consistency and timestamp validation is server-side. Extra fields are rejected.

## Endpoints

### `POST /api/flows` (and compatibility alias `POST /score`)

Analyzes and stores one record. Request is the flow above. Response `201` includes `flow_id`, classification, severity, risk score, derived features, all rule matches, anomaly score/components, optional ML result, and optional alert. A duplicate `flow_id` returns `409`. Analyst role required.

### `GET /api/flows`

Query: optional `protocol`, `classification`; `limit` 1–1000 (default 100), non-negative `offset`. Response `200`: `{items, limit, offset}` ordered newest first.

### `GET /api/flows/{id}`

Response `200` is the stored observation plus `model_results`; `404` if absent.

### `GET /api/alerts`

Query filters: `severity`, `protocol`, exact `alert_type`, `status`, `time_range` (`1h|24h|7d|30d`), `limit`, `offset`. Response is a paged newest-first queue. Invalid range returns `422`.

### `GET /api/alerts/{id}`

Returns complete alert, notes, source flow, optional model results, matched rule IDs and recommended defensive steps. `404` if absent.

### `PUT /api/alerts/{id}/status`

Analyst request:

```json
{"status":"INVESTIGATING","resolution_notes":null}
```

`NEW` can stay new or move to investigating/resolved/false-positive. `INVESTIGATING` can stay or become resolved/false-positive. Terminal states cannot be reopened in this version. The first investigating change records `investigation_timestamp`; resolution text is capped at 4,000 characters. Response is the updated alert. Invalid transition `409`.

### `POST /api/alerts/{id}/notes`

Analyst request: `{"note":"Reviewed authorized firewall logs; change ticket found."}`. Notes are 1–4,000 characters and are returned with ID/time. Missing alert `404`.

### `GET /api/incidents`

Optional `window_seconds` 1–86,400, default 60. Returns alert groups sharing source/type within the window, with underlying IDs/count/first-last time/max risk/status.

### `GET /api/dashboard/stats` (alias `GET /stats`)

Returns total/normal/suspicious flows, average risk, total/open/critical alerts, and optional ML enabled state.

### `GET /api/dashboard/traffic`

Returns minute timeline with flow, packets/s, bytes/s, connections, failures and average risk; plus protocol, destination-port, and classification distributions.

### `GET /api/dashboard/alerts`

Returns severity, top type, top source, risk-band, and alert/risk timeline data.

### `GET /api/rules`

Returns seven persisted rules including ID/name/description/severity/threshold/enabled/update time.

### `PUT /api/rules/{id}`

Analyst request may include `threshold` (non-negative number, or non-empty port list for IDS-005), `enabled`, and `severity`. Response is the updated in-memory and persisted rule. Unknown ID `404`; invalid threshold/severity `422`.

### `GET /health`

Unauthenticated liveness response with `status`, safe mode, and ML availability. It reveals no database content.

## Error shape

```json
{"detail":"human-readable reason"}
```

Validation errors use FastAPI's structured `detail` array. Stack traces, SQL, secrets, and filesystem paths are never returned. Production should add TLS, gateway controls, enterprise identity/RBAC, persistent distributed rate limiting, request IDs, and centralized audit storage.
