# Security and Privacy

## Implemented controls

- Synthetic RFC 5737 addresses only; no payloads or credentials.
- Pydantic + domain validation, size-limited notes, fixed protocol/status enums, finite non-negative statistics.
- Parameterized SQLite, foreign keys, uniqueness, risk range checks, indexes, and transaction rollback.
- API key authentication, analyst/viewer authorization, per-key in-memory rate limit, restricted CORS, and generic 500 output.
- React text escaping; no dangerous HTML rendering.
- Audit events for flow submission, status/rule changes, and notes.
- Secrets are environment variables and `.env` is ignored.

## Production controls required

Terminate TLS; rotate secrets through a secret manager; replace the demonstration API key with SSO/OIDC and fine-grained RBAC; put durable distributed rate limiting at the gateway; encrypt database/backups; restrict network access; centralize immutable audit logs; patch dependencies; add CSP/security headers; redact sensitive logs; define retention and legal access; monitor authentication and model drift; and run with least-privilege service/database accounts.

IDS data itself is sensitive. Endpoint names/addresses, open services, traffic timing, security controls, suspected weaknesses, and analyst notes can reveal architecture or active investigation. Access, retention, sharing, and backup must therefore be controlled even when payloads are absent.

## Ethical boundary

This repository detects statistical **records** only. Do not adapt it to probe, scan, exploit, disrupt, flood, evade, steal, or operate against systems without explicit authorization. Production ingestion should accept only authorized telemetry.
