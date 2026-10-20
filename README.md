# 🚨 SOC Acolyte

**The security-operations service of the [Talia](https://github.com/Baderholdjr/Talia-project) platform.** Ingests logs, runs a YAML-driven detection rules engine with UEBA, enriches alerts with threat intelligence, and exposes alert triage and response-action APIs.

**Status:** V2 prototype (2025). Runs locally with Docker Compose. No automated tests or auth layer yet — see [Known gaps](#known-gaps).

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL_14-4169E1?style=flat&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker_Compose-2496ED?style=flat&logo=docker&logoColor=white)

## How it works

```
 raw logs ──POST /ingest/logs──▶ parsing_service ──▶ security_events (PostgreSQL)
                                      │  structured fields; LLM parsing stub for unstructured text
                                      ▼
                        ┌──── rules_engine (rules/*.yml) ────┐
                        │     count / time-window triggers   │
                        │                                    ▼
                        │  ueba_service ──▶ user_activity baseline ──▶ anomalous-login-time alerts
                        ▼
                      alerts ──▶ cti_service (VirusTotal) enrichment ──▶ anonymizer_service
                        │
                        ├── GET /alerts · GET /alerts/summary · PATCH /alerts/{id}/status
                        ├── POST /alerts/{id}/actions  (response_action_service)
                        └── GET /inquisitor/fetch-data  (pulled by The Inquisitor agent)
```

| Component | What it does |
| --- | --- |
| `parsing_service` | Normalizes incoming log lines into `security_events` rows; `nlp_service` is the hook for LLM-based parsing of unstructured logs (Gemini endpoint stubbed, not wired to a key) |
| `rules_engine` | Loads every `rules/*.yml`; evaluates `conditions` (field / operator / value) and `trigger` (count over a time window) against stored events |
| `ueba_service` | Builds a per-user login-time baseline from `user_activity` and raises `UEBA-ANOMALY-001` on deviations |
| `cti_service` | Enriches alert indicators via the VirusTotal API (`VIRUSTOTAL_API_KEY`) |
| `anonymizer_service` | Scrubs identifying fields before alerts leave the service |
| `response_action_service` | Records and executes response actions against an alert (`POST /alerts/{id}/actions`) |

## Detection rules

Rules are plain YAML in `rules/`. Example, `SOC-RULE-001`:

```yaml
id: "SOC-RULE-001"
name: "Multiple Failed Logins Detected"
severity: "MEDIUM"
conditions:
  all:
    - field: "security_events.source_host"
      operator: "equals"
      value: "{source_host}"
    - field: "security_events.parsed_data.action"
      operator: "equals"
      value: "login_failed"
trigger:
  type: "count"
  operator: "greater_than_or_equal_to"
  value: 5
  time_window_minutes: 5
```

Add a file, restart the service, and the rule is live. UEBA rules (`ueba-*.yml`) declare metadata only; their logic lives in `ueba_service`.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/ingest/logs` | Submit raw log entries |
| `GET` | `/alerts` | List alerts (filterable) |
| `GET` | `/alerts/summary` | Counts by severity / status |
| `PATCH` | `/alerts/{alert_id}/status` | Triage: open → investigating → closed |
| `POST` | `/alerts/{alert_id}/actions` | Record or execute a response action |
| `GET` | `/inquisitor/fetch-data` | Snapshot endpoint for the Inquisitor deployment agent |
| `GET` | `/` | Health |

Interactive docs at `http://localhost:8001/docs` once running.

## Quick start

```bash
git clone https://github.com/Baderholdjr/SOC-Acolyte.git && cd SOC-Acolyte
export VIRUSTOTAL_API_KEY=...        # optional; enrichment is skipped without it
docker compose up --build
```

Compose starts PostgreSQL 14 (host port 5433), runs Alembic migrations, and serves the API on port 8001 with hot reload. Schema history is in `alembic/versions/`.

## Known gaps

- No automated tests or CI
- No authentication on the API (intended to sit behind the Inquisitor / platform gateway)
- LLM log parsing is a stub; the Gemini call is commented out pending key management
- Rule evaluation is query-per-rule; no streaming or batching

Lessons from this service fed the next project, [ONI](https://github.com/Baderholdjr/grc-readiness) — GRC-as-code with CI gates and a 244-test suite.

## Author

Bernard A. Aderhold Jr., DBA — [GitHub profile](https://github.com/Baderholdjr) · [LinkedIn](https://www.linkedin.com/in/bernard-aderhold-jr-dba-963ab9305)

## License

[PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/) — free for noncommercial use; commercial use by arrangement. © 2025–2026 Bernard A. Aderhold Jr.
