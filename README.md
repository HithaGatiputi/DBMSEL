# Cybersecurity Incident Management & Investigation System

RVCE · DBMS (CD252IA). A hybrid PostgreSQL + MongoDB platform. It ingests security telemetry, scores it with database rules and two ML models (one trained on real CIC-IDS2017 + CTU-13 traffic), raises alerts by trigger, correlates them into incidents inside PostgreSQL, makes every analyst action accountable through transactions and an append-only audit trail, and lets investigators query the data in plain English through a validated, read-only SQL path.

```bash
scripts/run_all.sh      # then open http://127.0.0.1:8765  (analyst.rao / admin.iyer, password Rvce@2026)
```

* **How to use it:** [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
* **Design** (objectives, scope, SRS, ER→schema mapping, normalisation, DFD→code, SQL+NoSQL, security, societal relevance, limitations): [docs/DESIGN.md](docs/DESIGN.md)
* **Diagrams:** [docs/diagrams/](docs/diagrams/)
* **Datasets and real-data evaluation:** sections 11–12 of [docs/DESIGN.md](docs/DESIGN.md)

## Layout

| Path | Contents |
|---|---|
| `db/01_schema.sql` | tables mapped from the ER diagram (incl. the disjoint ISA enforced by a composite FK) |
| `db/02_functions.sql` | risk scoring, correlation, entity roles, analyst procedures |
| `db/03_triggers.sql` | scoring, alerting, last_seen, state machine, append-only tables, audit |
| `db/04_views.sql` | enriched views, materialized explainable-risk view |
| `db/05_roles.sql` | least-privilege roles (`dbmsel_app`, read-only `dbmsel_ro`) |
| `db/06_kb_seed.sql`, `db/07_rules_seed.sql` | MITRE/NIST/policy knowledge base; detection rules |
| `app/` | FastAPI backend: ingest, ML, MongoDB store, agent, SQL guard, reports, auth, automation |
| `frontend/` | dashboard (vanilla JS) |
| `tests/` | SQL-guard, database and API tests |

## Requirements

PostgreSQL 16 (Homebrew path in `scripts/services.sh`, override with `PGBIN`), MongoDB (optional), Python 3.12. `run_all.sh` creates `.venv` and installs `requirements.txt`. `ANTHROPIC_API_KEY` is optional (see `.env.example`).
