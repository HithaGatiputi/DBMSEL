# Quick start: run it, open it, query it

All commands run in Terminal from the project folder:

```bash
cd "/Users/hithagatiputi/Documents/RVCE/DBMS EL/DBMSEL"
```

## 1. The project in short

**Cybersecurity Incident Management & Investigation System.** Thousands of security logs (logins, file access, network flows, privilege changes) are stored in a **normalised PostgreSQL database**, with the raw original logs in **MongoDB**. Inside the database:

* **triggers** score every event and raise **alerts**;
* a **correlation function** groups related alerts (same user / IP / device within 30 minutes) into **multi-stage incidents** with an ordered timeline and an **explainable 0–100 risk score**;
* critical incidents are **contained automatically**: attacker IPs are blocked and compromised accounts disabled, and anything they try afterwards is flagged ⛔ blocked (Admin → **Security self-test** shows 13/13 attacks on the system itself blocked);
* analysts work incidents through **stored procedures** (assign → act → contain → resolve), and every change is written to an **append-only audit log** by triggers, so nothing can be tampered with.

**Machine learning** (Isolation Forest + XGBoost, trained on the real **CIC-IDS2017** and **CTU-13** datasets) scores each event before it is stored. On real botnet traffic the model had never seen, it flagged **6/6 infected machines and 0/12 clean ones**. A web **dashboard** shows everything, and **Ask AI** answers plain-English questions by generating SQL that is validated and runs on a read-only database role.

**Stack:** PostgreSQL 16 · MongoDB 8 · Python (FastAPI, scikit-learn, XGBoost) · HTML/JavaScript · free local AI model (qwen2.5-coder 7B via Ollama; keep the Ollama app running).

## 2. Start / stop

| What | Command |
|---|---|
| Fresh start with clean demo data (before a demo) | `scripts/run_all.sh` |
| Start the databases only | `scripts/services.sh start` |
| Start the website (databases must be running) | `.venv/bin/python -m app.cli serve` |
| Stop the website | `Ctrl+C` in its Terminal window |
| Stop the databases | `scripts/services.sh stop` |

`run_all.sh` rebuilds the database, so run step 4's dataset import again afterwards if you want the raw datasets in PostgreSQL.

## 3. The website

Open **http://127.0.0.1:8765** and sign in (password `Rvce@2026`):

* `admin.iyer`: Admin (inject attacks, manage users/devices/rules, integrity check)
* `analyst.rao`, `analyst.menon`, `analyst.das`: Analysts

Tabs: **Overview** (KPIs, inject attack, ML results) · **Incidents** (timeline, risk breakdown, actions, report) · **Alerts** · **Events** · **Ask AI** · **SQL Reports** (15 named queries + CSV) · **Raw Logs** (MongoDB search) · **Audit** · **Admin** · **Design** (your diagrams) · **How to use**.

Interactive API documentation: **http://127.0.0.1:8765/docs**.

## 4. Open the database (PostgreSQL)

| What | Command |
|---|---|
| Open psql as the owner | `scripts/db.sh psql` |
| Run one query | `scripts/db.sh sql "SELECT * FROM v_incident_summary LIMIT 5"` |
| Open the read-only role used by Ask AI | `scripts/db.sh ro` |
| Connection details for pgAdmin / DBeaver / TablePlus | `scripts/db.sh info` |
| Full guided tour with real output | open `docs/DATABASE_TOUR.md` (regenerate: `.venv/bin/python -I scripts/db_tour.py`) |

Inside psql: `\dt` tables · `\d security_events` one table · `\dv` views · `\df fn_*` functions · `\dn` schemas · `\q` quit.

### The raw datasets inside PostgreSQL

Load them (about 35 s; re-run after `run_all.sh`):

```bash
.venv/bin/python -I scripts/import_datasets.py
```

This creates schema **`datasets`**: `cicids2017_flows` (2.83 M flows), `ctu13_flows` (scenarios 5, 11, 12, 562 K flows) and `ctu13_scenarios`. Add `--ctu all` for all 13 CTU-13 captures (about 20 M rows, slower).

Example queries:

```sql
-- attack types in CIC-IDS2017
SELECT label, COUNT(*) FROM datasets.cicids2017_flows GROUP BY label ORDER BY 2 DESC;

-- average traffic profile: attack vs benign
SELECT is_attack, AVG(bytes_sent) AS avg_sent, AVG(duration_us)/1e6 AS avg_seconds
FROM datasets.cicids2017_flows GROUP BY is_attack;

-- infected machines in a CTU-13 capture
SELECT scenario, src_addr, COUNT(*) AS botnet_flows
FROM datasets.ctu13_flows WHERE kind = 'botnet'
GROUP BY 1,2 ORDER BY 3 DESC;
```

The application uses the datasets this way: ML training and testing (`app/flowml.py`), real flows inside the simulator (`app/generator.py`), and **replaying held-out CTU-13 botnets through the live pipeline** (`app/ctu13.py`). The replayed traffic appears in the app's own tables with `event_source = 'ctu13'`.

## 5. Open MongoDB (raw logs)

| What | Command |
|---|---|
| MongoDB shell | `scripts/db.sh mongo` |
| One document | `db.raw_logs.findOne()` |
| Full-text search | `db.raw_logs.find({$text: {$search: "polkit"}})` |
| GUI (MongoDB Compass) | paste the connection string from `scripts/db.sh info` |

## 6. Where the code is

| Folder / file | What it contains |
|---|---|
| `db/01_schema.sql` | tables, keys, constraints (ER diagram → relations) |
| `db/02_functions.sql` | risk scoring, correlation, analyst procedures |
| `db/03_triggers.sql` | scoring, alerts, audit, append-only rules |
| `db/04_views.sql`, `05_roles.sql` | views, materialized view, database roles |
| `app/main.py` | the web API (all endpoints) |
| `app/ingest.py` | ML score → MongoDB → PostgreSQL pipeline |
| `app/ml.py`, `app/flowml.py` | the two ML models |
| `app/agent.py`, `app/sqlguard.py`, `app/llm.py` | Ask AI, the SQL validator, AI providers |
| `app/sql_reports.py` | the 15 SQL reports |
| `frontend/` | the website (HTML, CSS, JavaScript) |
| `scripts/` | start/stop, setup, database helpers, tour, importer |
| `tests/` | 71 automated tests (`.venv/bin/python -m pytest tests -q`) |
| `docs/` | design document, user guide, database tour, this file |

## 7. Useful commands

| Command | Does |
|---|---|
| `.venv/bin/python -m app.cli evaluate-ctu` | real-data results (infected / clean hosts flagged) |
| `.venv/bin/python -m app.cli evaluate` | correlation quality on simulated attacks |
| `.venv/bin/python -m app.cli ctu-replay 11` | replay another real botnet capture |
| `.venv/bin/python -m app.cli train-flow` | retrain the real-data flow model (~4 min) |
| `.venv/bin/python -m pytest tests -q` | run all tests |
| `.venv/bin/python -I scripts/eval_nl2sql.py` | measure how well Ask AI answers |
