# User Guide

## 1. Start the system

From the project folder (`DBMSEL`):

```bash
scripts/run_all.sh
```

This starts PostgreSQL (port 5433) and MongoDB (port 27018), rebuilds the database, trains the ML models (the real-data flow model only on first run, about 4 minutes), loads 7 days of simulated activity plus real botnet traffic from 3 CTU-13 captures, correlates it, and serves the app. Open **http://127.0.0.1:8765**.

Later runs, when you don't want to rebuild the data:

```bash
scripts/services.sh start
```

```bash
.venv/bin/python -m app.cli serve
```

To stop the databases:

```bash
scripts/services.sh stop
```

## 2. Accounts

| Username | Role | Password |
|---|---|---|
| analyst.rao, analyst.menon, analyst.das | Security Analyst | `Rvce@2026` |
| admin.iyer, admin.singh | System Administrator | `Rvce@2026` |

Only Analyst and Admin accounts can sign in. Accounts an Admin creates (or resets) get a temporary password that must be changed at first sign-in. Click your name in the header to change your own password.

**Who can do what:** analysts pick up *unassigned* incidents and work only on their own (actions, evidence, status). Admins can re-assign and act on any incident, inject simulated attacks, run the integrity check and manage users, devices and rules. Resolving, closing or marking False Positive needs a written reason.

**Secrets:** database passwords and the login-token key are generated per machine in `~/.dbmsel/secrets.env` (outside the project), so zipping the project for submission is safe. Delete that file only together with `.pgdata/` and `.mongodata/`. Employees, executives and service accounts are monitored, not users of the console.

## 3. Demo script (about 8 minutes)

1. **Sign in** as `analyst.rao`. The **Overview** shows events, alerts, open incidents, incidents assigned to you, charts, and the ML model's metrics.
2. **Inject an attack** (signed in as `admin.iyer`): choose `account_takeover_exfil` and press **Inject attack**. About 18 events pass through the ML scorer into MongoDB and PostgreSQL. Triggers raise alerts, correlation builds the incident, and the incident page opens.
3. **Investigate the incident:**
   * The *Analysis* text and *kill chain* (MITRE tactics) are built only from the stored evidence.
   * The *Event timeline* lists each step with risk, anomaly score, detail and a data badge (*simulated* / *CTU-13 real*). **raw log (MongoDB)** opens the original document with an **integrity verified** badge: its SHA-256 is recomputed and compared with the hash PostgreSQL stored at ingest. **±30 min context** shows nearby events that share a user, IP or device (`fn_event_window`).
   * *Why this risk score?* lists the five components computed in SQL.
   * *Findings* and *Framework context* list detected patterns and the matching MITRE ATT&CK, NIST and policy guidance.
4. **Work the incident:** press **Assign to me**. The status becomes *Investigating*, and an ASSIGN action and audit rows appear. Record a *Containment* action with notes, then change the status to *Contained*. The status list only offers legal next states, and the database also rejects illegal jumps.
5. **Accountability:** sign out and sign in as `analyst.menon`. Open the same incident: the controls are gone, because it belongs to another analyst. Analysts cannot take over a colleague's incident; only an Admin can re-assign it.
6. **Containment** (as `admin.iyer`): open a Critical incident, e.g. one titled "Account takeover…" or "Reconnaissance…". Its **Response & containment** card shows what was blocked **automatically**: the attacker's IP, and the compromised account (never staff accounts; those are flagged for review). Press **🔁 Simulate the attacker returning**: every new attempt is marked **⛔ BLOCKED** on the timeline, raises an alert, and is added to the same incident. Lifting a block needs an Admin and a reason, and both blocking and lifting appear in the audit trail.
7. **Security self-test** (as `admin.iyer`): **Admin → 🛡 Security self-test → Run**. The system is attacked 13 ways (brute force, forged token, SQL injection through AI, evidence tampering, privilege abuse, raw-log editing, returning attacker) and shows each one blocked, with the database's own error message. Nothing is changed.
8. **Report:** press **Download report** for a Markdown incident report (summary, timeline, entities, findings, risk breakdown, MITRE context, actions, audit trail).
7. **Alerts / Events:** alerts raised by the trigger, grouped by detection rule. Events can be filtered by category, risk and alert flag; click a row to see its raw log.
8. **Ask AI:** try "Which users had the most failed logins?", "Transfers larger than 100 MB" and "Analyst workload". The generated SQL is shown and validated. Then try "drop table users": it is blocked.
9. **SQL Reports:** 15 named queries showing DBMS concepts. Each shows its SQL and live result and can be downloaded as CSV.
10. **Raw Logs:** search MongoDB full-text, e.g. `polkit`, `Emotet`, `Mirai`, `backup`.
11. **Audit:** every incident change with who, when, old value and new value. These rows cannot be changed or deleted.
12. **Admin** (sign in as `admin.iyer`):
    * *Users:* create a user (try an invalid email or a weak password to see validation), deactivate or reactivate, reset a password.
    * *Devices:* register a device (hostname, IP and MAC are validated) and change criticality.
    * *Detection rules:* change base risk or ML threshold, or switch a rule off.
    * *Automation:* run the **evidence integrity check**, and turn the live stream on. New events and occasional attacks arrive every 10 seconds, and correlation runs on a schedule.
    * *Change history:* every admin change, written by triggers.
13. **Real botnet data:** on **Overview**, the flow-model card shows the real-data results. In **SQL Reports**, open *Real botnet replay (CTU-13): alerts per host* to see which replayed machines raised alerts. In **Incidents**, look for titles ending in `[ctu…]`.
14. **Design** tab: objectives, normalisation summary, SQL + NoSQL integration, societal relevance, and the ER, relational and DFD diagrams. Click a diagram to enlarge it.

## 3b. Live attack demo (best for presentations)

1. Start the website and sign in as `admin.iyer`; stay on the **Dashboard**.
2. In a **second Terminal window**, from the project folder:
   ```bash
   .venv/bin/python scripts/live_attack.py
   ```
3. Put the two windows side by side. The Terminal narrates each attacker step and the system's reaction. The website shows banners at the top as alerts arrive, then **"Contained automatically"** when the break-in succeeds, then **"attacker attempts blocked"**, and the *Attacker attempts blocked* counter climbs.
4. Afterwards open the incident it names (Incidents → #N): the timeline shows the attack step by step, with every step after the break-in marked ⛔ BLOCKED.

Other attacks: `--scenario recon_bruteforce`, `malware_outbreak`, `insider_data_theft`, `privilege_abuse`. Slower or faster: `--delay 3`. Everything it creates is tagged *simulated*.

## 4. Command line

| Command | Does |
|---|---|
| `.venv/bin/python -m app.cli reset` | drop and rebuild the database from `db/*.sql` |
| `.venv/bin/python -m app.cli train` | train the ML models, print metrics |
| `.venv/bin/python -m app.cli seed` | load simulated data and the 3 held-out CTU-13 botnets, correlate, replay analyst history |
| `.venv/bin/python -m app.cli train-flow` | train and evaluate the flow model on CIC-IDS2017 + CTU-13 |
| `.venv/bin/python -m app.cli ctu-replay 11` | replay one more real CTU-13 capture through the pipeline |
| `.venv/bin/python -m app.cli evaluate-ctu` | host- and flow-level results against the real CTU-13 labels |
| `.venv/bin/python -m app.cli correlate` | run correlation once |
| `.venv/bin/python -m app.cli evaluate` | correlation quality against simulator ground truth |
| `.venv/bin/python -m pytest tests -q` | run all tests (needs a seeded database) |

Interactive API documentation is at http://127.0.0.1:8765/docs.

## 5. Optional extras

* **AI model (free, local):** Ollama with `qwen2.5-coder:7b` is installed on this Mac and used automatically when Ollama is running (menu-bar icon). Typed questions in Ask AI take a few seconds; the example buttons are instant; the "✨ AI explanation" button on an incident takes ~30 s. Close heavy apps for best speed. On another Mac: install Ollama from ollama.com, then `ollama pull qwen2.5-coder:7b`. Gemini or Claude keys (in `~/.dbmsel/secrets.env`) are optional alternatives. Without any model, Ask AI uses its built-in question library. Everything goes through the SQL validator and the read-only role.
* **Datasets:** CIC-IDS2017 CSVs go in `data/raw/cicids2017/` and CTU-13 `.binetflow` files in `data/raw/ctu13/CTU-13-Dataset/<n>/`. Both are already in place. If you ever re-download CTU-13, extract only the flow files (`tar -xjf CTU-13-Dataset.tar.bz2 --include '*.binetflow' --include '*/README*'`), because the archive also contains real malware samples that antivirus will flag.

## 6. Troubleshooting

* **Port 5433, 27018 or 8765 is busy:** set `PGPORT` / `MONGOPORT` before `scripts/services.sh start`, or stop the other program.
* **MongoDB not installed or not running:** the system falls back to PostgreSQL JSONB for raw logs automatically (the header shows `postgres-jsonb`).
* **"Session expired":** sign in again (tokens last 8 hours).
