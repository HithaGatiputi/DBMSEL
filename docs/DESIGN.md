# Design Document: Cybersecurity Incident Management & Investigation System

RVCE · Database Management Systems (CD252IA) · Hitha Gatiputi (1RV24CI040), Hrithik Bhattacharya (1RV24CI041), Mahek Arora (1RV24CI062)

---

## 1. Objectives

1. Store users, devices, security events, alerts and incidents in a **normalised relational schema** with enforced integrity (PK, FK, composite keys, CHECK, generated columns).
2. **Score every event** in the database (admin-configurable rules + an ML anomaly score) and **raise system alerts by trigger**.
3. **Automatically correlate** alerted events into multi-stage incidents with ordered timelines (`fn_correlate_events`).
4. Make analyst work **accountable**: transactional procedures, a role-checked state machine, and an append-only, trigger-written audit trail.
5. **Integrate SQL and NoSQL**: PostgreSQL holds the structured core; MongoDB holds the raw, variable-schema logs; they are linked through `raw_log_ref` and `sql_event_id`.
6. Help investigators with **AI**: natural-language queries (validated, read-only SQL), evidence-grounded explanations, MITRE ATT&CK context (RAG) and generated reports.

## 2. Scope

**In scope:** ingestion and normalisation of authentication, network, file and privilege telemetry; rules + ML scoring; alerting; correlation; analyst workflow (assign, actions, status, evidence); incident reports; audit; administration of users, devices and detection rules; natural-language and canned SQL reporting; a simulator for multi-stage attacks; a web dashboard with role-based login.

**Out of scope:** live collection from real sensors or SIEM agents (the simulator and the CTU-13 replay stand in); automated response such as blocking IPs on a real firewall; multi-tenant deployment; Elasticsearch (MongoDB is the NoSQL layer).

## 3. Software Requirements Specification (summary)

| ID | Functional requirement | Implemented by |
|---|---|---|
| FR1 | Collect and store failed/successful logins, new-device access, file and confidential-file access, privilege escalation, data transfers, port scans, malware alerts | `security_events` + 4 sub-type tables, `app/ingest.py` |
| FR2 | Rule-based + ML risk score and Low/Medium/High/Critical severity for every event | `fn_event_risk`, `trg_score_event`, `detection_rules`, `app/ml.py` |
| FR3 | Raise alerts for suspicious events | `trg_event_after` → `system_alerts` |
| FR4 | Correlate related events within a time window into incidents | `fn_correlate_events`, `fn_event_window` |
| FR5 | Natural-language querying through a SQL validation layer on a read-only connection | `app/agent.py`, `app/sqlguard.py`, role `dbmsel_ro` |
| FR6 | Investigation tools: incident details, timelines, entities | `app/investigate.py`, views `v_incident_*` |
| FR7 | Structured incident report: summary, timeline, affected users/devices/IPs, severity, framework context | `app/report.py` |
| FR8 | Dashboard to view events, timelines, relationships and AI explanations | `frontend/` |
| FR9 | RAG over policies and MITRE ATT&CK | `kb_documents` + PostgreSQL full-text search |
| FR10 | Administrators manage users, devices and detection rules; changes are audited | `/api/admin/*`, `entity_audit_log` |

| Non-functional | How |
|---|---|
| Security | scrypt password hashes, HMAC-signed expiring tokens, login lockout, role-based API, least-privilege DB roles, SQL AST allow-list, statement timeout, row caps, append-only evidence and audit tables |
| Integrity | FKs everywhere; composite FK enforces the disjoint ISA; CHECK constraints; state-machine trigger |
| Concurrency | `SELECT … FOR UPDATE` in every analyst procedure; advisory lock around correlation |
| Usability | single-page dashboard; client-side and server-side form validation with readable errors |
| Portability | Windows/Linux/macOS; PostgreSQL 14+; MongoDB optional (falls back to JSONB) |

Hardware: 8 GB RAM, multi-core CPU, 20 GB disk. Software: PostgreSQL 16, MongoDB 8, Python 3.12, FastAPI, scikit-learn, XGBoost, sqlglot, any modern browser.

## 4. ER diagram → relational schema

Diagrams: `docs/diagrams/er_diagram.jpg` and `docs/diagrams/relational_schema.jpg` (also in the app's **Design** tab).

| ER construct | Relation(s) | Mapping rule |
|---|---|---|
| User, Device, Security Event, System Alert, Incident, Investigation Action (strong entities) | `users`, `devices`, `security_events`, `system_alerts`, `incidents`, `investigation_actions` | entity → relation, key attribute → PK |
| User 1–N Device (Owns/Uses) | `devices.owner_id → users` | FK on the N side |
| Device 1–N Security Event (Generates) | `security_events.device_id → devices` | FK on the N side |
| Security Event 1–N System Alert (Triggers) | `system_alerts.event_id → security_events` | FK on the N side |
| User / Device 1–N Incident (Involves, attribute *entity_role*) | `incidents.user_id`, `incidents.device_id`, `user_entity_role`, `device_entity_role` | FK on the N side; the relationship attribute moves with it |
| Security Event M–N Incident (Correlates Into: correlated_at, step_sequence, correlation_rule) | `incident_events(incident_id, event_id)` | junction relation, composite PK |
| User 1–N Investigation Action (Performs), Incident 1–N Investigation Action (Has Timeline Of) | `investigation_actions.analyst_id`, `.incident_id` | FKs on the N side |
| Audit Log (weak, identifying relationship *Generates*, partial key audit_id) | `audit_logs` PK `(incident_id, audit_id)` | owner PK + partial key, total participation (`incident_id NOT NULL`) |
| Security Event ISA {Login, Network, File Access} (disjoint) | `login_events`, `network_events`, `file_access_events` | sub-type PK is also FK to the super-type |

**Disjointness is enforced, not just documented.** `security_events.event_kind` is a generated column derived from `event_category`. Each sub-type table carries a constant `event_kind` (CHECK) and a composite FK `(event_id, event_kind) → security_events(event_id, event_kind)`. A network event therefore cannot receive a login row; the test suite checks this.

### 4.1 Gaps in the diagrams and how they were resolved

| # | Gap | Resolution |
|---|---|---|
| 1 | The ISA has no sub-type for **privilege escalation**, which the SRS requires | Added a fourth disjoint sub-type `privilege_events(old_role, new_role, method)` |
| 2 | Security Event has no link to the **acting user**, but incidents involve users and correlation needs them; a server such as the VPN gateway has no single owner | Added nullable `security_events.user_id`. If it is missing at ingest, a trigger fills it from the device owner (DFD 1.0 "device/owner lookup") |
| 3 | Audit Log is a weak entity of Incident, but DFD 4.0 also audits **user and device administration** | Kept `audit_logs` incident-scoped; added `entity_audit_log` for users, devices and detection rules |
| 4 | No place for the **currently assigned analyst** | Derived from the latest `ASSIGN` row in `investigation_actions` (`fn_current_analyst`), so assignment history is never overwritten |
| 5 | DFD level 0 says the administrator supplies **detection rules**, but no entity stores them | Added `detection_rules`; `fn_event_risk` and the alert trigger read it |
| 6 | Risk scoring needs **asset criticality**, which Device lacks | Added `devices.criticality (1–5)` |
| 7 | A weak entity with FK to Incident conflicts with an immutable audit trail if incidents can be deleted | Incidents can never be deleted (trigger + revoked privilege); they are closed or marked False Positive |
| 8 | Nothing stops **evidence tampering** | `security_events`, sub-types, `system_alerts`, `investigation_actions`, `audit_logs` and `entity_audit_log` are append-only: triggers block UPDATE, DELETE and TRUNCATE, and privileges are revoked |
| 9 | Without authentication, the analyst identity was **client-supplied** in the first version | Login with scrypt hashes and signed tokens; the actor always comes from the token and is bound to the transaction for the audit triggers |
| 10 | Concurrent correlation runs could **double-link** an event | `pg_advisory_xact_lock` in `fn_correlate_events`; incident rows are locked `FOR UPDATE` in all analyst procedures |

### 4.2 Security audit fixes (each has an automated test in `tests/`)

| # | Loophole | Fix |
|---|---|---|
| 1 | Local PostgreSQL used `trust` (no passwords); MongoDB had no authentication | PostgreSQL uses `scram-sha-256`; MongoDB runs with `--auth` (separate root and least-privilege `dbmsel_app` users). Random passwords per machine |
| 2 | Raw logs in MongoDB could be edited undetectably | SHA-256 of each raw document is stored in `security_events.raw_log_sha256` at ingest (append-only). Every raw-log view re-hashes the document and shows *verified* / *TAMPERED*; Admins can scan all evidence |
| 3 | An analyst could take over a colleague's incident and add notes/evidence to incidents not theirs | `sp_assign_incident`: analysts can only pick up unassigned incidents; re-assignment is Admin-only. `fn_require_owner` guards actions and evidence |
| 4 | Simulated attacks were indistinguishable from real evidence; any analyst could inject them | `security_events.event_source` (`sensor` / `simulator` / `ctu13`) on every event, shown as a badge everywhere; simulation is Admin-only |
| 5 | Token-signing key stored in the project folder (would leak in a zip) | All secrets live in `~/.dbmsel/secrets.env` (mode 600), outside the project |
| 6 | A password reset or deactivation did not end existing sessions | `user_credentials.token_version` is embedded in every token and bumped on password change, reset and deactivation |
| 7 | Login lockout was in memory and reset on restart | Every attempt is stored in `login_attempts` (append-only); 5 failures in 5 minutes lock the account across restarts |
| 8 | Nothing forced a password change | Admin-created accounts and resets set `must_change`; the API refuses everything except "change password" until it is done. (Seeded demo accounts keep the shared demo password unless `FORCE_PASSWORD_CHANGE=1`) |
| 9 | Incidents could be closed without a reason | Resolved / Closed / False Positive require a reason of at least 5 characters, enforced in the stored procedure |
| 10 | The ISA was only partially enforced (an event could lack its sub-type row) | Deferred constraint trigger `trg_events_isa_complete` checks at COMMIT that every event has the sub-type row its `event_kind` requires |
| 11 | "Off-hours" used UTC, not the organisation's time | `fn_org_timezone()` = Asia/Kolkata in SQL scoring, ML features and the simulator |
| 12 | Correlation could join unrelated users through shared servers | Device-based linking applies only to personal devices (laptop/workstation); servers, the VPN gateway and databases are not linking entities |
| 13 | Risk scores of open incidents could go stale | Every correlation run refreshes all open incidents, then the materialized view |

## 5. Normalisation

Functional dependencies (key → attributes) for the main relations:

* `users`: user_id → username, email, role, department, is_active, created_at; also username → user_id and email → user_id. Every determinant is a candidate key → **BCNF**.
* `devices`: device_id → owner_id, hostname, ip_address, mac_address, os_version, device_type, last_seen, criticality; hostname and mac_address are candidate keys → **BCNF**. The owner's department is *not* stored here, which avoids the transitive dependency device_id → owner_id → department.
* `security_events`: event_id → all attributes. `event_kind` depends on `event_category`, but it is a **generated** column, so it can never be updated inconsistently. It exists only to serve as the target of the ISA composite FK. Severity is a function of risk_score and is set by a trigger in the same row. All other attributes depend only on event_id → **BCNF**.
* Sub-type tables: event_id → sub-type attributes; there are no partial dependencies because the key is a single attribute → **BCNF**. Splitting them out removes the sparse, repeating "optional column" groups of a single wide event table (1NF / null-avoidance).
* `incident_events`: (incident_id, event_id) → correlated_at, step_sequence, correlation_rule; (incident_id, step_sequence) is also a candidate key (UNIQUE). Every non-key attribute depends on the whole key → **2NF and BCNF**.
* `incidents`: incident_id → everything. `title`, `risk_score` and `severity_level` are **derived** (from linked events) and stored for performance and audit history. They are recomputed only by `fn_refresh_incident`. This controlled redundancy keeps the table in **3NF** with respect to its stored attributes.
* `audit_logs`: (incident_id, audit_id) → remaining attributes → **BCNF**.
* `investigation_actions`, `system_alerts`, `detection_rules`, `entity_audit_log`: single-attribute keys, no transitive dependencies → **BCNF**.

The query report for this section is the **SQL Reports** tab: 15 queries covering joins, GROUP BY/HAVING, nested and correlated sub-queries, outer/anti-joins, INTERSECT/EXCEPT, window functions, CTEs, interval arithmetic, the materialized view, and an ISA consistency check. Each one is downloadable as CSV.

## 6. Data-flow design (DFD → code)

Diagrams: `docs/diagrams/dfd_level0.jpg`, `dfd_level1.jpg`, `dfd_level2.jpg`.

| DFD element | Implementation |
|---|---|
| External entity: Security Log Sources | `app/generator.py` (simulator), `app/automation.py` (live stream), `POST /api/simulate` |
| External entity: Security Analyst | Analyst login; Incidents, Alerts, Events, Ask AI, Reports tabs |
| External entity: System Administrator | Admin login; Admin tab (users, devices, rules, automation, change history) |
| 1.0 Ingest & Normalize | `app/ingest.py`: features → ML score → MongoDB → `security_events` + sub-type, one transaction; trigger owner lookup |
| 2.1 Retrieve Event Time Windows | `fn_event_window()`; sliding-window features in `app/features.py` |
| 2.2 Classify & Score | `fn_event_risk()` (rules from `detection_rules`), ML anomaly score, `trg_score_event` |
| 2.3 Correlate Related Events | `fn_correlate_events()` (shared user / IP / device within the window), run by the scheduler every 60 s |
| 2.4 Create / Update Incidents & Alerts | `trg_event_after` → `system_alerts`; correlation → `incidents`, `incident_events`; `fn_refresh_incident` (title, risk, entities) |
| 3.0 Investigate & Report | `app/investigate.py`, `app/report.py`, `app/agent.py`, `app/sql_reports.py`, analyst procedures |
| 4.0 Manage Entities & Audit Changes | `/api/admin/*`, `trg_entity_audit` → `entity_audit_log` |
| d1 Users & Devices | `users`, `devices`, `user_credentials` |
| d2 Security Events & Subtypes | `security_events`, `login_events`, `network_events`, `file_access_events`, `privilege_events` |
| d3 Incidents & Incident Events | `incidents`, `incident_events`, `mv_incident_risk` |
| d4 Alerts | `system_alerts` |
| d5 Investigation Actions & Audit Logs | `investigation_actions`, `audit_logs`, `entity_audit_log` |

## 7. SQL + NoSQL integration

* **PostgreSQL** holds structured entities, relationships, workflow, audit, rules and the knowledge base.
* **MongoDB** (`dbmsel_raw.raw_logs`) holds raw payloads whose shape differs by source: syslog lines, packet samples (hex), malware stack traces, device fingerprints, vendor fields. A wildcard text index supports full-text search.
* **Linking:** at ingest, the raw document is inserted first. Its ObjectId is stored in `security_events.raw_log_ref`. After the SQL insert, `sql_event_id` is written back into the document. The two-way link is used by the "raw log" button on every timeline step and by the Raw Logs search.
* **Fallback:** if MongoDB is unreachable, raw documents go to the `raw_logs_fallback` JSONB table and the system keeps working.

## 8. Security design

* Passwords are hashed with scrypt (salted). Tokens are HMAC-SHA256 signed, carry a token version and expire after 8 hours; a password change, reset or deactivation invalidates all earlier tokens. Every login attempt is stored; five failures in 5 minutes lock the account, even across restarts. Temporary passwords must be changed at first sign-in.
* Database servers require authentication: PostgreSQL `scram-sha-256`, MongoDB `--auth`. All passwords and the token key are random per machine and stored outside the project in `~/.dbmsel/secrets.env`.
* Evidence is tamper-evident end to end: PostgreSQL rows are append-only, and each MongoDB raw document is pinned by a SHA-256 hash stored in PostgreSQL.
* There are two database roles. `dbmsel_app` cannot UPDATE or DELETE evidence or audit tables, or DELETE incidents. `dbmsel_ro` (used only for AI and reports) has SELECT on business tables, no access to credentials or raw fallback, read-only transactions, a 5-second statement timeout and almost no function EXECUTE rights.
* AI-generated SQL is parsed with sqlglot. It must be a single SELECT, use only approved tables and functions, contain no schema-qualified or system tables, no `INTO`, no locks, and a LIMIT of at most 500 is enforced.
* All inputs are validated twice: in the browser, and with Pydantic models and regexes on the server. Database CHECK constraints give a third layer.
* HTML output is escaped in the UI to prevent XSS.

## 8a. Response and containment (DFD level 0: "response decisions")

The system is a detection-and-investigation platform, not a firewall: it does not drop network packets. It does make and enforce **containment decisions inside its own data**, the way a SOAR playbook would before handing off to network devices.

* **Automatic:** after each correlation run, `sp_auto_contain` contains every open incident whose risk reaches the active `response_policy` (default 75 = Critical). It blocks the incident's **external** source IPs and disables accounts whose role in the incident is `compromised_account` or `insider_suspect`. It **never disables an Analyst or Admin account**; it writes an `auto_response_review` audit row instead, so automation can't lock out the responders.
* **Manual:** the incident owner (or an Admin) can block an IP or account with a written reason (`sp_block_entity`). Analysts can't block internal addresses or disable staff accounts. Only an Admin can lift a block, again with a reason (`sp_lift_block`). Blocks are never deleted, and a lifted block can't be edited.
* **Enforcement:** the BEFORE INSERT trigger flags any later event from a blocked IP or disabled account (`security_events.blocked`). The event is still stored as evidence, raises a `BLOCKED_ATTEMPT` alert, and correlation attaches it to the incident that contained the attacker (rule `blocked_return`), however much later it happens.
* **Accountability:** every block and lift is written to the incident's `audit_logs` by a trigger, policy changes go to `entity_audit_log`, and blocks appear in the incident report.

## 8b. Security self-test

**Admin → Security self-test** attacks the running system in 13 ways and reports what stopped each attack, with the database's own error message: brute-force login (lockout), a forged admin token (HMAC check), SQL injection through Ask AI, a stacked SQL statement (validator), writing and reading password hashes through the AI role (read-only role, privileges), rewriting the audit trail, deleting evidence or an incident (privileges + append-only triggers), taking over a colleague's incident (procedure ownership check), skipping the investigation (state machine), editing a raw MongoDB log (SHA-256 pinned in PostgreSQL), and a contained attacker trying again (containment trigger). Database attempts run inside transactions that are rolled back, tampering is tried on an in-memory copy, and the brute-force test uses a throw-away username, so the test changes nothing. Result on the live system: **13/13 blocked**.

## 9. Innovation, trends and automation

* **AI/ML:** two detectors score every event before insertion: a **flow model** trained on real CIC-IDS2017 + CTU-13 traffic, and a **behaviour model** for login/file/privilege sequences. Both are Isolation Forest (unsupervised) blended with XGBoost (supervised). See sections 11–12 for the datasets and real-data evaluation.
* **NLP:** natural-language to SQL through a pluggable LLM layer: a **free local model (qwen2.5-coder 7B via Ollama)**, Google Gemini, or Claude, with an offline intent library as the fallback. The model only proposes SQL; the AST validator and the read-only role decide what runs. Measured on the live database (`scripts/eval_nl2sql.py`, report in `docs/NL2SQL_EVAL.md`): example questions 5/5 (verified queries, ~0.5 s); free-form questions 6/8 answered by the local model (~3 s each), 2/8 answered by the closest built-in query, clearly labelled; 5/5 attack prompts (delete/drop/update/read password hashes/`pg_sleep`) produced no change to the database. Incident explanations from the local model take ~30 s, so they are generated on demand and cached; the local model can occasionally over-interpret the evidence, so its text is labelled "AI" next to the rule-based analysis. It also writes evidence-grounded narratives and does RAG over MITRE ATT&CK, NIST SP 800-61 and policies using PostgreSQL full-text search.
* **Automation:** in-database triggers (scoring, alerting, last_seen, auditing); a background scheduler that correlates every 60 seconds; a live telemetry stream; auto-generated reports; seeded analyst workflow.
* **Explainability:** every incident risk score is broken into named components computed in SQL (`fn_incident_risk_components`, `mv_incident_risk`).

## 10. Societal relevance

Cyber attacks on hospitals, banks, government and education leak citizens' personal data and interrupt essential services. This system shortens detection and response by turning thousands of isolated logs into a few explainable incidents. Its tamper-proof audit trail supports legal and regulatory obligations such as **India's DPDP Act 2023** and the **CERT-In directive to report incidents within 6 hours**. AI assistance is deliberately read-only and evidence-grounded, so automation can help analysts without altering evidence or making unaccountable decisions.

## 11. Datasets

| Dataset | What it is | Used for |
|---|---|---|
| **CIC-IDS2017** (Canadian Institute for Cybersecurity, `MachineLearningCVE` CSVs) | 2.83 M real labelled network flows over 5 days: benign plus DoS/DDoS, PortScan, FTP/SSH brute force (Patator), Bot, web attacks, Infiltration, Heartbleed | Training and testing the **flow anomaly model**; real benign flows, scan probes and bot beacons inside the simulator |
| **CTU-13** (Czech Technical University, `.binetflow` NetFlow) | 13 real botnet captures (Neris, Rbot, Virut, Menti, Sogou, Murlo, NSIS.ay) with timestamps, IPs, ports, bytes and Botnet/Normal labels | Extra training data (10 scenarios); **held-out evaluation** (scenarios 5, 11, 12) both as a test set and **replayed through the whole pipeline**: MongoDB → PostgreSQL → alert triggers → correlation |
| Simulator (`app/generator.py`) | Synthetic organisation with login/file/privilege behaviour and 5 multi-stage attack stories, overlaid on real CIC-IDS2017 flows | Behaviour model; end-to-end demo; live injection |

**Change from the synopsis.** The synopsis named UNSW-NB15. CIC-IDS2017 + CTU-13 were used instead for the same purpose (real public network traffic). Together they add labelled brute-force and botnet traffic, and CTU-13 provides real timestamps and IP addresses, which correlation needs and the common UNSW-NB15 CSVs lack.

**Malware safety.** The CTU-13 distribution also contains the original botnet executables and packet captures. Only the `.binetflow` text files and READMEs were extracted (`tar --include`); the archive was then deleted. No executable sample is stored in the project.

## 12. Evaluation on real data

Flow model (Isolation Forest 25% + XGBoost 75%), features shared by all sources: destination-port group, duration, bytes sent/received, packets, bytes per packet, receive/send ratio.

| Test set (never used for training) | Flows | ROC-AUC | Precision | Recall |
|---|---|---|---|---|
| CIC-IDS2017 random 30% hold-out | 178,286 | 0.998 | 0.94 | 0.99 |
| CIC-IDS2017 unseen day (train Mon–Thu, test Friday: DDoS, PortScan, Bot) | 231,966 | 0.860 | 0.90 | 0.31 |
| CTU-13 all scenarios, CIC-only model (pure cross-dataset transfer) | 46,893 | 0.850 | 0.998 | 0.12 |
| **CTU-13 held-out scenarios 5, 11, 12** (model also trained on the other 10) | 10,521 | **0.926** | 0.93 | 0.68 |

(Precision/recall at score 0.5. Detection by CIC attack type: DDoS, DoS, PortScan, Patator ≥ 99%; Bot 63%; SQL injection 33% (21 samples).)

**Alert threshold.** The live network rules alert at anomaly ≥ 0.80. This threshold was chosen on a validation split of the *training* data (≈ 0.1% false positives on both datasets, recall 80–90%), never on the held-out scenarios.

**Score fusion.** Network events that belong to a user session take the higher of the behaviour and flow scores; host-only flows (no user, as in CTU-13) use the flow model only. Before this rule the simulated-data behaviour model flagged 100% of real CTU-13 normal traffic; afterwards, 0%.

**End-to-end replay of the held-out CTU-13 botnets** (`python -m app.cli evaluate-ctu`; 1,200 botnet + 1,800 normal real flows, 18 hosts):

| Metric | Result |
|---|---|
| Infected hosts flagged | **6 / 6** |
| Clean hosts flagged | **0 / 12** |
| Alert precision | 1.00 |
| Botnet flows alerted | 0.56 |
| Normal flows alerted | 0.00 |
| Incident purity (share of botnet flows in CTU incidents) | 1.00 |

## 13. Known limitations

* Login, file and privilege events have no public labelled dataset, so the behaviour model and the attack storylines are simulated. Its scores (ROC-AUC ≈ 1.0) and the simulated-scenario correlation scores (completeness 0.96, purity 1.0) overstate real-world performance. The network side is evaluated on real data (section 12).
* The flow model leans heavily on the destination port, DNS in particular (≈ 75% of importance), because CIC-IDS2017's benign traffic contains a lot of DNS and its attacks none. This is a known dataset artefact; it is why the model drops on an unseen day (ROC-AUC 0.86) and why training on extra CTU-13 captures helps.
* Flow-level recall on unseen botnets is moderate (56% of botnet flows alerted). Host-level detection is what matters operationally, and there all infected hosts were flagged with no false alarms, but only 6 infected and 12 clean hosts were tested.
* CIC-IDS2017's "MachineLearningCVE" CSVs have no IPs or timestamps, so they train and test the flow model but cannot be replayed through correlation; CTU-13 is used for that.
* Correlation is greedy sessionisation. It does not merge two incidents that later turn out to be one campaign.
* The offline NL→SQL mode understands a fixed set of question types; free-form questions need an LLM key.
* There is no ingestion endpoint for real sensors yet; telemetry arrives from the simulator and the CTU-13 replay. Events from a real collector would be tagged `sensor`.
* There is no backup or data-retention policy. Raw logs contain personal data (usernames, IPs, file paths); a production deployment needs retention limits and backups to meet the DPDP Act 2023.
* A PostgreSQL **superuser** can still disable triggers or alter tables. Append-only guarantees hold for the application and read-only roles, which is the usual DBMS boundary; protecting against a malicious DBA needs external log shipping or WORM storage.
* The automation scheduler runs inside the web process; running several web workers would start several schedulers. Run one worker (as the scripts do) or move the scheduler to its own process.
* The seeded demo accounts share one known password (for the demo). Set `FORCE_PASSWORD_CHANGE=1` before seeding for any shared deployment.
