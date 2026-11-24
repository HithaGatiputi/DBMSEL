"""Generate docs/DATABASE_TOUR.md: a guided tour of the live databases.

Everything is read from the running PostgreSQL / MongoDB, and every demo runs
inside a transaction that is ROLLED BACK, so the data is not changed.

    .venv/bin/python scripts/db_tour.py
"""
from __future__ import annotations

import getpass
import json
import os
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import psycopg  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402

from app import config, sqlguard  # noqa: E402
from app.ingest import doc_sha256  # noqa: E402
from app.rawstore import store  # noqa: E402

SUPER_DSN = (f"postgresql://{getpass.getuser()}:{os.environ['PG_SUPER_PASSWORD']}"
             f"@{config.PG_HOST}:{config.PG_PORT}/{config.PG_DB}")
OUT = ROOT / "docs" / "DATABASE_TOUR.md"
L: list[str] = []


def w(*lines):
    L.extend(lines)


def md_table(rows, limit=12, width=60):
    if not rows:
        return "_(no rows)_"
    cols = list(rows[0].keys())

    def cell(v):
        s = "" if v is None else (json.dumps(v, default=str) if isinstance(v, (dict, list)) else str(v))
        s = s.replace("|", "\\|").replace("\n", " ")
        return s if len(s) <= width else s[:width - 1] + "…"
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    out += ["| " + " | ".join(cell(r[c]) for c in cols) + " |" for r in rows[:limit]]
    if len(rows) > limit:
        out.append(f"\n_… {len(rows) - limit} more rows_")
    return "\n".join(out)


def conn(dsn=SUPER_DSN):
    return psycopg.connect(dsn, row_factory=dict_row, autocommit=False)


def q(sql, params=None, dsn=SUPER_DSN):
    with conn(dsn) as c, c.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else []


def show(title, sql, params=None, limit=12, dsn=SUPER_DSN, note=None):
    w(f"**{title}**", "", "```sql", sql.strip(), "```")
    if note:
        w(note, "")
    w(md_table(q(sql, params, dsn), limit), "")


def expect_error(title, steps, dsn=SUPER_DSN, explain=""):
    """Run statements in one transaction; show the database's error; roll back."""
    w(f"**{title}**", "", "```sql", *[s.strip() + ";" for s in steps], "```")
    try:
        with conn(dsn) as c:
            with c.cursor() as cur:
                for s in steps:
                    cur.execute(s)
            c.commit()
        w("Result: ⚠ no error (unexpected)", "")
    except psycopg.Error as e:
        w(f"Result, rejected by the database: `{type(e).__name__}`: {str(e).splitlines()[0]}", "")
    if explain:
        w(explain, "")


# ---------------------------------------------------------------------------
def header():
    w("# Database tour", "",
      f"_Generated {datetime.now():%Y-%m-%d %H:%M} from the live databases by `scripts/db_tour.py`. "
      "Every demo below ran inside a transaction that was **rolled back**, so nothing was changed._", "",
      "## 0. Opening the databases yourself", "",
      "| Command | Opens |", "|---|---|",
      "| `scripts/db.sh psql` | PostgreSQL as the owner (full access) |",
      "| `scripts/db.sh app` | PostgreSQL as `dbmsel_app`, the role the web app uses |",
      "| `scripts/db.sh ro` | PostgreSQL as `dbmsel_ro`, the read-only role used by Ask AI |",
      "| `scripts/db.sh mongo` | MongoDB shell on the raw-log database |",
      "| `scripts/db.sh sql \"SELECT …\"` | run one query and print the result |",
      "| `scripts/db.sh info` | host, port, users and passwords for pgAdmin / DBeaver / MongoDB Compass |", "",
      "Useful commands inside `psql`: `\\dt` (tables), `\\d security_events` (one table), `\\dv` (views), "
      "`\\df fn_*` (functions), `\\dy` (event triggers), `\\du` (roles), `\\q` (quit).", "",
      "## 1. Architecture at a glance", "",
      "| Layer | Technology | Holds |", "|---|---|---|",
      f"| Relational core | PostgreSQL 16 on 127.0.0.1:{config.PG_PORT}, database `dbmsel` | users, devices, events + 4 sub-types, alerts, incidents, actions, audit, rules, knowledge base |",
      f"| Raw-log store | MongoDB on 127.0.0.1:27018, database `dbmsel_raw`, collection `raw_logs` ({store().backend}) | original semi-structured log documents |",
      "| Link | `security_events.raw_log_ref` ↔ MongoDB `_id`; MongoDB `sql_event_id` ↔ `event_id`; `raw_log_sha256` pins the document | |",
      "| Security | scram-sha-256 passwords (PostgreSQL), `--auth` (MongoDB); secrets in `~/.dbmsel/secrets.env` | |", "")


def tables():
    w("## 2. Tables and row counts", "")
    rows = q("""SELECT c.relname AS table_name, c.reltuples::bigint AS approx_rows,
                       obj_description(c.oid) AS note
                  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname='public' AND c.relkind='r' ORDER BY c.relname""")
    exact = []
    for r in rows:
        n = q(f'SELECT COUNT(*) AS n FROM "{r["table_name"]}"')[0]["n"]
        exact.append({"table": r["table_name"], "rows": n})
    w(md_table(exact, limit=50), "")
    w("## 3. Table structure (columns, keys, constraints)", "",
      "The main entities from the ER diagram. Run `\\d <table>` in psql for the full detail.", "")
    for t in ["users", "devices", "security_events", "login_events", "network_events", "file_access_events",
              "privilege_events", "system_alerts", "incidents", "incident_events", "investigation_actions",
              "audit_logs", "detection_rules", "blocked_entities", "response_policy"]:
        w(f"### `{t}`", "")
        cols = q("""SELECT column_name AS column, data_type AS type, is_nullable AS nullable,
                           COALESCE(column_default, CASE WHEN is_generated='ALWAYS' THEN 'GENERATED: ' || generation_expression END, '') AS "default / generated"
                      FROM information_schema.columns WHERE table_schema='public' AND table_name=%s
                     ORDER BY ordinal_position""", (t,))
        w(md_table(cols, limit=40, width=70), "")
        cons = q("""SELECT conname AS constraint, CASE contype WHEN 'p' THEN 'PRIMARY KEY' WHEN 'f' THEN 'FOREIGN KEY'
                           WHEN 'u' THEN 'UNIQUE' WHEN 'c' THEN 'CHECK' ELSE contype::text END AS kind,
                           pg_get_constraintdef(oid) AS definition
                      FROM pg_constraint WHERE conrelid = %s::regclass ORDER BY contype, conname""", (t,))
        w(md_table(cons, limit=40, width=110), "")
    show("Indexes (B-tree, composite and GIN full-text)",
         """SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname='public'
             AND indexname NOT LIKE '%_pkey' ORDER BY tablename, indexname""", limit=60)


def programmability():
    w("## 4. Functions, procedures and triggers", "")
    show("Functions and stored procedures",
         """SELECT p.proname AS name, pg_get_function_identity_arguments(p.oid) AS arguments,
                   pg_get_function_result(p.oid) AS returns,
                   CASE WHEN p.proname LIKE 'sp\\_%' THEN 'procedure (writes)'
                        WHEN p.proname LIKE 'trg\\_%' THEN 'trigger function' ELSE 'function' END AS kind
              FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname='public' ORDER BY kind, name""", limit=60)
    show("Triggers: what fires, when, on which table",
         """SELECT event_object_table AS "table", trigger_name, action_timing AS timing,
                   string_agg(event_manipulation, ' OR ' ORDER BY event_manipulation) AS events,
                   regexp_replace(action_statement, 'EXECUTE FUNCTION ', '') AS runs
              FROM information_schema.triggers WHERE trigger_schema='public'
             GROUP BY 1,2,3,5 ORDER BY 1,2""", limit=60,
         note="TRUNCATE triggers and the deferred ISA constraint trigger are included below:")
    show("Statement-level / constraint triggers",
         """SELECT tgrelid::regclass AS "table", tgname AS trigger,
                   CASE WHEN tgconstraint <> 0 THEN 'CONSTRAINT, DEFERRABLE INITIALLY DEFERRED'
                        WHEN tgtype & 32 = 32 THEN 'BEFORE TRUNCATE' ELSE '' END AS kind
              FROM pg_trigger WHERE NOT tgisinternal AND (tgconstraint <> 0 OR tgtype & 32 = 32)
             ORDER BY 1,2""", limit=30)


def views_roles():
    w("## 5. Views and the materialized view", "")
    show("Views", """SELECT table_name AS view FROM information_schema.views WHERE table_schema='public' ORDER BY 1""")
    rows = q("""SELECT m.incident_id, i.title, m.risk_score, m.breakdown
                  FROM mv_incident_risk m JOIN incidents i USING (incident_id) ORDER BY m.risk_score DESC LIMIT 5""")
    w("**Explainable risk (materialized view `mv_incident_risk`)**", "", "```sql",
      "SELECT m.incident_id, i.title, m.risk_score, m.breakdown FROM mv_incident_risk m JOIN incidents i USING (incident_id) ORDER BY m.risk_score DESC LIMIT 5;",
      "```", md_table(rows, width=120), "")
    top = rows[0]["incident_id"] if rows else 1
    show(f"The same score, explained component by component (function fn_incident_risk_components({top}))",
         f"SELECT * FROM fn_incident_risk_components({top})")
    w("## 6. Roles and privileges (least privilege)", "")
    show("Login roles and their settings",
         """SELECT rolname AS role, rolsuper AS superuser, rolcanlogin AS can_login,
                   array_to_string(rolconfig, ', ') AS settings
              FROM pg_roles WHERE rolname IN ('dbmsel_app','dbmsel_ro') OR rolname = current_user ORDER BY 1""")
    show("What each role may do on the evidence and audit tables",
         """SELECT table_name AS "table",
                   string_agg(privilege_type, ', ' ORDER BY privilege_type) FILTER (WHERE grantee='dbmsel_app') AS dbmsel_app,
                   string_agg(privilege_type, ', ' ORDER BY privilege_type) FILTER (WHERE grantee='dbmsel_ro')  AS dbmsel_ro
              FROM information_schema.role_table_grants
             WHERE table_schema='public' AND grantee IN ('dbmsel_app','dbmsel_ro')
               AND table_name IN ('security_events','system_alerts','incidents','incident_events',
                                  'investigation_actions','audit_logs','user_credentials','login_attempts','users')
             GROUP BY table_name ORDER BY 1""")


def sample_data():
    w("## 7. Sample data", "")
    show("users", "SELECT user_id, username, role, department, is_active FROM users ORDER BY user_id LIMIT 8")
    show("devices", "SELECT device_id, hostname, host(ip_address) AS ip, device_type, criticality, owner_id, last_seen FROM devices ORDER BY criticality DESC, device_id LIMIT 8")
    show("detection_rules (editable by Admins)", "SELECT rule_name, event_category, base_risk, min_anomaly, is_active FROM detection_rules ORDER BY rule_id")
    show("Events per provenance and kind",
         "SELECT event_source, event_kind, COUNT(*) AS events, COUNT(*) FILTER (WHERE severity IN ('High','Critical')) AS high_or_critical FROM security_events GROUP BY 1,2 ORDER BY 1,2")
    show("security_events joined to its sub-type (one of each kind)",
         """SELECT DISTINCT ON (e.event_kind) e.event_id, e.event_kind, e.event_category, e.severity, e.risk_score,
                   e.anomaly_score, l.login_status, n.bytes_sent, f.is_sensitive, p.new_role
              FROM security_events e
              LEFT JOIN login_events l USING (event_id) LEFT JOIN network_events n USING (event_id)
              LEFT JOIN file_access_events f USING (event_id) LEFT JOIN privilege_events p USING (event_id)
             ORDER BY e.event_kind, e.risk_score DESC""")
    show("system_alerts (written by trigger)",
         "SELECT alert_id, event_id, alert_type, rule_matched, risk_impact FROM system_alerts ORDER BY risk_impact DESC LIMIT 6")
    show("incidents (v_incident_summary)",
         "SELECT incident_id, title, severity_level, status, risk_score, primary_user, user_entity_role, analyst, event_count, sources FROM v_incident_summary ORDER BY risk_score DESC LIMIT 8")
    inc = q("SELECT incident_id FROM incidents ORDER BY risk_score DESC LIMIT 1")[0]["incident_id"]
    show(f"How correlation built incident {inc}: ordered steps (incident_events / v_incident_timeline)",
         f"SELECT step_sequence, event_timestamp, event_category, username, hostname, host(source_ip) AS src, correlation_rule FROM v_incident_timeline WHERE incident_id={inc} ORDER BY step_sequence")
    show("investigation_actions", "SELECT incident_id, action_type, action_notes, analyst_id, performed_at FROM investigation_actions ORDER BY action_id LIMIT 8")
    show("audit_logs (weak entity, PK = incident_id + audit_id)",
         "SELECT incident_id, audit_id, field_changed, old_value, new_value, actor, analyst_id, changed_at FROM audit_logs WHERE field_changed <> 'evidence_added' ORDER BY changed_at DESC LIMIT 10")


def demos():
    w("## 8. Live demos: the database enforcing the rules", "",
      "Each block runs inside a transaction, shows what happened, then rolls back.", "")
    dev = q("SELECT device_id, last_seen FROM devices WHERE hostname='file-srv-01'")[0]
    w("### 8.1 Insert one event and watch the triggers work", "",
      "One `INSERT` causes: BEFORE trigger scores it (`fn_event_risk` from `detection_rules` + ML score), "
      "AFTER trigger raises a `system_alert` and updates `devices.last_seen`, and the deferred constraint trigger checks the ISA sub-type row at commit.", "")
    with conn() as c, c.cursor() as cur:
        cur.execute("""INSERT INTO security_events (device_id, user_id, event_timestamp, event_category, source_ip, anomaly_score, event_source)
                       VALUES (%s, 10, now(), 'privilege_escalation', '10.1.0.99', 0.92, 'simulator')
                       RETURNING event_id, user_id, risk_score, severity, event_kind""", (dev["device_id"],))
        ev = cur.fetchone()
        cur.execute("INSERT INTO privilege_events (event_id, old_role, new_role, method) VALUES (%s,'user','root','exploit')", (ev["event_id"],))
        cur.execute("SELECT alert_type, rule_matched, risk_impact FROM system_alerts WHERE event_id=%s", (ev["event_id"],))
        al = cur.fetchall()
        cur.execute("SELECT last_seen FROM devices WHERE device_id=%s", (dev["device_id"],))
        ls = cur.fetchone()["last_seen"]
        c.rollback()
    w("```sql", "INSERT INTO security_events (device_id, user_id, event_timestamp, event_category, source_ip, anomaly_score)",
      "VALUES (<file-srv-01>, 10, now(), 'privilege_escalation', '10.1.0.99', 0.92) RETURNING event_id, risk_score, severity, event_kind;",
      "INSERT INTO privilege_events (event_id, old_role, new_role, method) VALUES (<new id>, 'user', 'root', 'exploit');", "```",
      md_table([ev]), "", "Alert raised automatically:", "", md_table(al), "",
      f"`devices.last_seen` for file-srv-01: {dev['last_seen']} → **{ls}** (then rolled back).", "")

    w("### 8.2 Integrity constraints", "")
    netev = q("SELECT event_id FROM security_events WHERE event_kind='network' LIMIT 1")[0]["event_id"]
    expect_error("Disjoint ISA: a network event cannot get a login sub-type row",
                 [f"INSERT INTO login_events (event_id, login_status) VALUES ({netev}, 'success')"],
                 explain="The composite FK `(event_id, event_kind)` only matches a parent whose generated `event_kind` is 'login'.")
    expect_error("Total participation: an event without its sub-type row cannot be committed",
                 [f"INSERT INTO security_events (device_id, event_timestamp, event_category) VALUES ({dev['device_id']}, now(), 'port_scan')"],
                 explain="The deferred constraint trigger `trg_events_isa_complete` checks at COMMIT.")
    expect_error("CHECK constraint: unknown category", [
        f"INSERT INTO security_events (device_id, event_timestamp, event_category) VALUES ({dev['device_id']}, now(), 'coffee_break')"])
    expect_error("Foreign key: device must exist", [
        "INSERT INTO security_events (device_id, event_timestamp, event_category) VALUES (999999, now(), 'port_scan')"])

    w("### 8.3 Analyst workflow, accountability and the audit trail", "")
    rao = q("SELECT user_id FROM users WHERE username='analyst.rao'")[0]["user_id"]
    menon = q("SELECT user_id FROM users WHERE username='analyst.menon'")[0]["user_id"]
    with conn() as c, c.cursor() as cur:
        cur.execute("INSERT INTO incidents (title) VALUES ('tour demo incident') RETURNING incident_id")
        iid = cur.fetchone()["incident_id"]
        cur.execute("SELECT sp_assign_incident(%s, %s, %s)", (iid, rao, rao))
        cur.execute("SELECT sp_add_action(%s, %s, 'CONTAINMENT', 'Isolated host and reset credentials')", (iid, rao))
        cur.execute("SELECT sp_set_incident_status(%s, 'Contained', %s, 'Host isolated')", (iid, rao))
        cur.execute("SELECT action_type, action_notes, analyst_id FROM investigation_actions WHERE incident_id=%s ORDER BY action_id", (iid,))
        acts = cur.fetchall()
        cur.execute("SELECT audit_id, field_changed, old_value, new_value, actor, analyst_id FROM audit_logs WHERE incident_id=%s ORDER BY audit_id", (iid,))
        aud = cur.fetchall()
        c.rollback()
    w("```sql", "SELECT sp_assign_incident(<incident>, <analyst.rao>, <analyst.rao>);",
      "SELECT sp_add_action(<incident>, <analyst.rao>, 'CONTAINMENT', 'Isolated host and reset credentials');",
      "SELECT sp_set_incident_status(<incident>, 'Contained', <analyst.rao>, 'Host isolated');", "```",
      "Rows written to `investigation_actions` by the procedures:", "", md_table(acts), "",
      "Rows written to `audit_logs` **by triggers** (nobody inserts them directly):", "", md_table(aud), "")
    demo_inc = "(SELECT incident_id FROM incidents ORDER BY incident_id DESC LIMIT 1)"
    expect_error("Another analyst cannot take over rao's incident", [
        "INSERT INTO incidents (title) VALUES ('tour demo')",
        f"SELECT sp_assign_incident({demo_inc}, {rao}, {rao})",
        f"SELECT sp_assign_incident({demo_inc}, {menon}, {menon})"])
    expect_error("Illegal status jump (Investigating → Closed skips Resolved; not in the state machine)", [
        "INSERT INTO incidents (title) VALUES ('tour demo')",
        f"SELECT sp_assign_incident({demo_inc}, {rao}, {rao})",
        f"SELECT sp_set_incident_status({demo_inc}, 'Closed', {rao}, 'skip it')"])
    expect_error("Closing requires a reason", [
        "INSERT INTO incidents (title) VALUES ('tour demo')",
        f"SELECT sp_assign_incident({demo_inc}, {rao}, {rao})",
        f"SELECT sp_set_incident_status({demo_inc}, 'False Positive', {rao}, '')"])

    w("### 8.4 Append-only evidence and tamper-proof audit", "")
    app_dsn = config.DSN_APP
    expect_error("Even the database owner cannot edit an audit row (trigger)", ["UPDATE audit_logs SET new_value = 'nothing happened'"])
    expect_error("…or delete evidence", ["DELETE FROM security_events WHERE event_id = (SELECT MIN(event_id) FROM security_events)"])
    expect_error("…or wipe the audit table", ["TRUNCATE audit_logs"])
    expect_error("Incidents are never deleted (close them instead)", ["DELETE FROM incidents WHERE incident_id = 1"])
    expect_error("The application role has no UPDATE privilege on the audit table at all", ["UPDATE audit_logs SET actor = 'x'"], dsn=app_dsn)

    w("### 8.5 The read-only role used by Ask AI", "")
    ro = config.DSN_RO
    expect_error("dbmsel_ro cannot write", ["DELETE FROM users"], dsn=ro)
    expect_error("dbmsel_ro cannot read password hashes", ["SELECT * FROM user_credentials"], dsn=ro)
    w("**And the SQL validator in front of it (app/sqlguard.py)**", "")
    tests = ["SELECT username, COUNT(*) FROM v_events_enriched GROUP BY 1", "DROP TABLE users",
             "SELECT pg_sleep(10)", "SELECT * FROM pg_catalog.pg_user", "SELECT 1; DELETE FROM incidents"]
    rows = []
    for t in tests:
        v = sqlguard.validate(t)
        rows.append({"question SQL": t, "verdict": "allowed" if v.ok else "blocked", "detail": v.sql if v.ok else v.reason})
    w(md_table(rows, width=90), "")


def mongo():
    w("## 9. MongoDB: the raw-log store", "")
    rs = store()
    if rs.backend != "mongodb":
        w("_MongoDB not reachable; raw logs are in the PostgreSQL fallback table._", "")
        return
    col = rs._col
    w(f"Collection `dbmsel_raw.raw_logs`: **{col.estimated_document_count()}** documents.", "",
      "Indexes:", "", md_table([{"name": k, "keys": str(v["key"])} for k, v in col.index_information().items()]), "")
    ev = q("""SELECT e.event_id, e.event_category, e.event_source, e.raw_log_ref, e.raw_log_sha256
                FROM security_events e JOIN incident_events ie USING (event_id)
               WHERE e.event_category='malware_alert' LIMIT 1""") or q(
        "SELECT event_id, event_category, event_source, raw_log_ref, raw_log_sha256 FROM security_events LIMIT 1")
    ev = ev[0]
    doc = rs.get(ev["raw_log_ref"])
    w("**SQL → NoSQL: the event row points at its document**", "", md_table([ev], width=70), "",
      "```js", f'db.raw_logs.findOne({{_id: ObjectId("{ev["raw_log_ref"]}")}})', "```", "```json",
      json.dumps(doc, indent=2, default=str)[:2500], "```", "",
      f"**NoSQL → SQL:** the document's `sql_event_id` = {doc.get('sql_event_id')} = the row's `event_id`.", "",
      f"**Integrity:** SHA-256 recomputed now = `{doc_sha256(doc)}`; stored in PostgreSQL at ingest = "
      f"`{ev['raw_log_sha256']}` → **{rs.verify(ev['raw_log_ref'], ev['raw_log_sha256'])}**.", "")
    hits = rs.search("polkit", 3) or rs.search("Mirai", 3)
    w("**Full-text search (wildcard text index)**", "", "```js", 'db.raw_logs.find({$text: {$search: "polkit"}})', "```",
      md_table([{"_id": h["_id"], "sql_event_id": h.get("sql_event_id"), "message": h.get("message")} for h in hits], width=80), "")
    by_src = list(col.aggregate([{"$group": {"_id": "$event_source", "documents": {"$sum": 1}}}, {"$sort": {"_id": 1}}]))
    w("**Aggregation: documents per provenance**", "", "```js",
      'db.raw_logs.aggregate([{$group: {_id: "$event_source", documents: {$sum: 1}}}])', "```",
      md_table([{"event_source": b["_id"], "documents": b["documents"]} for b in by_src]), "")


def main():
    header()
    tables()
    programmability()
    views_roles()
    sample_data()
    demos()
    mongo()
    OUT.write_text("\n".join(L) + "\n")
    print(f"wrote {OUT} ({len(L)} lines)")


if __name__ == "__main__":
    main()
