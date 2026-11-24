"""Database-level tests. Need a seeded DB:  python -m app.cli reset && python -m app.cli seed"""
import psycopg
import pytest

from app import agent, db, sql_reports, sqlguard


def uid(name):
    return db.one("SELECT user_id FROM users WHERE username=%s", (name,))["user_id"]


def call(sql, params):
    with db.conn() as c, c.cursor() as cur:
        cur.execute(sql, params)
        c.commit()


def new_incident():
    """A fresh, unassigned incident for this test (tests never borrow seeded data)."""
    return db.one("INSERT INTO incidents (title) VALUES ('pytest incident') RETURNING incident_id")["incident_id"]


def test_assign_writes_action_and_audit():
    inc, a = new_incident(), uid("analyst.das")
    call("SELECT sp_assign_incident(%s,%s,%s)", (inc, a, a))
    assert db.one("SELECT fn_current_analyst(%s) AS a", (inc,))["a"] == a
    audit = db.query("SELECT field_changed, new_value, analyst_id FROM audit_logs WHERE incident_id=%s", (inc,))
    assert any(r["field_changed"] == "assigned_analyst" and r["analyst_id"] == a for r in audit)
    assert any(r["field_changed"] == "status" and r["new_value"] == "Investigating" for r in audit)


def test_only_assigned_analyst_changes_status():
    inc = new_incident()
    call("SELECT sp_assign_incident(%s,%s,%s)", (inc, uid("analyst.rao"), uid("analyst.rao")))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        call("SELECT sp_set_incident_status(%s,'Contained',%s,'')", (inc, uid("analyst.menon")))
    with pytest.raises(psycopg.errors.CheckViolation):          # illegal jump
        call("SELECT sp_set_incident_status(%s,'Closed',%s,'done here')", (inc, uid("analyst.rao")))
    call("SELECT sp_set_incident_status(%s,'Contained',%s,'ok')", (inc, uid("analyst.rao")))


# ---- loophole #3: no takeover, owner-only actions/evidence -------------------
def test_analyst_cannot_take_over_or_act_on_others_incident():
    inc = new_incident()
    call("SELECT sp_assign_incident(%s,%s,%s)", (inc, uid("analyst.rao"), uid("analyst.rao")))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):    # take-over blocked
        call("SELECT sp_assign_incident(%s,%s,%s)", (inc, uid("analyst.menon"), uid("analyst.menon")))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):    # note on someone else's incident
        call("SELECT sp_add_action(%s,%s,'NOTE','looked at it')", (inc, uid("analyst.menon")))
    ev = db.one("SELECT event_id FROM security_events ORDER BY event_id LIMIT 1")["event_id"]
    with pytest.raises(psycopg.errors.InsufficientPrivilege):    # evidence on someone else's incident
        call("SELECT sp_add_evidence(%s,%s,%s,'')", (inc, ev, uid("analyst.menon")))
    call("SELECT sp_assign_incident(%s,%s,%s)", (inc, uid("analyst.menon"), uid("admin.iyer")))  # admin may re-assign
    assert db.one("SELECT fn_current_analyst(%s) a", (inc,))["a"] == uid("analyst.menon")


def test_unassigned_incident_needs_assignment_before_notes():
    inc = new_incident()
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        call("SELECT sp_add_action(%s,%s,'NOTE','early note')", (inc, uid("analyst.das")))


# ---- loophole #9: closing needs a reason ------------------------------------
def test_reason_required_for_terminal_status():
    inc = new_incident()
    a = uid("analyst.das")
    call("SELECT sp_assign_incident(%s,%s,%s)", (inc, a, a))
    with pytest.raises(psycopg.errors.InvalidParameterValue):
        call("SELECT sp_set_incident_status(%s,'False Positive',%s,'')", (inc, a))
    call("SELECT sp_set_incident_status(%s,'False Positive',%s,'authorised scan')", (inc, a))


# ---- loophole #10: ISA total participation ------------------------------------
def test_event_without_subtype_row_is_rejected_at_commit():
    dev = db.one("SELECT device_id FROM devices LIMIT 1")["device_id"]
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        call("INSERT INTO security_events (device_id, event_timestamp, event_category) VALUES (%s, now(), 'port_scan')",
             (dev,))


# ---- loophole #11: organisation time zone -------------------------------------
def test_off_hours_uses_ist():
    dev = db.one("SELECT device_id FROM devices WHERE criticality=2 LIMIT 1")["device_id"]
    # 23:30 IST = 18:00 UTC  -> off-hours bonus applies; 10:00 IST = 04:30 UTC -> no bonus
    night = db.one("SELECT fn_event_risk('file_access', 0, %s, '2026-11-20 18:00+00') r", (dev,))["r"]
    day = db.one("SELECT fn_event_risk('file_access', 0, %s, '2026-11-20 04:30+00') r", (dev,))["r"]
    assert night - day == 8


# ---- loophole #4 / #2: provenance and tamper-evidence stored with every event --
def test_every_event_has_source_and_hash():
    r = db.one("""SELECT COUNT(*) FILTER (WHERE raw_log_ref IS NOT NULL AND raw_log_sha256 IS NULL) AS nohash,
                         COUNT(DISTINCT event_source) AS sources FROM security_events""")
    assert r["nohash"] == 0 and r["sources"] >= 2


def test_non_staff_and_cross_assign_rejected():
    inc = new_incident()
    emp = db.one("SELECT user_id FROM users WHERE role='Employee' LIMIT 1")["user_id"]
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        call("SELECT sp_assign_incident(%s,%s,%s)", (inc, emp, emp))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):   # analyst assigning someone else
        call("SELECT sp_assign_incident(%s,%s,%s)", (inc, uid("analyst.das"), uid("analyst.rao")))


# ---- loophole #1: databases refuse connections without credentials ------------
def test_postgres_requires_password():
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect("postgresql://dbmsel_app@127.0.0.1:5433/dbmsel", connect_timeout=3)
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect("postgresql://dbmsel_app:wrong@127.0.0.1:5433/dbmsel", connect_timeout=3)


def test_mongodb_requires_auth():
    import pymongo
    from pymongo.errors import OperationFailure
    c = pymongo.MongoClient("mongodb://127.0.0.1:27018", serverSelectionTimeoutMS=2000)
    with pytest.raises(OperationFailure):
        c["dbmsel_raw"]["raw_logs"].count_documents({})


@pytest.mark.parametrize("stmt", [
    "UPDATE audit_logs SET new_value='x'", "DELETE FROM audit_logs",
    "UPDATE security_events SET risk_score=0", "DELETE FROM security_events",
    "DELETE FROM investigation_actions", "DELETE FROM incidents", "UPDATE system_alerts SET risk_impact=0"])
def test_append_only(stmt):
    with pytest.raises(psycopg.Error):
        with db.conn() as c, c.cursor() as cur:
            cur.execute(stmt)


def test_disjoint_isa_enforced():
    ev = db.one("SELECT event_id FROM security_events WHERE event_kind='network' LIMIT 1")["event_id"]
    with pytest.raises(psycopg.errors.ForeignKeyViolation):     # network event cannot get a login row
        call("INSERT INTO login_events (event_id, login_status) VALUES (%s,'success')", (ev,))


def test_readonly_role_cannot_write():
    with pytest.raises(psycopg.Error):
        with db.conn("ro") as c, c.cursor() as cur:
            cur.execute("DELETE FROM users")
    with pytest.raises(psycopg.Error):
        with db.conn("ro") as c, c.cursor() as cur:
            cur.execute("SELECT * FROM user_credentials")
    with pytest.raises(ValueError):
        sqlguard.run_readonly("DELETE FROM users")


def test_alerts_and_last_seen_from_triggers():
    assert db.one("SELECT COUNT(*) n FROM system_alerts")["n"] > 0
    assert db.one("SELECT COUNT(*) n FROM devices WHERE last_seen IS NOT NULL")["n"] > 0
    assert db.one("SELECT COUNT(*) n FROM (SELECT event_id FROM system_alerts EXCEPT SELECT event_id FROM incident_events) t")["n"] == 0


def test_risk_components_sum_to_score():
    inc = db.one("SELECT incident_id, risk_score FROM incidents ORDER BY risk_score DESC LIMIT 1")
    assert 0 <= inc["risk_score"] <= 100
    assert abs(db.one("SELECT fn_incident_risk(%s) r", (inc["incident_id"],))["r"] - inc["risk_score"]) < 1


def test_every_sql_report_runs():
    for r in sql_reports.REPORTS:
        sql_reports.run(r["key"])


def test_nl_query_runs_offline(monkeypatch):
    from app import config
    monkeypatch.setattr(config, "LLM_PROVIDER", "none")      # deterministic, no model needed
    r = agent.ask("Which users had the most failed logins?")
    assert r["validated"] and r["rows"]
    assert agent.ask("drop table users")["rows"] == []


def test_example_buttons_are_instant_and_verified():
    r = agent.ask("Alerts by rule")
    assert r["mode"] == "verified example query" and r["validated"] and r["rows"]


def test_ai_cannot_change_data_whatever_the_provider():
    before = db.one("SELECT (SELECT COUNT(*) FROM users) u, (SELECT COUNT(*) FROM audit_logs) a")
    for q in ("drop table users", "delete every audit log row", "set every incident to Closed"):
        r = agent.ask(q)
        assert not r["sql"] or r["sql"].lstrip().upper().startswith(("SELECT", "WITH"))
    assert db.one("SELECT (SELECT COUNT(*) FROM users) u, (SELECT COUNT(*) FROM audit_logs) a") == before


def test_ctu_replay_detects_infected_hosts_without_false_alarms():
    """Held-out real CTU-13 botnets (scenarios 5, 11, 12) replayed by `seed`."""
    from app import cli
    r = cli.evaluate_ctu()
    if not r:
        pytest.skip("CTU-13 not replayed")
    flagged, total = map(int, r["infected_hosts_flagged"].split("/"))
    assert flagged == total
    assert r["alert_precision"] >= 0.9


# ---- loophole #12: shared servers do not glue unrelated users together ---------
def test_shared_server_does_not_link_different_users():
    vpn = db.one("SELECT device_id FROM devices WHERE hostname='vpn-gw-01'")["device_id"]
    u1, u2 = db.query("SELECT user_id FROM users WHERE role='Employee' ORDER BY user_id LIMIT 2")
    ids = []
    with db.conn() as c, c.cursor() as cur:
        for k, (u, ip) in enumerate([(u1["user_id"], "10.1.9.1"), (u2["user_id"], "10.1.9.2")]):
            cur.execute("""INSERT INTO security_events (device_id, user_id, event_timestamp, event_category,
                                                        source_ip, anomaly_score, event_source)
                           VALUES (%s, %s, now() - make_interval(mins => %s), 'new_device_access', %s, 0.9, 'simulator')
                           RETURNING event_id""", (vpn, u, 10 - k * 5, ip))
            eid = cur.fetchone()["event_id"]
            cur.execute("INSERT INTO login_events (event_id, login_status) VALUES (%s, 'success')", (eid,))
            ids.append(eid)
        c.commit()
    db.one("SELECT * FROM fn_correlate_events()")
    incs = {r["incident_id"] for r in db.query("SELECT incident_id FROM incident_events WHERE event_id = ANY(%s)", (ids,))}
    assert len(incs) == 2     # same VPN server, 5 minutes apart, different users -> separate incidents


# ---- loophole #13: open-incident risk is never stale after correlation ----------
def test_open_incident_risk_matches_recomputation():
    db.one("SELECT * FROM fn_correlate_events()")
    stale = db.query("""SELECT incident_id FROM incidents
                         WHERE status IN ('New','Investigating','Contained')
                           AND abs(risk_score - fn_incident_risk(incident_id)) > 0.01""")
    assert stale == []
