"""Automated response / containment and the security self-test. Needs a seeded DB."""
import os

os.environ["DISABLE_AUTOMATION"] = "1"
import psycopg
import pytest
from fastapi.testclient import TestClient

from app import db, selftest
from app.auth import DEFAULT_PASSWORD
from app.main import app

c = TestClient(app)


def tok(u):
    return {"Authorization": "Bearer " + c.post("/api/login", json={"username": u, "password": DEFAULT_PASSWORD}).json()["token"]}


def call(sql, params):
    with db.conn() as cn, cn.cursor() as cur:
        cur.execute(sql, params)
        cn.commit()


def test_critical_incidents_were_contained_automatically():
    r = db.one("""SELECT COUNT(*) FILTER (WHERE entity_type='ip') AS ips, COUNT(*) FILTER (WHERE entity_type='user') AS users
                    FROM blocked_entities WHERE actor='auto-response' AND active""")
    assert r["ips"] >= 1 and r["users"] >= 1
    # every automatically disabled account is a non-staff account
    staff = db.one("""SELECT COUNT(*) n FROM blocked_entities b JOIN users u ON u.user_id::text = b.entity_value
                       WHERE b.entity_type='user' AND b.actor='auto-response' AND u.role IN ('Analyst','Admin')""")["n"]
    assert staff == 0


def test_staff_accounts_are_flagged_not_disabled():
    # the seeded staff stay active even though admin.singh's account was compromised in a critical incident
    n = db.one("""SELECT COUNT(*) n FROM users WHERE role IN ('Analyst','Admin') AND NOT is_active
                   AND username IN ('analyst.rao','analyst.menon','analyst.das','admin.iyer','admin.singh')""")["n"]
    assert n == 0
    assert db.one("SELECT COUNT(*) n FROM audit_logs WHERE field_changed='auto_response_review'")["n"] >= 1


def test_returning_attacker_is_blocked_and_linked():
    h = tok("admin.iyer")
    inc = db.one("""SELECT incident_id FROM blocked_entities b JOIN incidents i USING (incident_id)
                     WHERE b.entity_type='ip' AND b.active AND i.status IN ('New','Investigating','Contained') LIMIT 1""")["incident_id"]
    r = c.post(f"/api/incidents/{inc}/attacker-returns", headers=h).json()
    assert r["attempts"] > 0 and r["blocked"] == r["attempts"] and r["blocked_attempt_alerts"] == r["attempts"]
    assert r["correlation"]["incidents_created"] == 0
    rules = {t["correlation_rule"] for t in c.get(f"/api/incidents/{inc}", headers=h).json()["timeline"] if t["blocked"]}
    assert rules == {"blocked_return"}


def test_attacker_returns_is_admin_only():
    assert c.post("/api/incidents/1/attacker-returns", headers=tok("analyst.rao")).status_code == 403


def test_manual_block_needs_ownership_and_reason_and_lift_needs_admin():
    rao = db.one("SELECT user_id FROM users WHERE username='analyst.rao'")["user_id"]
    menon = db.one("SELECT user_id FROM users WHERE username='analyst.menon'")["user_id"]
    inc = db.one("INSERT INTO incidents (title) VALUES ('pytest block') RETURNING incident_id")["incident_id"]
    call("SELECT sp_assign_incident(%s,%s,%s)", (inc, rao, rao))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):        # not the owner
        call("SELECT sp_block_entity(%s,'ip','203.0.113.9',%s,'suspicious host')", (inc, menon))
    with pytest.raises(psycopg.errors.InvalidParameterValue):        # no reason
        call("SELECT sp_block_entity(%s,'ip','203.0.113.9',%s,'')", (inc, rao))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):        # analyst cannot disable staff
        call("SELECT sp_block_entity(%s,'user','admin.iyer',%s,'testing it')", (inc, rao))
    call("SELECT sp_block_entity(%s,'ip','203.0.113.9',%s,'suspicious host')", (inc, rao))
    bid = db.one("SELECT block_id FROM blocked_entities WHERE entity_value='203.0.113.9' AND active")["block_id"]
    with pytest.raises(psycopg.errors.InsufficientPrivilege):        # only admins lift
        call("SELECT sp_lift_block(%s,%s,'false alarm')", (bid, rao))
    admin = db.one("SELECT user_id FROM users WHERE username='admin.iyer'")["user_id"]
    call("SELECT sp_lift_block(%s,%s,'false alarm')", (bid, admin))
    with pytest.raises(psycopg.Error):                                # a lifted block cannot be re-edited or deleted
        call("DELETE FROM blocked_entities WHERE block_id=%s", (bid,))
    audit = [a["field_changed"] for a in db.query("SELECT field_changed FROM audit_logs WHERE incident_id=%s", (inc,))]
    assert audit.count("containment") == 2                            # block + lift both audited


def test_security_self_test_blocks_everything():
    res = selftest.run()
    assert len(res) >= 12
    assert [r["attack"] for r in res if r["result"] != "BLOCKED"] == []
