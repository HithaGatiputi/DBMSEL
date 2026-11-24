"""API tests: authentication, roles, validation. Need a seeded DB."""
import os

os.environ["DISABLE_AUTOMATION"] = "1"
import uuid

import pytest
from fastapi.testclient import TestClient

from app.auth import DEFAULT_PASSWORD
from app.main import app

c = TestClient(app)


def tok(user):
    r = c.post("/api/login", json={"username": user, "password": DEFAULT_PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def test_requires_login():
    assert c.get("/api/incidents").status_code == 401
    assert c.get("/api/incidents", headers={"Authorization": "Bearer forged.token"}).status_code == 401


def test_bad_password():
    assert c.post("/api/login", json={"username": "analyst.rao", "password": "nope"}).status_code == 401


def test_analyst_cannot_admin():
    h = tok("analyst.rao")
    assert c.get("/api/admin/users", headers=h).status_code == 403


def test_workflow_attributed_to_token_user():
    h = tok("analyst.das")
    from app import db
    inc = db.one("INSERT INTO incidents (title) VALUES ('pytest incident') RETURNING incident_id")["incident_id"]
    assert c.post(f"/api/incidents/{inc}/assign", json={}, headers=h).status_code == 200
    assert c.post(f"/api/incidents/{inc}/actions", json={"action_type": "NOTE", "notes": "checked logs"}, headers=h).status_code == 200
    d = c.get(f"/api/incidents/{inc}", headers=h).json()
    assert d["actions"][-1]["analyst"] == "analyst.das"
    assert c.post(f"/api/incidents/{inc}/status", json={"status": "Closed"}, headers=h).status_code == 409
    assert c.post(f"/api/incidents/{inc}/status", json={"status": "Bogus"}, headers=h).status_code == 422


@pytest.mark.parametrize("body", [
    {"username": "Bad Name", "email": "a@b.co", "role": "Employee", "department": "HR"},
    {"username": "okname", "email": "not-an-email", "role": "Employee", "department": "HR"},
    {"username": "okname", "email": "a@b.co", "role": "Hacker", "department": "HR"},
    {"username": "okname2", "email": "x@b.co", "role": "Analyst", "department": "SOC"},           # no password
    {"username": "okname3", "email": "y@b.co", "role": "Analyst", "department": "SOC", "password": "short"},
])
def test_admin_form_validation(body):
    assert c.post("/api/admin/users", json=body, headers=tok("admin.iyer")).status_code == 422


def test_admin_creates_device_and_it_is_audited():
    h = tok("admin.iyer")
    sfx = uuid.uuid4().hex[:4]
    host, mac = f"test-host-{sfx}", ":".join(["aa", "bb", "cc", "dd", sfx[:2], sfx[2:]])
    r = c.post("/api/admin/devices", headers=h, json={"hostname": host, "ip_address": "10.9.9.9",
              "mac_address": mac.upper().replace(":", "-"), "os_version": "Ubuntu 24.04", "device_type": "server", "criticality": 3})
    assert r.status_code == 200, r.text
    assert c.post("/api/admin/devices", headers=h, json={"hostname": host, "ip_address": "10.9.9.9",
                  "mac_address": "aa:bb:cc:dd:ee:98", "os_version": "x1", "device_type": "server"}).status_code == 409
    audit = c.get("/api/admin/entity-audit", headers=h).json()
    assert any(a["table_name"] == "devices" and a["changed_by"] == "admin.iyer" for a in audit)


def test_reports_and_csv():
    h = tok("analyst.rao")
    cat = c.get("/api/reports", headers=h).json()
    assert len(cat) >= 10
    r = c.get(f"/api/reports/{cat[0]['key']}?format=csv", headers=h)
    assert r.status_code == 200 and "," in r.text


# ---- loophole #4: only admins inject simulated attacks -----------------------
def test_simulate_is_admin_only():
    assert c.post("/api/simulate", json={"scenario": "privilege_abuse"}, headers=tok("analyst.rao")).status_code == 403


# ---- loophole #2: tampering with a raw MongoDB document is detected ------------
def test_raw_log_tampering_detected():
    from bson import ObjectId
    from app.rawstore import store
    from app import db
    ev = db.one("SELECT event_id, raw_log_ref FROM security_events WHERE event_source='simulator' LIMIT 1")
    h = tok("analyst.rao")
    assert c.get(f"/api/events/{ev['event_id']}/raw", headers=h).json()["integrity"] == "verified"
    col = store()._col
    orig = col.find_one({"_id": ObjectId(ev["raw_log_ref"])})["message"]
    try:
        col.update_one({"_id": ObjectId(ev["raw_log_ref"])}, {"$set": {"message": "nothing to see here"}})
        assert c.get(f"/api/events/{ev['event_id']}/raw", headers=h).json()["integrity"] == "TAMPERED"
    finally:
        col.update_one({"_id": ObjectId(ev["raw_log_ref"])}, {"$set": {"message": orig}})
    assert c.get(f"/api/events/{ev['event_id']}/raw", headers=h).json()["integrity"] == "verified"


def test_admin_integrity_scan():
    r = c.get("/api/admin/integrity", headers=tok("admin.iyer")).json()
    assert r["checked"] > 0 and r["TAMPERED"] == 0 and r["missing"] == 0


# ---- loopholes #6 and #8: reset kills sessions and forces a password change ----
def test_password_reset_revokes_sessions_and_forces_change():
    admin = tok("admin.iyer")
    name = "temp." + uuid.uuid4().hex[:6]
    r = c.post("/api/admin/users", headers=admin, json={"username": name, "email": f"{name}@x.io",
                                                        "role": "Analyst", "department": "SOC", "password": "Temp1234x"})
    assert r.status_code == 200, r.text
    uid_ = r.json()["user_id"]
    lg = c.post("/api/login", json={"username": name, "password": "Temp1234x"}).json()
    assert lg["user"]["must_change"] is True
    h = {"Authorization": "Bearer " + lg["token"]}
    assert c.get("/api/incidents", headers=h).status_code == 403            # blocked until changed
    r = c.post("/api/me/password", headers=h, json={"current_password": "Temp1234x", "new_password": "Better5678y"})
    assert r.status_code == 200
    assert c.get("/api/incidents", headers=h).status_code == 401             # old token revoked
    h2 = {"Authorization": "Bearer " + r.json()["token"]}
    assert c.get("/api/incidents", headers=h2).status_code == 200
    assert c.patch(f"/api/admin/users/{uid_}", headers=admin, json={"password": "Reset9999z"}).status_code == 200
    assert c.get("/api/incidents", headers=h2).status_code == 401            # admin reset kills session
    c.patch(f"/api/admin/users/{uid_}", headers=admin, json={"is_active": False})


# ---- loophole #7: lockout persists in the database -------------------------------
def test_lockout_is_persistent():
    from app import db
    for _ in range(5):
        c.post("/api/login", json={"username": "admin.singh", "password": "wrong"})
    assert c.post("/api/login", json={"username": "admin.singh", "password": DEFAULT_PASSWORD}).status_code == 429
    n = db.one("SELECT COUNT(*) n FROM login_attempts WHERE username='admin.singh' AND NOT success")["n"]
    assert n >= 6     # recorded in PostgreSQL, so a server restart does not reset it
