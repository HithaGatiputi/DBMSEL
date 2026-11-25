"""FastAPI backend + static dashboard.

Every /api route except /api/login and /api/health needs a bearer token.
The acting user is taken from the verified token (never from the body).
"""
from __future__ import annotations

import ipaddress
import json
import random
import re
from datetime import datetime, timedelta, timezone
from typing import Literal

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from . import agent, auth, automation, cli, config, db, flowml, ingest, llm, ml, rag, report, selftest, sql_reports
from . import investigate as inv
from .generator import SCENARIOS, Generator
from .rawstore import store

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(_app):
    automation.start()
    yield


app = FastAPI(title="Cybersecurity Incident Management & Investigation System", version="2.0", lifespan=lifespan)


def j(obj):
    return JSONResponse(json.loads(json.dumps(obj, default=str)))


# ------------------------------------------------------------------ auth
PASSWORD_CHANGE_ALLOWED = ("/api/me", "/api/me/password")


def current_user(request: Request, authorization: str = Header(default="")) -> dict:
    tok = authorization.removeprefix("Bearer ").strip()
    data = auth.read_token(tok) if tok else None
    if not data:
        raise HTTPException(401, "Please sign in")
    u = db.one("""SELECT u.user_id, u.username, u.role, u.department, c.token_version, c.must_change
                    FROM users u JOIN user_credentials c USING (user_id)
                   WHERE u.user_id=%s AND u.is_active""", (data["uid"],))
    if not u or u["role"] not in auth.STAFF_ROLES:
        raise HTTPException(401, "Account disabled")
    if data.get("tv") != u["token_version"]:
        raise HTTPException(401, "Your password was changed; please sign in again")
    if u["must_change"] and request.url.path not in PASSWORD_CHANGE_ALLOWED:
        raise HTTPException(403, "You must change your password before continuing")
    return u


def admin_user(u: dict = Depends(current_user)) -> dict:
    if u["role"] != "Admin":
        raise HTTPException(403, "Administrator role required")
    return u


class Login(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=1, max_length=128)


@app.post("/api/login")
def login(body: Login):
    try:
        u = auth.login(body.username.strip().lower(), body.password)
    except PermissionError as e:
        raise HTTPException(429, str(e))
    if not u:
        raise HTTPException(401, "Invalid username or password")
    return {"token": auth.make_token(u), "user": {k: u[k] for k in ("user_id", "username", "role", "must_change")}}


@app.get("/api/me")
def me(u: dict = Depends(current_user)):
    return {k: u[k] for k in ("user_id", "username", "role", "department", "must_change")}


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


@app.post("/api/me/password")
def change_password(body: PasswordChange, u: dict = Depends(current_user)):
    row = db.one("SELECT password_hash FROM user_credentials WHERE user_id=%s", (u["user_id"],))
    if not row or not auth.verify_password(body.current_password, row["password_hash"]):
        raise HTTPException(403, "Current password is incorrect")
    err = auth.validate_password_strength(body.new_password)
    if err:
        raise HTTPException(422, err)
    if body.new_password == body.current_password:
        raise HTTPException(422, "New password must differ from the current one")
    auth.set_password(u["user_id"], body.new_password, must_change=False)
    fresh = {**u, "token_version": u["token_version"] + 1}
    return {"ok": True, "token": auth.make_token(fresh)}


def _db_error(e: Exception):
    msg = str(e).splitlines()[0]
    code = getattr(e, "sqlstate", None)
    status = {"42501": 403, "23514": 409, "23505": 409, "P0002": 404, "22023": 422}.get(code, 400)
    raise HTTPException(status, msg)


def _tx(sql: str, params, actor: int | None = None):
    """Run a write in one transaction with the actor bound for audit triggers."""
    try:
        with db.conn() as c, c.cursor() as cur:
            if actor is not None:
                cur.execute("SELECT set_config('app.analyst_id', %s, true)", (str(actor),))
            cur.execute(sql, params)
            row = cur.fetchone() if cur.description else None
            c.commit()
            return row
    except psycopg.Error as e:
        _db_error(e)


# --------------------------------------------------------------- general
@app.get("/api/health")
def health():
    return j({"postgres": bool(db.one("SELECT 1 AS ok")), "raw_store": store().backend,
              "raw_documents": store().count(), "llm": llm.describe(),
              "model_loaded": ml.MODEL_FILE.exists(), "automation": automation.STATE})


@app.get("/api/stats")
def stats(u: dict = Depends(current_user)):
    return j({
        "events": db.one("SELECT COUNT(*) AS n FROM security_events")["n"],
        "alerts": db.one("SELECT COUNT(*) AS n FROM system_alerts")["n"],
        "incidents": db.one("SELECT COUNT(*) AS n FROM incidents")["n"],
        "active_blocks": db.one("SELECT COUNT(*) AS n FROM blocked_entities WHERE active")["n"],
        "blocked_attempts": db.one("SELECT COUNT(*) AS n FROM security_events WHERE blocked")["n"],
        "open_incidents": db.one("SELECT COUNT(*) AS n FROM incidents WHERE status IN ('New','Investigating','Contained')")["n"],
        "my_open": db.one("SELECT COUNT(*) AS n FROM incidents WHERE status IN ('Investigating','Contained') "
                          "AND fn_current_analyst(incident_id)=%s", (u["user_id"],))["n"],
        "by_severity": db.query("SELECT severity_level AS k, COUNT(*) AS n FROM incidents GROUP BY 1"),
        "by_status": db.query("SELECT status AS k, COUNT(*) AS n FROM incidents GROUP BY 1 ORDER BY 2 DESC"),
        "by_category": db.query("SELECT event_category AS k, COUNT(*) AS n FROM security_events GROUP BY 1 ORDER BY 2 DESC"),
        "events_per_day": db.query(
            "SELECT date_trunc('day', event_timestamp)::date AS d, COUNT(*) AS n, "
            "COUNT(*) FILTER (WHERE risk_score >= 50) AS risky FROM security_events GROUP BY 1 ORDER BY 1"),
        "ml": ml.metrics(), "flow_ml": flowml.metrics(), "ctu_eval": cli.evaluate_ctu(),
        "automation": automation.STATE,
    })


@app.get("/api/live")
def live(u: dict = Depends(current_user)):
    """Cheap change-detection for the dashboard's live updates."""
    return j(db.one("""SELECT (SELECT COALESCE(MAX(alert_id), 0) FROM system_alerts) AS last_alert,
                              (SELECT COALESCE(MAX(incident_id), 0) FROM incidents) AS last_incident,
                              (SELECT COALESCE(MAX(block_id), 0) FROM blocked_entities) AS last_block,
                              (SELECT COUNT(*) FROM security_events WHERE blocked) AS blocked_attempts,
                              (SELECT row_to_json(x) FROM (SELECT incident_id, title, severity_level, risk_score
                                 FROM incidents ORDER BY updated_at DESC LIMIT 1) x) AS latest_incident,
                              (SELECT row_to_json(b) FROM (SELECT entity_type, entity, incident_id FROM v_blocks
                                 ORDER BY block_id DESC LIMIT 1) b) AS latest_block"""))


@app.get("/api/users")
def users(role: str | None = None, u: dict = Depends(current_user)):
    return j(db.query("SELECT user_id, username, role, department FROM users WHERE is_active AND "
                      "(%s::text IS NULL OR role=%s) ORDER BY username", (role, role)))


# ---------------------------------------------------------------- events
@app.get("/api/events")
def events(category: str | None = None, min_risk: float = Query(0, ge=0, le=100), username: str | None = None,
           alerted: bool | None = None, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
           u: dict = Depends(current_user)):
    return j(db.query(
        """SELECT event_id, event_timestamp, event_category, severity, risk_score, anomaly_score, username, hostname,
                  host(source_ip) AS source_ip, incident_id, alerted, raw_log_ref
             FROM v_events_enriched
            WHERE (%s::text IS NULL OR event_category=%s) AND risk_score >= %s
              AND (%s::text IS NULL OR username=%s) AND (%s::bool IS NULL OR alerted=%s)
            ORDER BY event_timestamp DESC LIMIT %s OFFSET %s""",
        (category, category, min_risk, username, username, alerted, alerted, limit, offset)))


@app.get("/api/events/{event_id}/raw")
def raw_event(event_id: int, u: dict = Depends(current_user)):
    row = db.one("SELECT raw_log_ref, raw_log_sha256, event_source FROM security_events WHERE event_id=%s", (event_id,))
    if not row:
        raise HTTPException(404, "event not found")
    doc = store().get(row["raw_log_ref"]) if row["raw_log_ref"] else None
    integrity = store().verify(row["raw_log_ref"], row["raw_log_sha256"]) if row["raw_log_ref"] else "no-raw-log"
    return j({"event_id": event_id, "raw_log_ref": row["raw_log_ref"], "backend": store().backend,
              "sha256": row["raw_log_sha256"], "integrity": integrity, "event_source": row["event_source"],
              "document": doc})


@app.get("/api/events/{event_id}/window")
def event_window(event_id: int, minutes: int = Query(30, ge=1, le=720), u: dict = Depends(current_user)):
    return j(db.query("""SELECT w.*, us.username, d.hostname, host(w.source_ip) AS src,
                                (SELECT incident_id FROM incident_events ie WHERE ie.event_id=w.event_id LIMIT 1) AS incident_id
                           FROM fn_event_window(%s, make_interval(mins => %s)) w
                           LEFT JOIN users us ON us.user_id = w.user_id JOIN devices d ON d.device_id = w.device_id""",
                      (event_id, minutes)))


@app.get("/api/logs/search")
def search_logs(q: str = Query(min_length=2, max_length=100), limit: int = Query(25, le=100),
                u: dict = Depends(current_user)):
    return j({"backend": store().backend, "results": store().search(q, limit)})


@app.get("/api/alerts")
def alerts(limit: int = Query(200, le=500), u: dict = Depends(current_user)):
    return j(db.query("SELECT * FROM v_alerts ORDER BY created_at DESC LIMIT %s", (limit,)))


# ------------------------------------------------------------- incidents
@app.get("/api/incidents")
def incidents(status: str | None = None, severity: str | None = None, mine: bool = False,
              limit: int = Query(200, le=500), u: dict = Depends(current_user)):
    return j(db.query(
        """SELECT * FROM v_incident_summary
            WHERE (%s::text IS NULL OR status=%s) AND (%s::text IS NULL OR severity_level=%s)
              AND (NOT %s OR analyst = %s)
            ORDER BY risk_score DESC, incident_id DESC LIMIT %s""",
        (status, status, severity, severity, mine, u["username"], limit)))


@app.get("/api/incidents/{iid}")
def incident(iid: int, u: dict = Depends(current_user)):
    a = inv.investigate(iid)
    if not a:
        raise HTTPException(404, "incident not found")
    return j({**a, "timeline": inv.get_timeline(iid), "audit": inv.get_audit(iid), "actions": inv.get_actions(iid),
              "blocks": inv.get_blocks(iid)})


# ------------------------------------------------------- response / containment
class BlockIn(BaseModel):
    entity_type: Literal["ip", "user"]
    value: str = Field(min_length=3, max_length=64)
    reason: str = Field(min_length=5, max_length=500)


class LiftIn(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


@app.get("/api/blocks")
def blocks(active: bool | None = None, u: dict = Depends(current_user)):
    return j(db.query("SELECT * FROM v_blocks WHERE (%s::bool IS NULL OR active = %s) ORDER BY block_id DESC",
                      (active, active)))


@app.post("/api/incidents/{iid}/block")
def block(iid: int, body: BlockIn, u: dict = Depends(current_user)):
    row = _tx("SELECT sp_block_entity(%s, %s, %s, %s, %s) AS block_id",
              (iid, body.entity_type, body.value.strip(), u["user_id"], body.reason.strip()))
    return {"ok": True, "block_id": row["block_id"]}


@app.post("/api/blocks/{bid}/lift")
def lift(bid: int, body: LiftIn, u: dict = Depends(current_user)):
    _tx("SELECT sp_lift_block(%s, %s, %s)", (bid, u["user_id"], body.reason.strip()))
    return {"ok": True}


@app.post("/api/incidents/{iid}/attacker-returns")
def attacker_returns(iid: int, u: dict = Depends(admin_user)):
    """Demo: the contained attacker comes back from the same IP."""
    from .generator import attacker_returns as gen_return
    b = db.one("""SELECT entity_value FROM blocked_entities WHERE incident_id=%s AND entity_type='ip' AND active
                  ORDER BY block_id LIMIT 1""", (iid,))
    if not b:
        raise HTTPException(409, "This incident has no active IP block yet; contain it first")
    victim = db.one("""SELECT entity_value::int AS uid FROM blocked_entities WHERE incident_id=%s AND entity_type='user'
                       AND active LIMIT 1""", (iid,))
    events_ = gen_return(Generator(seed=random.randint(1, 10 ** 6)), b["entity_value"], victim["uid"] if victim else None,
                         datetime.now(timezone.utc).replace(microsecond=0))
    ids = ingest.ingest_events(events_, use_history=True)
    res = automation.correlate_now()
    r = db.one("""SELECT COUNT(*) FILTER (WHERE blocked) AS blocked, COUNT(*) AS total,
                         (SELECT COUNT(*) FROM system_alerts WHERE event_id = ANY(%s) AND alert_type='BLOCKED_ATTEMPT') AS alerts
                    FROM security_events WHERE event_id = ANY(%s)""", (ids, ids))
    return j({"attacker_ip": b["entity_value"], "attempts": r["total"], "blocked": r["blocked"],
              "blocked_attempt_alerts": r["alerts"], "correlation": res})


class PolicyPatch(BaseModel):
    min_risk: float | None = Field(None, ge=0, le=100)
    contain_on_takeover: bool | None = None
    block_external_ips: bool | None = None
    disable_accounts: bool | None = None
    is_active: bool | None = None


@app.get("/api/admin/response-policy")
def get_policy(u: dict = Depends(current_user)):
    return j(db.one("SELECT * FROM response_policy ORDER BY policy_id LIMIT 1"))


@app.patch("/api/admin/response-policy")
def patch_policy(body: PolicyPatch, u: dict = Depends(admin_user)):
    fields = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    if not fields:
        raise HTTPException(422, "nothing to update")
    sets = ", ".join(f"{k}=%s" for k in fields)
    _tx(f"UPDATE response_policy SET {sets} WHERE policy_id=(SELECT MIN(policy_id) FROM response_policy) RETURNING policy_id",
        tuple(fields.values()), u["user_id"])
    return {"ok": True}


@app.post("/api/admin/self-test")
def self_test(u: dict = Depends(admin_user)):
    return j(selftest.summary(selftest.run()))


@app.post("/api/incidents/{iid}/ai-explanation")
def ai_explanation(iid: int, u: dict = Depends(current_user)):
    if not llm.available():
        raise HTTPException(503, "No AI model is available (offline mode)")
    a = inv.investigate(iid, with_llm=True)
    if not a:
        raise HTTPException(404, "incident not found")
    if a["explanation_source"] == "rule-based":
        raise HTTPException(502, "The AI model did not answer; showing the rule-based analysis")
    return j({"explanation": a["explanation"], "source": a["explanation_source"]})


class Assign(BaseModel):
    assignee_id: int | None = None          # default: yourself


class Status(BaseModel):
    status: Literal["Investigating", "Contained", "Resolved", "Closed", "False Positive"]
    notes: str = Field("", max_length=1000)     # required (>= 5 chars) for Resolved/Closed/False Positive


class Action(BaseModel):
    action_type: Literal["NOTE", "CONTAINMENT", "ESCALATION"]
    notes: str = Field(min_length=3, max_length=2000)


class Evidence(BaseModel):
    event_id: int = Field(gt=0)
    notes: str = Field("", max_length=500)


@app.post("/api/incidents/{iid}/assign")
def assign(iid: int, body: Assign, u: dict = Depends(current_user)):
    _tx("SELECT sp_assign_incident(%s, %s, %s)", (iid, body.assignee_id or u["user_id"], u["user_id"]))
    return {"ok": True}


@app.post("/api/incidents/{iid}/status")
def set_status(iid: int, body: Status, u: dict = Depends(current_user)):
    _tx("SELECT sp_set_incident_status(%s, %s, %s, %s)", (iid, body.status, u["user_id"], body.notes.strip()))
    return {"ok": True}


@app.post("/api/incidents/{iid}/actions")
def add_action(iid: int, body: Action, u: dict = Depends(current_user)):
    _tx("SELECT sp_add_action(%s, %s, %s, %s)", (iid, u["user_id"], body.action_type, body.notes.strip()))
    return {"ok": True}


@app.post("/api/incidents/{iid}/evidence")
def add_evidence(iid: int, body: Evidence, u: dict = Depends(current_user)):
    _tx("SELECT sp_add_evidence(%s, %s, %s, %s)", (iid, body.event_id, u["user_id"], body.notes.strip()))
    db.query("SELECT sp_refresh_risk()")
    return {"ok": True}


@app.get("/api/incidents/{iid}/report")
def incident_report(iid: int, format: Literal["json", "md"] = "json", u: dict = Depends(current_user)):
    r = report.build(iid)
    if not r:
        raise HTTPException(404, "incident not found")
    if format == "md":
        return PlainTextResponse(report.to_markdown(r), media_type="text/markdown",
                                 headers={"Content-Disposition": f'attachment; filename="incident-{iid}.md"'})
    return j(r)


@app.get("/api/audit")
def audit(limit: int = Query(200, le=500), u: dict = Depends(current_user)):
    return j(db.query(
        """SELECT a.audit_id, a.changed_at, a.incident_id, a.operation, a.field_changed, a.old_value, a.new_value,
                  a.actor, us.username AS analyst
             FROM audit_logs a LEFT JOIN users us ON us.user_id=a.analyst_id
            WHERE a.field_changed <> 'evidence_added' ORDER BY a.changed_at DESC LIMIT %s""", (limit,)))


# ------------------------------------------------------------- AI / query
class Question(BaseModel):
    question: str = Field(min_length=3, max_length=500)


@app.post("/api/query")
def query(body: Question, u: dict = Depends(current_user)):
    return j(agent.ask(body.question))


@app.get("/api/kb")
def kb(q: str = "", categories: str = "", u: dict = Depends(current_user)):
    return j(rag.retrieve([c for c in categories.split(",") if c], q, 8))


@app.get("/api/reports")
def reports_list(u: dict = Depends(current_user)):
    return sql_reports.catalogue()


@app.get("/api/reports/{key}")
def reports_run(key: str, format: Literal["json", "csv"] = "json", u: dict = Depends(current_user)):
    if key not in sql_reports.BY_KEY:
        raise HTTPException(404, "unknown report")
    res = sql_reports.run(key)
    if format == "csv":
        return PlainTextResponse(sql_reports.to_csv(res), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="{key}.csv"'})
    return j(res)


# ----------------------------------------------------- automation / demo
class Correlate(BaseModel):
    window_minutes: int = Field(30, ge=1, le=1440)


@app.post("/api/correlate")
def correlate(body: Correlate = Correlate(), u: dict = Depends(current_user)):
    with automation._lock:
        return j(cli.correlate(body.window_minutes))


class Sim(BaseModel):
    scenario: Literal["account_takeover_exfil", "recon_bruteforce", "insider_data_theft",
                      "malware_outbreak", "privilege_abuse"] = "account_takeover_exfil"


@app.post("/api/simulate")
def simulate(body: Sim = Sim(), u: dict = Depends(admin_user)):
    """Admin-only: injected events are tagged event_source='simulator'."""
    gen = Generator(seed=random.randint(1, 10 ** 6))
    t0 = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=45)
    ids = ingest.ingest_events(gen.attack(body.scenario, t0), use_history=True)
    res = automation.correlate_now()
    inc = db.one("SELECT incident_id FROM incident_events WHERE event_id = ANY(%s) "
                 "GROUP BY incident_id ORDER BY COUNT(*) DESC LIMIT 1", (ids,))
    return j({"scenario": body.scenario, "events_injected": len(ids), "correlation": res,
              "incident_id": inc["incident_id"] if inc else None})


class Stream(BaseModel):
    on: bool
    correlate_every_seconds: int = Field(60, ge=15, le=3600)


@app.post("/api/admin/automation")
def set_automation(body: Stream, u: dict = Depends(admin_user)):
    automation.STATE["stream_on"] = body.on
    automation.STATE["auto_correlate_seconds"] = body.correlate_every_seconds
    return j(automation.STATE)


@app.get("/api/ml")
def ml_info(u: dict = Depends(current_user)):
    return j({"behaviour_model": ml.metrics(), "flow_model": flowml.metrics(), "ctu13_pipeline": cli.evaluate_ctu()})


class CtuReplay(BaseModel):
    scenario: int = Field(11, ge=1, le=13)
    minutes: int = Field(60, ge=5, le=240)


@app.post("/api/admin/ctu-replay")
def ctu_replay(body: CtuReplay, u: dict = Depends(admin_user)):
    try:
        with automation._lock:
            return j(cli.ctu_replay(body.scenario, body.minutes))
    except (FileNotFoundError, ValueError) as e:
        raise HTTPException(404, str(e))


# ------------------------------------------------------------------ admin
USERNAME_RE = re.compile(r"^[a-z][a-z0-9._-]{2,49}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{1,78}[A-Za-z0-9]$")
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
Role = Literal["Employee", "Analyst", "Admin", "Executive", "Service"]
DevType = Literal["workstation", "server", "database", "firewall", "laptop"]


class UserIn(BaseModel):
    username: str
    email: str
    role: Role
    department: str = Field(min_length=2, max_length=50)
    password: str | None = None

    @field_validator("username")
    @classmethod
    def _u(cls, v):
        v = v.strip().lower()
        if not USERNAME_RE.match(v):
            raise ValueError("username: 3-50 chars, lowercase letters, digits, . _ -; must start with a letter")
        return v

    @field_validator("email")
    @classmethod
    def _e(cls, v):
        v = v.strip()
        if not EMAIL_RE.match(v):
            raise ValueError("invalid email address")
        return v


class UserPatch(BaseModel):
    role: Role | None = None
    department: str | None = Field(None, min_length=2, max_length=50)
    is_active: bool | None = None
    password: str | None = None


def _check_pw(pw: str | None):
    if pw is not None:
        err = auth.validate_password_strength(pw)
        if err:
            raise HTTPException(422, err)


@app.get("/api/admin/users")
def admin_users(u: dict = Depends(admin_user)):
    return j(db.query("""SELECT u.user_id, u.username, u.email, u.role, u.department, u.is_active, u.created_at,
                                (c.user_id IS NOT NULL) AS can_login,
                                (SELECT COUNT(*) FROM devices d WHERE d.owner_id=u.user_id) AS devices
                           FROM users u LEFT JOIN user_credentials c USING (user_id) ORDER BY u.user_id"""))


@app.post("/api/admin/users")
def admin_create_user(body: UserIn, u: dict = Depends(admin_user)):
    _check_pw(body.password)
    if body.role in auth.STAFF_ROLES and not body.password:
        raise HTTPException(422, "Analyst/Admin accounts need an initial password")
    row = _tx("INSERT INTO users (username,email,role,department) VALUES (%s,%s,%s,%s) RETURNING user_id",
              (body.username, body.email, body.role, body.department.strip()), u["user_id"])
    if body.password:     # temporary password: must be changed at first sign-in
        auth.set_password(row["user_id"], body.password, must_change=True)
    return {"ok": True, "user_id": row["user_id"]}


@app.patch("/api/admin/users/{uid}")
def admin_update_user(uid: int, body: UserPatch, u: dict = Depends(admin_user)):
    _check_pw(body.password)
    if uid == u["user_id"] and (body.is_active is False or (body.role and body.role != "Admin")):
        raise HTTPException(409, "You cannot deactivate or demote your own account")
    fields = {k: v for k, v in body.model_dump().items() if v is not None and k != "password"}
    if fields:
        sets = ", ".join(f"{k}=%s" for k in fields)
        row = _tx(f"UPDATE users SET {sets} WHERE user_id=%s RETURNING user_id", (*fields.values(), uid), u["user_id"])
        if not row:
            raise HTTPException(404, "user not found")
    if body.password:     # reset: kills existing sessions, must be changed at next sign-in
        auth.set_password(uid, body.password, must_change=True)
    if body.is_active is False:   # deactivation also kills existing sessions
        db.query("UPDATE user_credentials SET token_version = token_version + 1 WHERE user_id=%s", (uid,))
    return {"ok": True}


class DeviceIn(BaseModel):
    hostname: str
    ip_address: str
    mac_address: str
    os_version: str = Field(min_length=2, max_length=60)
    device_type: DevType
    criticality: int = Field(2, ge=1, le=5)
    owner_id: int | None = None

    @field_validator("hostname")
    @classmethod
    def _h(cls, v):
        if not HOST_RE.match(v.strip()):
            raise ValueError("hostname: 3-80 chars, letters, digits and hyphens")
        return v.strip()

    @field_validator("ip_address")
    @classmethod
    def _ip(cls, v):
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError:
            raise ValueError("invalid IP address")

    @field_validator("mac_address")
    @classmethod
    def _mac(cls, v):
        v = v.strip().lower().replace("-", ":")
        if not MAC_RE.match(v):
            raise ValueError("MAC must look like aa:bb:cc:dd:ee:ff")
        return v


class DevicePatch(BaseModel):
    os_version: str | None = Field(None, min_length=2, max_length=60)
    criticality: int | None = Field(None, ge=1, le=5)
    owner_id: int | None = None
    device_type: DevType | None = None


@app.get("/api/admin/devices")
def admin_devices(u: dict = Depends(admin_user)):
    return j(db.query("""SELECT d.device_id, d.hostname, host(d.ip_address) AS ip_address, d.mac_address::text,
                                d.os_version, d.device_type, d.criticality, d.last_seen, o.username AS owner, d.owner_id
                           FROM devices d LEFT JOIN users o ON o.user_id=d.owner_id ORDER BY d.device_id"""))


@app.post("/api/admin/devices")
def admin_create_device(body: DeviceIn, u: dict = Depends(admin_user)):
    row = _tx("""INSERT INTO devices (hostname,ip_address,mac_address,os_version,device_type,criticality,owner_id)
                 VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING device_id""",
              (body.hostname, body.ip_address, body.mac_address, body.os_version, body.device_type,
               body.criticality, body.owner_id), u["user_id"])
    return {"ok": True, "device_id": row["device_id"]}


@app.patch("/api/admin/devices/{did}")
def admin_update_device(did: int, body: DevicePatch, u: dict = Depends(admin_user)):
    fields = {k: v for k, v in body.model_dump(exclude_unset=True).items()}
    if not fields:
        raise HTTPException(422, "nothing to update")
    sets = ", ".join(f"{k}=%s" for k in fields)
    row = _tx(f"UPDATE devices SET {sets} WHERE device_id=%s RETURNING device_id", (*fields.values(), did), u["user_id"])
    if not row:
        raise HTTPException(404, "device not found")
    return {"ok": True}


class RulePatch(BaseModel):
    base_risk: float | None = Field(None, ge=0, le=100)
    min_anomaly: float | None = Field(None, ge=0, le=1)
    is_active: bool | None = None
    description: str | None = Field(None, max_length=300)


@app.get("/api/admin/rules")
def admin_rules(u: dict = Depends(current_user)):
    return j(db.query("""SELECT r.*, (SELECT COUNT(*) FROM system_alerts a WHERE a.rule_matched=r.rule_name) AS alerts
                           FROM detection_rules r ORDER BY rule_id"""))


@app.patch("/api/admin/rules/{rid}")
def admin_update_rule(rid: int, body: RulePatch, u: dict = Depends(admin_user)):
    fields = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    if not fields:
        raise HTTPException(422, "nothing to update")
    sets = ", ".join(f"{k}=%s" for k in fields)
    row = _tx(f"UPDATE detection_rules SET {sets} WHERE rule_id=%s RETURNING rule_id", (*fields.values(), rid), u["user_id"])
    if not row:
        raise HTTPException(404, "rule not found")
    return {"ok": True, "note": "Applies to events ingested from now on"}


@app.get("/api/admin/integrity")
def admin_integrity(scope: Literal["evidence", "all"] = "evidence", u: dict = Depends(admin_user)):
    """Re-hash raw documents and compare with the hash stored at ingest."""
    where = "WHERE e.event_id IN (SELECT event_id FROM incident_events)" if scope == "evidence" else ""
    rows = db.query(f"SELECT e.event_id, e.raw_log_ref, e.raw_log_sha256 FROM security_events e {where}")
    counts, bad = {"verified": 0, "TAMPERED": 0, "missing": 0, "no-hash": 0, "no-raw-log": 0}, []
    for r in rows:
        v = store().verify(r["raw_log_ref"], r["raw_log_sha256"]) if r["raw_log_ref"] else "no-raw-log"
        counts[v] += 1
        if v in ("TAMPERED", "missing"):
            bad.append({"event_id": r["event_id"], "result": v})
    return j({"scope": scope, "checked": len(rows), **counts, "problems": bad[:50]})


@app.get("/api/admin/entity-audit")
def admin_entity_audit(limit: int = Query(100, le=500), u: dict = Depends(admin_user)):
    return j(db.query("""SELECT e.entity_audit_id, e.changed_at, e.table_name, e.row_pk, e.operation,
                                e.old_row, e.new_row, us.username AS changed_by
                           FROM entity_audit_log e LEFT JOIN users us ON us.user_id=e.changed_by
                          WHERE e.changed_by IS NOT NULL ORDER BY e.entity_audit_id DESC LIMIT %s""", (limit,)))


# ---------------------------------------------------------------- static
app.mount("/static", StaticFiles(directory=config.ROOT / "frontend"), name="static")


@app.get("/")
def index():
    return FileResponse(config.ROOT / "frontend" / "index.html")
