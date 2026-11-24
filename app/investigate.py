"""Investigation tools + evidence-grounded analysis of an incident."""
from __future__ import annotations

import json

from . import db, llm, rag

MITRE = {"failed_login": ("Credential Access", "T1110"), "successful_login": ("Initial Access", "T1078"),
         "new_device_access": ("Persistence", "T1078"), "port_scan": ("Discovery", "T1046"),
         "confidential_file_access": ("Collection", "T1005"), "privilege_escalation": ("Privilege Escalation", "T1068"),
         "data_transfer": ("Exfiltration", "T1041"), "malware_alert": ("Execution", "T1204"),
         "file_access": ("Collection", "T1005")}
BIG_TRANSFER = 100 * 10 ** 6
_EXPLAIN_CACHE: dict[tuple, str] = {}


# ---------------------------- tools ------------------------------------
def get_incident(iid: int) -> dict | None:
    return db.one("SELECT * FROM v_incident_summary WHERE incident_id=%s", (iid,))


def get_timeline(iid: int) -> list[dict]:
    return db.query(
        """SELECT t.*, host(t.destination_ip) AS dst_ip FROM v_incident_timeline t
            WHERE t.incident_id=%s ORDER BY t.step_sequence""", (iid,))


def get_entities(iid: int) -> dict:
    return {
        "users": db.query("""SELECT DISTINCT u.user_id, u.username, u.role, u.department, c.compromise_rate
                               FROM incident_events ie JOIN security_events e USING (event_id)
                               JOIN users u ON u.user_id=e.user_id
                               JOIN v_user_compromise c ON c.user_id=u.user_id
                              WHERE ie.incident_id=%s""", (iid,)),
        "devices": db.query("""SELECT DISTINCT d.device_id, d.hostname, d.ip_address::text AS ip, d.criticality, d.device_type
                                 FROM incident_events ie JOIN security_events e USING (event_id)
                                 JOIN devices d USING (device_id) WHERE ie.incident_id=%s""", (iid,)),
        "ips": [r["ip"] for r in db.query(
            """SELECT DISTINCT host(e.source_ip) AS ip FROM incident_events ie JOIN security_events e USING (event_id)
                WHERE ie.incident_id=%s AND e.source_ip IS NOT NULL""", (iid,))],
    }


def risk_breakdown(iid: int) -> list[dict]:
    return db.query("SELECT * FROM fn_incident_risk_components(%s)", (iid,))


def get_blocks(iid: int) -> list[dict]:
    return db.query("SELECT * FROM v_blocks WHERE incident_id=%s ORDER BY block_id", (iid,))


def get_actions(iid: int) -> list[dict]:
    return db.query("""SELECT a.action_id, a.performed_at, a.action_type, a.action_notes, u.username AS analyst
                         FROM investigation_actions a JOIN users u ON u.user_id=a.analyst_id
                        WHERE a.incident_id=%s ORDER BY a.action_id""", (iid,))


def get_audit(iid: int) -> list[dict]:
    return db.query("""SELECT a.audit_id, a.changed_at, a.operation, a.field_changed, a.old_value, a.new_value,
                              a.actor, u.username AS analyst
                         FROM audit_logs a LEFT JOIN users u ON u.user_id=a.analyst_id
                        WHERE a.incident_id=%s ORDER BY a.audit_id""", (iid,))


# ------------------------- pattern detection ---------------------------
def detect_patterns(tl: list[dict]) -> list[dict]:
    """Find suspicious sequences in the (time-ordered) timeline."""
    out = []
    ids = lambda cat, pred=lambda r: True: [r["event_id"] for r in tl if r["event_category"] == cat and pred(r)]
    fails, logins = ids("failed_login"), ids("successful_login")
    if len(fails) >= 3:
        last_fail = max(r["step_sequence"] for r in tl if r["event_category"] == "failed_login")
        after = [r["event_id"] for r in tl if r["event_category"] == "successful_login" and r["step_sequence"] > last_fail]
        out.append({"pattern": "brute_force_then_success" if after else "brute_force",
                    "summary": f"{len(fails)} failed logins" + (" followed by a successful login" if after else ""),
                    "events": fails + after, "mitre": "T1110"})
    scans = ids("port_scan")
    if len(scans) >= 4:
        out.append({"pattern": "port_scan_burst", "summary": f"{len(scans)} scan probes from one source",
                    "events": scans, "mitre": "T1046"})
    nd = ids("new_device_access")
    if nd:
        out.append({"pattern": "new_device_access", "summary": "access from a previously unseen device" +
                    (" after authentication failures" if fails else ""), "events": nd, "mitre": "T1078"})
    cf = ids("confidential_file_access")
    if cf:
        out.append({"pattern": "sensitive_file_access", "summary": f"{len(cf)} confidential/restricted file reads",
                    "events": cf, "mitre": "T1005"})
    pe = ids("privilege_escalation")
    if pe:
        out.append({"pattern": "privilege_escalation", "summary": "account elevated to root/SYSTEM", "events": pe, "mitre": "T1068"})
    big = ids("data_transfer", lambda r: (r.get("bytes_sent") or 0) >= BIG_TRANSFER)
    if big:
        mb = sum((r.get("bytes_sent") or 0) for r in tl if r["event_id"] in big) / 1e6
        out.append({"pattern": "large_data_transfer", "summary": f"~{mb:,.0f} MB sent to external destination(s)",
                    "events": big, "mitre": "T1041"})
    mal = ids("malware_alert")
    if mal:
        out.append({"pattern": "malware_detected", "summary": "endpoint malware alert", "events": mal, "mitre": "T1204"})
    cats = {r["event_category"] for r in tl}
    chain = ["failed_login", "successful_login", "new_device_access", "confidential_file_access",
             "privilege_escalation", "data_transfer"]
    if sum(c in cats for c in chain) >= 5:
        out.append({"pattern": "full_kill_chain", "summary": "multi-stage chain: access -> collection -> escalation -> exfiltration",
                    "events": [r["event_id"] for r in tl], "mitre": "multiple"})
    return out


def _template_narrative(inc: dict, ent: dict, patterns: list[dict], tl: list[dict]) -> str:
    if not tl:
        return f"Incident #{inc['incident_id']} has no linked events yet; attach evidence to start the analysis."
    users = ", ".join(u["username"] for u in ent["users"]) or "no named user"
    devs = ", ".join(d["hostname"] for d in ent["devices"])
    first, last = tl[0], tl[-1]
    lines = [f"Incident #{inc['incident_id']} ({inc['severity_level']}, risk {inc['risk_score']}/100) spans "
             f"{len(tl)} correlated events from {first['event_timestamp']:%Y-%m-%d %H:%M} to {last['event_timestamp']:%H:%M} UTC, "
             f"involving {users} on {devs}."]
    if patterns:
        lines.append("Findings: " + "; ".join(p["summary"] for p in patterns) + ".")
    if any(p["pattern"] == "full_kill_chain" for p in patterns):
        lines.append("The ordering of events is consistent with an account takeover that progressed to data exfiltration. "
                     "Treat as a confirmed compromise until disproven.")
    elif any(p["pattern"] == "malware_detected" for p in patterns):
        lines.append("Isolate the affected host and collect the malware sample.")
    else:
        lines.append("Review the timeline to confirm whether the activity is expected.")
    return " ".join(lines)


def investigate(iid: int, with_llm: bool = False) -> dict | None:
    """with_llm=False (page loads): rule-based text, or a cached AI explanation.
    with_llm=True (the 'AI explanation' button): ask the model, then cache it."""
    inc = get_incident(iid)
    if not inc:
        return None
    tl, ent = get_timeline(iid), get_entities(iid)
    patterns = detect_patterns(tl)
    cats = sorted({r["event_category"] for r in tl})
    kb = rag.retrieve(cats, " ".join(p["pattern"].replace("_", " ") for p in patterns), k=5)
    stages = []
    for r in tl:
        stg = MITRE[r["event_category"]]
        if not stages or stages[-1]["tactic"] != stg[0]:
            stages.append({"tactic": stg[0], "technique": stg[1], "first_step": r["step_sequence"]})
    base = _template_narrative(inc, ent, patterns, tl)
    evidence = {"incident": {k: str(v) for k, v in inc.items()}, "patterns": patterns,
                "timeline": [{"step": r["step_sequence"], "time": str(r["event_timestamp"]), "event_id": r["event_id"],
                              "category": r["event_category"], "user": r["username"], "host": r["hostname"],
                              "src": r["source_ip"], "detail": r["detail"], "risk": str(r["risk_score"])} for r in tl[:40]],
                "knowledge": [{"ref": k["ref_id"], "title": k["title"], "text": k["body"]} for k in kb]}
    key = (iid, len(tl), str(inc["status"]), str(inc["risk_score"]), llm.describe())
    llm_text = _EXPLAIN_CACHE.get(key)
    if llm_text is None and with_llm:
        llm_text = llm.complete(
            "You are a SOC investigation assistant. Using ONLY the JSON evidence supplied, write a concise (max 150 words) "
            "analysis: what happened, why it is suspicious, and 3 recommended next actions. Cite event ids like [e123]. "
            "Do not invent facts that are not in the evidence.", json.dumps(evidence, default=str))
        if llm_text:
            _EXPLAIN_CACHE[key] = llm_text
    return {"incident": inc, "entities": ent, "patterns": patterns, "kill_chain": stages,
            "explanation": llm_text or base,
            "explanation_source": f"AI: {llm.describe()}" if llm_text else "rule-based",
            "ai_available": llm.available(),
            "context": [{"source": k["source"], "ref": k["ref_id"], "title": k["title"], "text": k["body"]} for k in kb],
            "risk_breakdown": risk_breakdown(iid)}
