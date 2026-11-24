"""Natural-language -> SQL investigation agent.

LLM mode (ANTHROPIC_API_KEY set): the model writes SQL from the schema
description; every statement is validated by sqlguard and executed on the
read-only role. Offline mode: a deterministic intent library produces the
same kind of validated SQL, so the system works without any API key.
"""
from __future__ import annotations

import json
import re

from . import llm, sqlguard

SCHEMA_DOC = """PostgreSQL schema (read-only, SELECT only):
users(user_id, username, email, role[Employee|Analyst|Admin|Executive|Service], department, is_active, created_at)
devices(device_id, owner_id->users, hostname, ip_address, mac_address, os_version, device_type, last_seen, criticality 1-5)
security_events(event_id, device_id->devices, user_id->users, event_timestamp, event_category[failed_login|successful_login|new_device_access|file_access|confidential_file_access|privilege_escalation|data_transfer|port_scan|malware_alert], event_kind[login|network|file|privilege], source_ip, severity[Low|Medium|High|Critical], anomaly_score 0-1, risk_score 0-100, raw_log_ref, event_source[sensor|simulator|ctu13], blocked)
login_events(event_id, auth_method, login_status[success|failure], failure_reason, location_geo)
network_events(event_id, destination_ip, destination_port, protocol, bytes_sent, bytes_received)
file_access_events(event_id, file_path, action_type, is_sensitive)
privilege_events(event_id, old_role, new_role, method)
system_alerts(alert_id, event_id, alert_type[ML_ANOMALY|RULE_THRESHOLD], rule_matched, risk_impact, created_at)
detection_rules(rule_id, rule_name, event_category, base_risk, min_anomaly, is_active)
incidents(incident_id, user_id, device_id, title, severity_level, status[New|Investigating|Contained|Resolved|Closed|False Positive], risk_score, created_at, updated_at, resolved_at, user_entity_role, device_entity_role)
incident_events(incident_id, event_id, correlated_at, step_sequence, correlation_rule)
investigation_actions(action_id, incident_id, analyst_id->users, action_type, action_notes, performed_at)
audit_logs(incident_id, audit_id, field_changed, old_value, new_value, changed_at, analyst_id, actor, operation)
v_blocks(block_id, entity_type[ip|user], entity, incident_id, reason, actor[auto-response|analyst], blocked_by, created_at, active, lifted_at, blocked_attempts)  -- containment; security_events.blocked marks events from blocked IPs/accounts
Views: v_events_enriched(event_id,event_timestamp,event_category,severity,risk_score,anomaly_score,source_ip,username,department,hostname,criticality,incident_id,alerted),
v_incident_timeline(incident_id,step_sequence,event_id,event_timestamp,event_category,severity,risk_score,username,hostname,source_ip,correlation_rule,detail,bytes_sent,destination_ip,is_sensitive),
v_incident_summary(incident_id,title,severity_level,status,risk_score,created_at,primary_user,user_entity_role,primary_device,device_entity_role,analyst,event_count,first_event,last_event,users_affected,devices_affected),
v_alerts(alert_id,created_at,alert_type,rule_matched,risk_impact,severity,event_id,event_category,username,hostname,source_ip,incident_id),
v_user_compromise(user_id,username,total_events,events_in_incidents,compromise_rate), mv_incident_risk(incident_id,risk_score,breakdown jsonb).
"""

SYSTEM = ("You translate analyst questions into ONE PostgreSQL SELECT query for the schema below. "
          "Output only the SQL, no prose, no markdown. Use only the listed tables/views. Never modify data. "
          "Prefer the views. Always include a sensible ORDER BY and LIMIT <= 100.\n" + SCHEMA_DOC + """
Rules:
- Alerts are rows of v_alerts (or system_alerts). There is NO event_category called 'alert'.
- Use only the literal values listed above for event_category, status, severity, role, event_source; never invent values.
- Show IP addresses with host(column). Dates: event_timestamp >= now() - interval '7 days'.
- If the request asks to change, delete or reveal secrets (passwords, credentials), output: SELECT 'request not allowed' AS message
Examples:
Q: Top 5 source IPs by number of alerts
SQL: SELECT host(source_ip) AS source_ip, COUNT(*) AS alerts FROM v_alerts WHERE source_ip IS NOT NULL GROUP BY 1 ORDER BY alerts DESC LIMIT 5
Q: Which departments have the most critical events?
SQL: SELECT department, COUNT(*) AS critical_events FROM v_events_enriched WHERE severity = 'Critical' GROUP BY department ORDER BY critical_events DESC LIMIT 20
Q: Average risk of real CTU-13 events vs simulated
SQL: SELECT event_source, ROUND(AVG(risk_score), 2) AS avg_risk, COUNT(*) AS events FROM security_events GROUP BY event_source ORDER BY event_source
Q: Incidents involving more than one user
SQL: SELECT incident_id, title, severity_level, status, users_affected, created_at FROM v_incident_summary WHERE users_affected > 1 ORDER BY created_at DESC LIMIT 50
Hints: per-incident counts (event_count, users_affected, devices_affected), the assigned analyst and first/last event times are already columns of v_incident_summary.
""")

# The dashboard's example buttons map straight to tested queries (instant, deterministic);
# the model is used for everything the analyst types themselves.
EXAMPLE_QUESTIONS = {"show open critical incidents", "which users had the most failed logins?",
                     "who accessed restricted files after hours?", "transfers larger than 100 mb", "alerts by rule",
                     "analyst workload", "which ips ran port scans?", "how many incidents per severity?",
                     "show open incidents by risk"}

SUGGESTIONS = ["Show open incidents by risk", "Which users had the most failed logins?",
               "Who accessed restricted files after hours?", "Show timeline of incident 5",
               "Transfers larger than 100 MB", "How many incidents per severity?",
               "Audit log for incident 5", "Which IPs ran port scans?", "Alerts by rule", "Analyst workload"]


def _num(q: str, default: int | None = None) -> int | None:
    m = re.search(r"\b(\d+)\b", q)
    return int(m.group(1)) if m else default


def offline_sql(q: str) -> str | None:
    s = q.lower()
    inc = re.search(r"incident\s*#?\s*(\d+)", s)
    user = re.search(r"\b([a-z]+\.[a-z]+)\b", s)
    if inc and "audit" in s:
        return f"SELECT changed_at, actor, operation, field_changed, old_value, new_value FROM audit_logs WHERE incident_id={int(inc[1])} ORDER BY audit_id"
    if inc and any(w in s for w in ("action", "note", "who worked")):
        return (f"SELECT a.performed_at, u.username AS analyst, a.action_type, a.action_notes FROM investigation_actions a "
                f"JOIN users u ON u.user_id = a.analyst_id WHERE a.incident_id={int(inc[1])} ORDER BY a.action_id")
    if inc and any(w in s for w in ("timeline", "events", "detail", "what happened", "sequence")):
        return (f"SELECT step_sequence, event_timestamp, event_category, username, hostname, source_ip, risk_score, detail "
                f"FROM v_incident_timeline WHERE incident_id={int(inc[1])} ORDER BY step_sequence")
    if inc:
        return f"SELECT * FROM v_incident_summary WHERE incident_id={int(inc[1])}"
    if "alert" in s:
        return ("SELECT rule_matched, alert_type, COUNT(*) AS alerts, ROUND(AVG(risk_impact),1) AS avg_risk, "
                "COUNT(incident_id) AS correlated FROM v_alerts GROUP BY 1,2 ORDER BY alerts DESC")
    if "analyst" in s and ("workload" in s or "assigned" in s or "per analyst" in s):
        return ("SELECT COALESCE(analyst,'(unassigned)') AS analyst, COUNT(*) AS incidents, "
                "COUNT(*) FILTER (WHERE status IN ('New','Investigating','Contained')) AS open "
                "FROM v_incident_summary GROUP BY 1 ORDER BY incidents DESC")
    if "audit" in s or "who changed" in s:
        return "SELECT changed_at, incident_id, actor, field_changed, old_value, new_value FROM audit_logs ORDER BY audit_id DESC LIMIT 50"
    if "per severity" in s or "by severity" in s or ("how many" in s and "incident" in s):
        return "SELECT severity_level, status, COUNT(*) AS incidents FROM incidents GROUP BY 1,2 ORDER BY 1,2"
    if "unassigned" in s:
        return "SELECT incident_id, title, severity_level, risk_score FROM v_incident_summary WHERE analyst IS NULL AND status='New' ORDER BY risk_score DESC LIMIT 25"
    if "incident" in s:
        where = []
        for sev in ("critical", "high", "medium", "low"):
            if sev in s:
                where.append(f"severity_level='{sev.capitalize()}'")
        if "open" in s or "active" in s:
            where.append("status IN ('New','Investigating','Contained')")
        n = _num(s, 15)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        return (f"SELECT incident_id, title, severity_level, status, risk_score, event_count, analyst FROM v_incident_summary "
                f"{w} ORDER BY risk_score DESC LIMIT {min(n, 100)}")
    if "failed login" in s or "brute" in s:
        return ("SELECT COALESCE(username,'(unknown)') AS username, COUNT(*) AS failed_logins, COUNT(DISTINCT source_ip) AS source_ips "
                "FROM v_events_enriched WHERE event_category='failed_login' GROUP BY 1 ORDER BY failed_logins DESC LIMIT 15")
    if any(w in s for w in ("restricted", "confidential")):
        after = " AND (EXTRACT(HOUR FROM event_timestamp) >= 22 OR EXTRACT(HOUR FROM event_timestamp) < 6)" if "after hours" in s or "night" in s else ""
        return ("SELECT v.username, v.hostname, f.action_type, f.file_path, v.event_timestamp, v.risk_score "
                "FROM v_events_enriched v JOIN file_access_events f USING (event_id) "
                f"WHERE f.is_sensitive{after.replace('event_timestamp','v.event_timestamp')} "
                "ORDER BY v.event_timestamp DESC LIMIT 50")
    if any(w in s for w in ("transfer", "exfil", "upload", "data out")):
        mb = _num(s, 100)
        return ("SELECT v.event_timestamp, v.username, v.hostname, host(v.source_ip) AS src, host(n.destination_ip) AS dst, "
                "ROUND(n.bytes_sent/1e6, 1) AS mb_sent, v.risk_score, v.incident_id FROM v_events_enriched v "
                "JOIN network_events n USING (event_id) "
                f"WHERE v.event_category='data_transfer' AND n.bytes_sent >= {mb}*1000000 ORDER BY n.bytes_sent DESC LIMIT 25")
    if "scan" in s:
        return ("SELECT host(source_ip) AS source_ip, COUNT(*) AS probes, MIN(event_timestamp) AS first_seen, MAX(event_timestamp) AS last_seen "
                "FROM security_events WHERE event_category='port_scan' GROUP BY 1 ORDER BY probes DESC LIMIT 20")
    if "privilege" in s or "escalat" in s or "root" in s:
        return ("SELECT v.event_timestamp, v.username, v.hostname, p.old_role, p.new_role, p.method, v.risk_score "
                "FROM v_events_enriched v JOIN privilege_events p USING (event_id) ORDER BY v.risk_score DESC, v.event_timestamp DESC LIMIT 30")
    if "new device" in s:
        return ("SELECT event_timestamp, username, hostname, host(source_ip) AS source_ip, risk_score FROM v_events_enriched "
                "WHERE event_category='new_device_access' ORDER BY event_timestamp DESC LIMIT 30")
    if "malware" in s:
        return ("SELECT event_timestamp, username, hostname, risk_score, incident_id FROM v_events_enriched "
                "WHERE event_category='malware_alert' ORDER BY event_timestamp DESC LIMIT 30")
    if "compromis" in s or "risky user" in s:
        return "SELECT username, total_events, events_in_incidents, compromise_rate FROM v_user_compromise ORDER BY compromise_rate DESC NULLS LAST LIMIT 15"
    if user:
        return (f"SELECT event_timestamp, event_category, hostname, host(source_ip) AS source_ip, risk_score, incident_id "
                f"FROM v_events_enriched WHERE username='{user[1]}' ORDER BY event_timestamp DESC LIMIT 50")
    if "device" in s or "host" in s:
        return "SELECT hostname, device_type, criticality, host(ip_address) AS ip FROM devices ORDER BY criticality DESC, hostname LIMIT 50"
    if "event" in s:
        return ("SELECT event_timestamp, event_category, username, hostname, severity, risk_score FROM v_events_enriched "
                "ORDER BY risk_score DESC, event_timestamp DESC LIMIT 30")
    return None


def _clean_sql(t: str) -> str:
    """Pull the SQL out of a model reply (local models sometimes add prose or fences)."""
    m = re.search(r"```(?:sql)?\s*(.*?)```", t, flags=re.S | re.I)
    if m:
        t = m.group(1)
    m = re.search(r"\b(WITH|SELECT)\b", t, flags=re.I)
    if m:
        t = t[m.start():]
    t = t.strip()
    if ";" in t:                      # keep only the first statement
        t = t[:t.index(";")]
    return t.strip()


def _jsonable(rows):
    return json.loads(json.dumps(rows, default=str))


def _summarise(question, cols, rows) -> str:
    if not rows:
        return "The query ran successfully but returned no rows."
    if llm.provider() == "ollama":      # local model: skip the second (slow) call, template is instant
        first = ", ".join(f"{k}={v}" for k, v in list(_jsonable(rows[0]).items())[:4])
        return f"{len(rows)} row(s) returned. Top result: {first}."
    text = llm.complete("Answer the analyst's question in at most 3 sentences using ONLY the result rows provided. "
                        "Be specific with names and numbers.",
                        f"Question: {question}\nRows (first 20): {json.dumps(_jsonable(rows[:20]))}", 300)
    if text:
        return text
    first = ", ".join(f"{k}={v}" for k, v in list(_jsonable(rows[0]).items())[:4])
    return f"{len(rows)} row(s) returned. Top result: {first}."


def ask(question: str) -> dict:
    out = {"question": question, "mode": "llm: " + llm.describe() if llm.available() else "offline-intent", "sql": None,
           "validated": False, "columns": [], "rows": [], "answer": "", "error": None}
    sql, err = None, None
    if question.strip().lower() in EXAMPLE_QUESTIONS and offline_sql(question):
        out["mode"] = "verified example query"
    elif llm.available():
        for attempt in range(2):
            prompt = question if not err else f"{question}\n\nYour previous SQL failed: {err}\nPrevious SQL: {sql}\nFix it."
            raw = llm.complete(SYSTEM, prompt, 500)
            if not raw:
                break
            sql = _clean_sql(raw)
            v = sqlguard.validate(sql)
            if not v.ok:
                err = v.reason
                continue
            try:
                cols, rows = sqlguard.run_readonly(sql)
                out.update(sql=v.sql, validated=True, columns=cols, rows=_jsonable(rows))
                out["answer"] = _summarise(question, cols, rows)
                return out
            except Exception as e:     # runtime SQL error -> retry with feedback
                err = str(e).splitlines()[0]
        out["mode"] = "built-in query (AI could not answer this exactly; closest match shown)" if llm.available() \
            else "offline-intent"
    sql = offline_sql(question)
    if sql is None:
        out["error"] = "I could not map that question to a query. Try: " + "; ".join(SUGGESTIONS[:4])
        return out
    v = sqlguard.validate(sql)
    if not v.ok:
        out["error"] = f"Blocked by SQL validator: {v.reason}"
        out["sql"] = sql
        return out
    try:
        cols, rows = sqlguard.run_readonly(sql)
    except Exception as e:
        out["error"] = str(e).splitlines()[0]
        out["sql"] = v.sql
        return out
    out.update(sql=v.sql, validated=True, columns=cols, rows=_jsonable(rows))
    out["answer"] = _summarise(question, cols, rows)
    return out
