"""Catalogue of named SQL reports. Each demonstrates a DBMS concept and runs
on the read-only role. Shown in the dashboard's "SQL Reports" tab and
exportable as CSV."""
from __future__ import annotations

import csv
import io

from . import config, db

REPORTS = [
    {"key": "incident_overview", "title": "Open incidents with involved entities", "concept": "Multi-table JOIN + view",
     "sql": """SELECT incident_id, title, severity_level, status, risk_score, primary_user, user_entity_role,
                      primary_device, device_entity_role, analyst, event_count
                 FROM v_incident_summary
                WHERE status IN ('New','Investigating','Contained')
                ORDER BY risk_score DESC"""},
    {"key": "severity_status_matrix", "title": "Incidents per severity and status", "concept": "GROUP BY + FILTER aggregates",
     "sql": """SELECT severity_level, COUNT(*) AS total,
                      COUNT(*) FILTER (WHERE status='New') AS new,
                      COUNT(*) FILTER (WHERE status='Investigating') AS investigating,
                      COUNT(*) FILTER (WHERE status IN ('Resolved','Closed')) AS resolved_or_closed,
                      COUNT(*) FILTER (WHERE status='False Positive') AS false_positive
                 FROM incidents GROUP BY severity_level
                ORDER BY array_position(ARRAY['Critical','High','Medium','Low'], severity_level)"""},
    {"key": "bruteforce_sources", "title": "Brute-force sources (>= 5 failures from one IP)", "concept": "GROUP BY + HAVING over a sub-type join",
     "sql": """SELECT host(e.source_ip) AS source_ip, COUNT(*) AS failures,
                      COUNT(DISTINCT e.user_id) AS accounts_targeted, MIN(e.event_timestamp) AS first_seen,
                      MAX(e.event_timestamp) AS last_seen, string_agg(DISTINCT l.location_geo, ',') AS geo
                 FROM security_events e JOIN login_events l USING (event_id)
                WHERE l.login_status = 'failure'
                GROUP BY e.source_ip HAVING COUNT(*) >= 5 ORDER BY failures DESC"""},
    {"key": "above_avg_exfil", "title": "Transfers larger than the average transfer", "concept": "Nested (scalar) sub-query",
     "sql": """SELECT e.event_id, e.event_timestamp, u.username, d.hostname, host(n.destination_ip) AS destination,
                      ROUND(n.bytes_sent/1e6,1) AS mb_sent
                 FROM network_events n JOIN security_events e USING (event_id)
                 JOIN devices d ON d.device_id = e.device_id LEFT JOIN users u ON u.user_id = e.user_id
                WHERE e.event_category = 'data_transfer'
                  AND n.bytes_sent > (SELECT AVG(bytes_sent) * 10 FROM network_events)
                ORDER BY n.bytes_sent DESC"""},
    {"key": "users_beyond_dept_baseline", "title": "Users whose risk exceeds their department's average", "concept": "Correlated sub-query",
     "sql": """SELECT u.username, u.department, ROUND(AVG(e.risk_score),2) AS avg_risk
                 FROM users u JOIN security_events e ON e.user_id = u.user_id
                GROUP BY u.user_id, u.username, u.department
               HAVING AVG(e.risk_score) > (SELECT AVG(e2.risk_score) FROM security_events e2
                                             JOIN users u2 ON u2.user_id = e2.user_id
                                            WHERE u2.department = u.department)
                ORDER BY avg_risk DESC"""},
    {"key": "silent_devices", "title": "Devices that never generated an event", "concept": "LEFT OUTER JOIN / anti-join",
     "sql": """SELECT d.hostname, d.device_type, d.criticality, o.username AS owner
                 FROM devices d LEFT JOIN security_events e ON e.device_id = d.device_id
                 LEFT JOIN users o ON o.user_id = d.owner_id
                WHERE e.event_id IS NULL ORDER BY d.hostname"""},
    {"key": "priv_and_sensitive", "title": "Users who escalated privileges AND touched sensitive files", "concept": "Set operation (INTERSECT)",
     "sql": """SELECT u.username FROM users u JOIN security_events e ON e.user_id = u.user_id
                WHERE e.event_category = 'privilege_escalation'
               INTERSECT
               SELECT u.username FROM users u JOIN security_events e ON e.user_id = u.user_id
                 JOIN file_access_events f ON f.event_id = e.event_id WHERE f.is_sensitive
               ORDER BY 1"""},
    {"key": "alerts_not_in_incident", "title": "Alerted events not yet in any incident", "concept": "Set operation (EXCEPT)",
     "sql": """SELECT event_id FROM system_alerts
               EXCEPT
               SELECT event_id FROM incident_events ORDER BY 1"""},
    {"key": "user_risk_rank", "title": "Riskiest users ranked within department", "concept": "Window functions (RANK, SUM OVER)",
     "sql": """SELECT department, username, total_risk,
                      RANK() OVER (PARTITION BY department ORDER BY total_risk DESC) AS dept_rank,
                      ROUND(100.0 * total_risk / SUM(total_risk) OVER (PARTITION BY department), 1) AS pct_of_dept
                 FROM (SELECT u.department, u.username, SUM(e.risk_score) AS total_risk
                         FROM users u JOIN security_events e ON e.user_id = u.user_id
                        GROUP BY u.department, u.username) t
                ORDER BY department, dept_rank"""},
    {"key": "attack_chain_gaps", "title": "Time between consecutive steps of each incident", "concept": "Window function LAG + CTE",
     "sql": """WITH steps AS (
                 SELECT incident_id, step_sequence, event_category, event_timestamp,
                        event_timestamp - LAG(event_timestamp) OVER (PARTITION BY incident_id ORDER BY step_sequence) AS gap
                   FROM v_incident_timeline)
               SELECT incident_id, step_sequence, event_category, event_timestamp, gap
                 FROM steps WHERE incident_id IN (SELECT incident_id FROM incidents ORDER BY risk_score DESC LIMIT 3)
                ORDER BY incident_id, step_sequence"""},
    {"key": "hourly_activity", "title": "Events per hour of day, organisation time (IST)", "concept": "Date functions + CASE",
     "sql": """SELECT EXTRACT(HOUR FROM event_timestamp AT TIME ZONE fn_org_timezone())::INT AS hour_ist, COUNT(*) AS events,
                      COUNT(*) FILTER (WHERE risk_score >= 50) AS risky,
                      CASE WHEN EXTRACT(HOUR FROM event_timestamp AT TIME ZONE fn_org_timezone()) < 6
                             OR EXTRACT(HOUR FROM event_timestamp AT TIME ZONE fn_org_timezone()) >= 22 THEN 'off-hours' ELSE 'business' END AS period
                 FROM security_events GROUP BY 1, 4 ORDER BY 1"""},
    {"key": "risk_explained", "title": "Explainable risk breakdown (materialized view)", "concept": "Materialized view + JSONB",
     "sql": """SELECT m.incident_id, i.title, m.risk_score,
                      m.breakdown->>'peak_event_severity' AS peak, m.breakdown->>'attack_stage_diversity' AS stages,
                      m.breakdown->>'asset_criticality' AS asset, m.breakdown->>'entity_compromise_history' AS history
                 FROM mv_incident_risk m JOIN incidents i USING (incident_id)
                ORDER BY m.risk_score DESC LIMIT 15"""},
    {"key": "audit_by_analyst", "title": "Audit trail: changes per analyst and field", "concept": "Trigger-populated table + aggregation",
     "sql": """SELECT COALESCE(u.username, a.actor) AS who, a.field_changed, COUNT(*) AS changes, MAX(a.changed_at) AS last_change
                 FROM audit_logs a LEFT JOIN users u ON u.user_id = a.analyst_id
                WHERE a.field_changed <> 'evidence_added'
                GROUP BY 1, 2 ORDER BY changes DESC"""},
    {"key": "mttr", "title": "Mean time to resolve by severity", "concept": "Interval arithmetic + AVG",
     "sql": """SELECT severity_level, COUNT(*) AS resolved,
                      justify_interval(AVG(resolved_at - created_at)) AS mean_time_to_resolve
                 FROM incidents WHERE resolved_at IS NOT NULL GROUP BY severity_level ORDER BY 1"""},
    {"key": "ctu13_hosts", "title": "Real botnet replay (CTU-13): alerts per host", "concept": "Aggregation over real data + LEFT JOIN",
     "sql": """SELECT d.hostname, COUNT(e.event_id) AS flows, COUNT(a.alert_id) AS alerts,
                      ROUND(MAX(e.anomaly_score), 3) AS max_anomaly,
                      COUNT(DISTINCT ie.incident_id) AS incidents,
                      MIN(e.event_timestamp) AS first_flow, MAX(e.event_timestamp) AS last_flow
                 FROM devices d JOIN security_events e ON e.device_id = d.device_id
                 LEFT JOIN system_alerts a ON a.event_id = e.event_id
                 LEFT JOIN incident_events ie ON ie.event_id = e.event_id
                WHERE d.hostname LIKE 'ctu%'
                GROUP BY d.hostname ORDER BY alerts DESC, flows DESC"""},
    {"key": "isa_distribution", "title": "Disjoint ISA: sub-type row counts vs. parent", "concept": "Generalisation / specialisation check",
     "sql": """SELECT e.event_kind, COUNT(*) AS parent_rows,
                      COUNT(l.event_id) + COUNT(n.event_id) + COUNT(f.event_id) + COUNT(p.event_id) AS subtype_rows
                 FROM security_events e
                 LEFT JOIN login_events l USING (event_id) LEFT JOIN network_events n USING (event_id)
                 LEFT JOIN file_access_events f USING (event_id) LEFT JOIN privilege_events p USING (event_id)
                GROUP BY e.event_kind ORDER BY 1"""},
]
BY_KEY = {r["key"]: r for r in REPORTS}


def catalogue() -> list[dict]:
    return [{k: r[k] for k in ("key", "title", "concept", "sql")} for r in REPORTS]


def run(key: str) -> dict:
    r = BY_KEY[key]
    with db.conn("ro") as c:
        with c.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute(r["sql"])
            cols = [d.name for d in cur.description]
            rows = cur.fetchmany(config.MAX_QUERY_ROWS)
        c.rollback()
    return {**{k: r[k] for k in ("key", "title", "concept", "sql")}, "columns": cols, "rows": rows}


def to_csv(result: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(result["columns"])
    for row in result["rows"]:
        w.writerow([row[c] for c in result["columns"]])
    return buf.getvalue()
