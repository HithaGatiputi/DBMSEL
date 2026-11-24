-- =====================================================================
-- 04_views.sql : enriched views + materialized explainable risk view
-- =====================================================================

CREATE OR REPLACE VIEW v_events_enriched AS
SELECT e.event_id, e.event_timestamp, e.event_category, e.event_kind, e.severity, e.risk_score,
       e.anomaly_score, e.source_ip, e.raw_log_ref, e.event_source, e.blocked,
       u.user_id, u.username, u.department,
       d.device_id, d.hostname, d.ip_address AS device_ip, d.criticality,
       ie.incident_id,
       EXISTS (SELECT 1 FROM system_alerts a WHERE a.event_id = e.event_id) AS alerted
  FROM security_events e
  LEFT JOIN users u ON u.user_id = e.user_id
  JOIN devices d    ON d.device_id = e.device_id
  LEFT JOIN incident_events ie ON ie.event_id = e.event_id;

CREATE OR REPLACE VIEW v_incident_timeline AS
SELECT ie.incident_id, ie.step_sequence, e.event_id, e.event_timestamp,
       e.event_category, e.severity, e.risk_score, e.anomaly_score,
       u.username, d.hostname, e.source_ip, ie.correlation_rule, e.raw_log_ref, e.event_source, e.blocked,
       n.bytes_sent, n.destination_ip, f.is_sensitive,
       COALESCE(
         CASE WHEN l.event_id IS NOT NULL THEN l.auth_method || ' ' || l.login_status ||
              COALESCE(' (' || l.failure_reason || ')', '') || COALESCE(' geo=' || l.location_geo, '') END,
         CASE WHEN f.event_id IS NOT NULL THEN f.action_type || ' ' || f.file_path ||
              CASE WHEN f.is_sensitive THEN ' [sensitive]' ELSE '' END END,
         CASE WHEN n.event_id IS NOT NULL THEN n.protocol || ' -> ' || COALESCE(host(n.destination_ip),'?') || ':' ||
              COALESCE(n.destination_port::TEXT,'?') || ' sent=' || n.bytes_sent END,
         p.old_role || ' -> ' || p.new_role || ' via ' || p.method) AS detail
  FROM incident_events ie
  JOIN security_events e ON e.event_id = ie.event_id
  LEFT JOIN users u  ON u.user_id = e.user_id
  JOIN devices d     ON d.device_id = e.device_id
  LEFT JOIN login_events l       ON l.event_id = e.event_id
  LEFT JOIN file_access_events f ON f.event_id = e.event_id
  LEFT JOIN network_events n     ON n.event_id = e.event_id
  LEFT JOIN privilege_events p   ON p.event_id = e.event_id;

CREATE OR REPLACE VIEW v_incident_summary AS
SELECT i.incident_id, i.title, i.severity_level, i.status, i.risk_score,
       i.created_at, i.updated_at, i.resolved_at,
       iu.username AS primary_user, i.user_entity_role,
       idv.hostname AS primary_device, i.device_entity_role,
       an.username AS analyst,
       (SELECT COUNT(*) FROM incident_events x WHERE x.incident_id = i.incident_id) AS event_count,
       s.first_event, s.last_event, s.users_affected, s.devices_affected, s.sources,
       (SELECT COUNT(*) FROM blocked_entities b WHERE b.incident_id = i.incident_id AND b.active) AS active_blocks
  FROM incidents i
  LEFT JOIN users iu    ON iu.user_id = i.user_id
  LEFT JOIN devices idv ON idv.device_id = i.device_id
  LEFT JOIN users an    ON an.user_id = fn_current_analyst(i.incident_id)
  LEFT JOIN LATERAL (
        SELECT MIN(e.event_timestamp) AS first_event, MAX(e.event_timestamp) AS last_event,
               COUNT(DISTINCT e.user_id) AS users_affected, COUNT(DISTINCT e.device_id) AS devices_affected,
               ARRAY_AGG(DISTINCT e.event_source) AS sources
          FROM incident_events ie JOIN security_events e ON e.event_id = ie.event_id
         WHERE ie.incident_id = i.incident_id) s ON TRUE;

CREATE OR REPLACE VIEW v_alerts AS
SELECT a.alert_id, a.created_at, a.alert_type, a.rule_matched, a.risk_impact,
       fn_severity_label(a.risk_impact) AS severity,
       e.event_id, e.event_category, u.username, d.hostname, e.source_ip, ie.incident_id
  FROM system_alerts a
  JOIN security_events e ON e.event_id = a.event_id
  LEFT JOIN users u ON u.user_id = e.user_id
  JOIN devices d ON d.device_id = e.device_id
  LEFT JOIN incident_events ie ON ie.event_id = e.event_id;

CREATE OR REPLACE VIEW v_user_compromise AS
SELECT u.user_id, u.username, COUNT(e.event_id) AS total_events,
       COUNT(ie.event_id) AS events_in_incidents,
       ROUND(COUNT(ie.event_id)::NUMERIC / NULLIF(COUNT(e.event_id),0), 4) AS compromise_rate
  FROM users u
  LEFT JOIN security_events e ON e.user_id = u.user_id
  LEFT JOIN incident_events ie ON ie.event_id = e.event_id
 GROUP BY u.user_id, u.username;

CREATE MATERIALIZED VIEW mv_incident_risk AS
SELECT i.incident_id,
       ROUND(LEAST(100, SUM(c.contribution)), 2) AS risk_score,
       jsonb_object_agg(c.component, c.contribution) AS breakdown
  FROM incidents i, LATERAL fn_incident_risk_components(i.incident_id) c
 GROUP BY i.incident_id;
CREATE UNIQUE INDEX idx_mv_incident_risk ON mv_incident_risk (incident_id);

CREATE OR REPLACE VIEW v_blocks AS
SELECT b.block_id, b.entity_type,
       CASE WHEN b.entity_type = 'user' THEN u.username ELSE b.entity_value END AS entity,
       b.incident_id, i.title AS incident_title, b.reason, b.actor, bb.username AS blocked_by,
       b.created_at, b.active, b.lifted_at, lb.username AS lifted_by, b.lift_reason,
       (SELECT COUNT(*) FROM security_events e
         WHERE e.blocked AND ((b.entity_type = 'ip' AND host(e.source_ip) = b.entity_value)
                           OR (b.entity_type = 'user' AND e.user_id::TEXT = b.entity_value))) AS blocked_attempts
  FROM blocked_entities b
  LEFT JOIN users u  ON b.entity_type = 'user' AND u.user_id::TEXT = b.entity_value
  LEFT JOIN incidents i ON i.incident_id = b.incident_id
  LEFT JOIN users bb ON bb.user_id = b.blocked_by
  LEFT JOIN users lb ON lb.user_id = b.lifted_by;
