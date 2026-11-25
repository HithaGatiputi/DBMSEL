-- =====================================================================
-- 02_functions.sql : scoring, alerting, correlation, analyst procedures
-- =====================================================================

CREATE OR REPLACE FUNCTION fn_severity_label(p_score NUMERIC)
RETURNS VARCHAR LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN p_score >= 75 THEN 'Critical'
                WHEN p_score >= 50 THEN 'High'
                WHEN p_score >= 25 THEN 'Medium'
                ELSE 'Low' END;
$$;

-- Organisation time zone used for "off-hours" (all timestamps are stored as timestamptz)
CREATE OR REPLACE FUNCTION fn_org_timezone() RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
    SELECT 'Asia/Kolkata'::TEXT;
$$;

-- DFD 2.2 Classify & score: rule base weight (admin-configurable) + ML
-- anomaly*25 + asset criticality*3 + 8 for off-hours (22:00-06:00 organisation time)
CREATE OR REPLACE FUNCTION fn_event_risk(
    p_category VARCHAR, p_anomaly NUMERIC, p_device INT, p_ts TIMESTAMPTZ)
RETURNS NUMERIC LANGUAGE plpgsql STABLE AS $$
DECLARE
    v_base NUMERIC; v_crit INT;
    v_hour INT := EXTRACT(HOUR FROM p_ts AT TIME ZONE fn_org_timezone());
BEGIN
    SELECT base_risk INTO v_base FROM detection_rules
     WHERE event_category = p_category AND is_active;
    SELECT criticality INTO v_crit FROM devices WHERE device_id = p_device;
    RETURN LEAST(100, ROUND(COALESCE(v_base, 5) + COALESCE(p_anomaly, 0) * 25
                            + COALESCE(v_crit, 2) * 3
                            + CASE WHEN v_hour < 6 OR v_hour >= 22 THEN 8 ELSE 0 END, 2));
END $$;

-- Who is currently assigned = analyst of the latest ASSIGN action ------
CREATE OR REPLACE FUNCTION fn_current_analyst(p_incident INT) RETURNS INT
LANGUAGE sql STABLE AS $$
    SELECT analyst_id FROM investigation_actions
     WHERE incident_id = p_incident AND action_type = 'ASSIGN'
     ORDER BY action_id DESC LIMIT 1;
$$;

-- Explainable incident risk ---------------------------------------------
CREATE OR REPLACE FUNCTION fn_incident_risk_components(p_incident INT)
RETURNS TABLE(component TEXT, raw_value NUMERIC, weight TEXT, contribution NUMERIC)
LANGUAGE plpgsql STABLE AS $$
DECLARE v_max NUMERIC; v_avg NUMERIC; v_cats INT; v_crit INT; v_hist NUMERIC;
BEGIN
    SELECT MAX(e.risk_score), AVG(e.risk_score), COUNT(DISTINCT e.event_category), MAX(d.criticality)
      INTO v_max, v_avg, v_cats, v_crit
      FROM incident_events ie
      JOIN security_events e ON e.event_id = ie.event_id
      JOIN devices d         ON d.device_id = e.device_id
     WHERE ie.incident_id = p_incident;

    SELECT COALESCE(MAX(rate), 0) INTO v_hist FROM (
        SELECT (SELECT COUNT(*) FROM incident_events ie2
                  JOIN security_events e2 ON e2.event_id = ie2.event_id
                 WHERE e2.user_id = u.user_id AND ie2.incident_id <> p_incident)::NUMERIC
               / NULLIF((SELECT COUNT(*) FROM security_events e3 WHERE e3.user_id = u.user_id), 0) AS rate
          FROM (SELECT DISTINCT e.user_id FROM incident_events ie
                  JOIN security_events e ON e.event_id = ie.event_id
                 WHERE ie.incident_id = p_incident AND e.user_id IS NOT NULL) u) t;

    RETURN QUERY VALUES
      ('peak_event_severity'::TEXT, COALESCE(v_max,0), '0.40 x max event risk', ROUND(0.40 * COALESCE(v_max,0), 2)),
      ('average_event_severity', COALESCE(v_avg,0), '0.10 x mean event risk', ROUND(0.10 * COALESCE(v_avg,0), 2)),
      ('attack_stage_diversity', COALESCE(v_cats,0)::NUMERIC, '5 per distinct stage (cap 20)',
            LEAST(20, 5 * COALESCE(v_cats,0))::NUMERIC),
      ('asset_criticality', COALESCE(v_crit,0)::NUMERIC, '3 per criticality level (cap 15)',
            LEAST(15, 3 * COALESCE(v_crit,0))::NUMERIC),
      ('entity_compromise_history', ROUND(v_hist,3), '15 x min(1, 10 x rate)', ROUND(15 * LEAST(1, 10 * v_hist), 2));
END $$;

CREATE OR REPLACE FUNCTION fn_incident_risk(p_incident INT)
RETURNS NUMERIC LANGUAGE sql STABLE AS $$
    SELECT COALESCE(LEAST(100, ROUND(SUM(contribution), 2)), 0)
      FROM fn_incident_risk_components(p_incident);
$$;

-- Title from the observed attack chain ------------------------------------
CREATE OR REPLACE FUNCTION fn_incident_title(p_incident INT) RETURNS TEXT
LANGUAGE plpgsql STABLE AS $$
DECLARE v_cats TEXT[]; v_failed INT; v_entity TEXT; v_title TEXT;
BEGIN
    SELECT ARRAY_AGG(DISTINCT e.event_category),
           COUNT(*) FILTER (WHERE e.event_category = 'failed_login')
      INTO v_cats, v_failed
      FROM incident_events ie JOIN security_events e ON e.event_id = ie.event_id
     WHERE ie.incident_id = p_incident;

    SELECT COALESCE(
        (SELECT u.username FROM incident_events ie JOIN security_events e ON e.event_id = ie.event_id
           JOIN users u ON u.user_id = e.user_id WHERE ie.incident_id = p_incident
          GROUP BY u.username ORDER BY COUNT(*) DESC LIMIT 1),
        (SELECT d.hostname FROM incident_events ie JOIN security_events e ON e.event_id = ie.event_id
           JOIN devices d ON d.device_id = e.device_id WHERE ie.incident_id = p_incident
          GROUP BY d.hostname ORDER BY COUNT(*) DESC LIMIT 1), 'unknown') INTO v_entity;

    v_title := CASE
      WHEN v_cats @> ARRAY['privilege_escalation','data_transfer'] AND (v_cats && ARRAY['failed_login','new_device_access'])
        THEN 'Account takeover with privilege escalation and data exfiltration'
      WHEN v_cats @> ARRAY['port_scan'] AND (v_cats && ARRAY['failed_login','new_device_access'])
        THEN 'Reconnaissance followed by credential attack'
      WHEN v_cats @> ARRAY['malware_alert'] THEN 'Malware activity'
      WHEN v_cats @> ARRAY['confidential_file_access','data_transfer'] THEN 'Suspected data exfiltration'
      WHEN v_cats @> ARRAY['privilege_escalation'] THEN 'Suspicious privilege escalation'
      WHEN v_failed >= 3 THEN 'Brute-force authentication attempts'
      WHEN v_cats @> ARRAY['new_device_access'] THEN 'Access from unrecognised device'
      WHEN v_cats @> ARRAY['data_transfer'] THEN 'Unusual data transfer'
      WHEN v_cats @> ARRAY['port_scan'] THEN 'Network reconnaissance (port scan)'
      ELSE 'Suspicious activity' END;
    RETURN v_title || ' [' || v_entity || ']';
END $$;

-- "Involves" relationship: primary user/device and their entity_role ------
CREATE OR REPLACE FUNCTION fn_incident_entities(p_incident INT,
    OUT o_user INT, OUT o_user_role TEXT, OUT o_device INT, OUT o_device_role TEXT)
LANGUAGE plpgsql STABLE AS $$
DECLARE v_cats TEXT[]; v_ext BOOLEAN;
BEGIN
    SELECT ARRAY_AGG(DISTINCT e.event_category),
           BOOL_OR(e.source_ip IS NOT NULL AND NOT (e.source_ip << '10.0.0.0/8' OR e.source_ip << '172.16.0.0/12'
                                                   OR e.source_ip << '192.168.0.0/16'))
      INTO v_cats, v_ext
      FROM incident_events ie JOIN security_events e ON e.event_id = ie.event_id
     WHERE ie.incident_id = p_incident;

    SELECT e.user_id INTO o_user FROM incident_events ie JOIN security_events e ON e.event_id = ie.event_id
     WHERE ie.incident_id = p_incident AND e.user_id IS NOT NULL
     GROUP BY e.user_id ORDER BY COUNT(*) DESC LIMIT 1;
    SELECT d.device_id INTO o_device FROM incident_events ie JOIN security_events e ON e.event_id = ie.event_id
      JOIN devices d ON d.device_id = e.device_id WHERE ie.incident_id = p_incident
     GROUP BY d.device_id, d.criticality ORDER BY d.criticality DESC, COUNT(*) DESC LIMIT 1;

    IF o_user IS NOT NULL THEN
        o_user_role := CASE
            WHEN v_cats && ARRAY['failed_login','new_device_access'] AND v_ext THEN 'compromised_account'
            WHEN NOT COALESCE(v_ext, FALSE) AND v_cats && ARRAY['confidential_file_access','data_transfer','privilege_escalation']
                THEN 'insider_suspect'
            ELSE 'affected_user' END;
    END IF;
    IF o_device IS NOT NULL THEN
        o_device_role := CASE
            WHEN v_cats @> ARRAY['malware_alert'] THEN 'infected_host'
            WHEN v_cats && ARRAY['port_scan','failed_login'] AND v_ext THEN 'attack_target'
            WHEN v_cats && ARRAY['confidential_file_access'] THEN 'data_source'
            ELSE 'affected_device' END;
    END IF;
END $$;

-- Recompute derived incident fields ----------------------------------------
CREATE OR REPLACE FUNCTION fn_refresh_incident(p_incident INT) RETURNS VOID
LANGUAGE plpgsql AS $$
DECLARE v_score NUMERIC := fn_incident_risk(p_incident); ent RECORD;
BEGIN
    SELECT * INTO ent FROM fn_incident_entities(p_incident);
    UPDATE incidents
       SET title = fn_incident_title(p_incident), risk_score = v_score,
           severity_level = fn_severity_label(v_score),
           user_id = ent.o_user, user_entity_role = ent.o_user_role,
           device_id = ent.o_device, device_entity_role = ent.o_device_role
     WHERE incident_id = p_incident
       AND (title, risk_score, severity_level, user_id, user_entity_role, device_id, device_entity_role)
           IS DISTINCT FROM (fn_incident_title(p_incident), v_score, fn_severity_label(v_score),
                             ent.o_user, ent.o_user_role, ent.o_device, ent.o_device_role);
END $$;

-- DFD 2.1: contextual time window around one event (same user, IP or device)
CREATE OR REPLACE FUNCTION fn_event_window(p_event BIGINT, p_window INTERVAL DEFAULT INTERVAL '30 minutes')
RETURNS TABLE(event_id BIGINT, event_timestamp TIMESTAMPTZ, event_category VARCHAR, risk_score NUMERIC,
              user_id INT, device_id INT, source_ip INET, shared_entity TEXT)
LANGUAGE sql STABLE AS $$
    SELECT e.event_id, e.event_timestamp, e.event_category, e.risk_score, e.user_id, e.device_id, e.source_ip,
           CASE WHEN e.user_id = x.user_id THEN 'user' WHEN e.source_ip = x.source_ip THEN 'source_ip' ELSE 'device' END
      FROM security_events x
      JOIN security_events e
        ON e.event_timestamp BETWEEN x.event_timestamp - p_window AND x.event_timestamp + p_window
       AND (e.user_id = x.user_id OR e.source_ip = x.source_ip OR e.device_id = x.device_id)
     WHERE x.event_id = p_event
     ORDER BY e.event_timestamp;
$$;

-- ---------------------------------------------------------------------
-- DFD 2.3 / 2.4 correlation. Candidates = events that triggered an alert
-- and are not yet linked. Greedy sessionisation on shared user / source
-- IP / device within p_window. Serialised with an advisory lock so two
-- concurrent runs can never double-link an event.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_correlate_events(p_window INTERVAL DEFAULT INTERVAL '30 minutes')
RETURNS TABLE(incidents_created INT, events_linked INT, incidents_touched INT)
LANGUAGE plpgsql AS $$
DECLARE
    r RECORD; v_inc INT; v_rule TEXT; v_seq INT;
    v_created INT := 0; v_linked INT := 0; v_touched INT[] := '{}';
BEGIN
    PERFORM pg_advisory_xact_lock(424242);
    PERFORM set_config('app.actor', 'correlation-engine', true);
    PERFORM set_config('app.analyst_id', '', true);

    FOR r IN
        SELECT e.event_id, e.user_id, e.device_id, e.source_ip, e.event_timestamp, e.blocked,
               d.device_type IN ('laptop','workstation') AS personal_device
          FROM security_events e JOIN devices d ON d.device_id = e.device_id
         WHERE EXISTS (SELECT 1 FROM system_alerts a WHERE a.event_id = e.event_id)
           AND NOT EXISTS (SELECT 1 FROM incident_events ie WHERE ie.event_id = e.event_id)
         ORDER BY e.event_timestamp, e.event_id
    LOOP
        v_inc := NULL; v_rule := NULL;
        -- a contained attacker coming back belongs to the incident that contained them,
        -- however much later it happens
        IF r.blocked THEN
            SELECT b.incident_id, 'blocked_return' INTO v_inc, v_rule
              FROM blocked_entities b JOIN incidents i ON i.incident_id = b.incident_id
             WHERE b.active AND i.status IN ('New','Investigating','Contained')
               AND ((b.entity_type = 'ip' AND r.source_ip IS NOT NULL AND b.entity_value = host(r.source_ip))
                 OR (b.entity_type = 'user' AND r.user_id IS NOT NULL AND b.entity_value = r.user_id::TEXT))
             ORDER BY b.block_id LIMIT 1;
        END IF;
        IF v_inc IS NULL THEN
        SELECT x.incident_id, x.rule INTO v_inc, v_rule FROM (
            SELECT ie.incident_id,
                   CASE WHEN e2.user_id = r.user_id THEN 'same_user_window'
                        WHEN e2.source_ip = r.source_ip THEN 'same_source_ip_window'
                        ELSE 'same_device_window' END AS rule
              FROM incident_events ie
              JOIN incidents i        ON i.incident_id = ie.incident_id
                                     AND i.status IN ('New','Investigating','Contained')
              JOIN security_events e2 ON e2.event_id = ie.event_id
             WHERE r.event_timestamp - e2.event_timestamp BETWEEN INTERVAL '0' AND p_window
               -- shared infrastructure (servers, VPN gateway, DB) is NOT a linking entity:
               -- many unrelated users touch it every minute
               AND (e2.user_id = r.user_id OR e2.source_ip = r.source_ip
                    OR (e2.device_id = r.device_id AND r.personal_device))
             ORDER BY (CASE WHEN e2.user_id = r.user_id THEN 0 WHEN e2.source_ip = r.source_ip THEN 1 ELSE 2 END),
                      e2.event_timestamp DESC
             LIMIT 1) x;
        END IF;

        IF v_inc IS NULL THEN
            INSERT INTO incidents (title, created_at, updated_at)
            VALUES ('Pending correlation', r.event_timestamp, r.event_timestamp)
            RETURNING incident_id INTO v_inc;
            v_rule := 'new_incident_seed';
            v_created := v_created + 1;
        END IF;

        SELECT COALESCE(MAX(step_sequence), 0) + 1 INTO v_seq FROM incident_events WHERE incident_id = v_inc;
        INSERT INTO incident_events (incident_id, event_id, step_sequence, correlation_rule)
        VALUES (v_inc, r.event_id, v_seq, v_rule);
        v_linked := v_linked + 1;
        IF NOT v_inc = ANY(v_touched) THEN v_touched := v_touched || v_inc; END IF;
    END LOOP;

    -- refresh every open incident, not only the touched ones: the entity
    -- compromise-history component depends on OTHER incidents too
    FOR v_inc IN SELECT incident_id FROM incidents
                  WHERE status IN ('New','Investigating','Contained') OR incident_id = ANY(v_touched) LOOP
        PERFORM fn_refresh_incident(v_inc);
    END LOOP;
    -- automated response: contain incidents that reached the policy's risk level
    FOR v_inc IN SELECT i.incident_id FROM incidents i, response_policy p
                  WHERE p.is_active AND i.incident_id = ANY(v_touched)
                    AND i.status IN ('New','Investigating','Contained')
                    AND (i.risk_score >= p.min_risk
                         OR (p.contain_on_takeover AND fn_takeover_pattern(i.incident_id))) LOOP
        PERFORM sp_auto_contain(v_inc);
    END LOOP;
    PERFORM set_config('app.actor', '', true);
    RETURN QUERY SELECT v_created, v_linked, COALESCE(array_length(v_touched,1), 0);
END $$;

-- Status state machine ------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_valid_transition(p_old TEXT, p_new TEXT) RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE AS $$
    SELECT (p_old, p_new) IN (
        ('New','Investigating'), ('New','False Positive'),
        ('Investigating','Contained'), ('Investigating','Resolved'), ('Investigating','False Positive'),
        ('Contained','Resolved'), ('Contained','Investigating'),
        ('Resolved','Closed'), ('Resolved','Investigating'));
$$;

-- ---------------------------------------------------------------------
-- Analyst procedures (transactional accountability). Each one:
--   * checks the actor's role, * locks the incident row (FOR UPDATE),
--   * binds the actor to the transaction for the audit triggers,
--   * records an INVESTIGATION_ACTION in the same transaction.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_require_staff(p_user INT) RETURNS TEXT
LANGUAGE plpgsql STABLE AS $$
DECLARE v_role TEXT;
BEGIN
    SELECT role INTO v_role FROM users WHERE user_id = p_user AND is_active;
    IF v_role IS NULL OR v_role NOT IN ('Analyst','Admin') THEN
        RAISE EXCEPTION 'User % is not an active analyst or admin', p_user USING ERRCODE = '42501';
    END IF;
    RETURN v_role;
END $$;

-- Owner = currently assigned analyst. Admins may act on any incident.
CREATE OR REPLACE FUNCTION fn_require_owner(p_incident INT, p_actor INT, p_role TEXT) RETURNS VOID
LANGUAGE plpgsql STABLE AS $$
DECLARE v_owner INT := fn_current_analyst(p_incident);
BEGIN
    IF p_role = 'Admin' THEN RETURN; END IF;
    IF v_owner IS NULL THEN
        RAISE EXCEPTION 'Incident % is unassigned; assign it to yourself first', p_incident USING ERRCODE = '42501';
    ELSIF v_owner <> p_actor THEN
        RAISE EXCEPTION 'Incident % belongs to %; only the owner or an Admin can do this', p_incident,
              (SELECT username FROM users WHERE user_id = v_owner) USING ERRCODE = '42501';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION fn_lock_incident(p_incident INT) RETURNS TEXT
LANGUAGE plpgsql AS $$
DECLARE v_status TEXT;
BEGIN
    SELECT status INTO v_status FROM incidents WHERE incident_id = p_incident FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Incident % not found', p_incident USING ERRCODE = 'P0002'; END IF;
    RETURN v_status;
END $$;

CREATE OR REPLACE FUNCTION sp_assign_incident(p_incident INT, p_assignee INT, p_actor INT) RETURNS VOID
LANGUAGE plpgsql AS $$
DECLARE v_actor_role TEXT := fn_require_staff(p_actor); v_status TEXT;
BEGIN
    PERFORM fn_require_staff(p_assignee);
    IF p_assignee <> p_actor AND v_actor_role <> 'Admin' THEN
        RAISE EXCEPTION 'Only an Admin can assign incidents to someone else' USING ERRCODE = '42501';
    END IF;
    v_status := fn_lock_incident(p_incident);
    IF v_status IN ('Closed','False Positive','Resolved') THEN
        RAISE EXCEPTION 'Incident % is % and cannot be assigned', p_incident, v_status USING ERRCODE = '23514';
    END IF;
    -- analysts may only pick up unassigned incidents; re-assignment is an Admin decision
    IF v_actor_role <> 'Admin' AND fn_current_analyst(p_incident) IS NOT NULL
       AND fn_current_analyst(p_incident) <> p_actor THEN
        RAISE EXCEPTION 'Incident % is already assigned to %; ask an Admin to re-assign it', p_incident,
              (SELECT username FROM users WHERE user_id = fn_current_analyst(p_incident)) USING ERRCODE = '42501';
    END IF;
    IF fn_current_analyst(p_incident) = p_assignee THEN
        RETURN;                                   -- already theirs: nothing to do
    END IF;
    PERFORM set_config('app.analyst_id', p_actor::TEXT, true);
    INSERT INTO investigation_actions (incident_id, analyst_id, action_type, action_notes)
    VALUES (p_incident, p_assignee, 'ASSIGN',
            'assigned by ' || (SELECT username FROM users WHERE user_id = p_actor));
    IF v_status = 'New' THEN
        UPDATE incidents SET status = 'Investigating' WHERE incident_id = p_incident;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION sp_set_incident_status(p_incident INT, p_status TEXT, p_actor INT, p_notes TEXT DEFAULT '')
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE v_role TEXT := fn_require_staff(p_actor); v_old TEXT; v_owner INT;
BEGIN
    v_old := fn_lock_incident(p_incident);
    v_owner := fn_current_analyst(p_incident);
    IF v_role <> 'Admin' AND v_owner IS DISTINCT FROM p_actor THEN
        RAISE EXCEPTION 'Only the assigned analyst (or an Admin) can change the status; assign the incident first'
            USING ERRCODE = '42501';
    END IF;
    IF NOT fn_valid_transition(v_old, p_status) THEN
        RAISE EXCEPTION 'Illegal status transition: % -> %', v_old, p_status USING ERRCODE = '23514';
    END IF;
    IF p_status IN ('Resolved','Closed','False Positive') AND length(trim(COALESCE(p_notes,''))) < 5 THEN
        RAISE EXCEPTION 'A reason (at least 5 characters) is required to mark an incident %', p_status
            USING ERRCODE = '22023';
    END IF;
    PERFORM set_config('app.analyst_id', p_actor::TEXT, true);
    UPDATE incidents SET status = p_status WHERE incident_id = p_incident;
    INSERT INTO investigation_actions (incident_id, analyst_id, action_type, action_notes)
    VALUES (p_incident, p_actor, 'STATUS_CHANGE', v_old || ' -> ' || p_status ||
            CASE WHEN COALESCE(p_notes,'') <> '' THEN ': ' || p_notes ELSE '' END);
END $$;

CREATE OR REPLACE FUNCTION sp_add_action(p_incident INT, p_actor INT, p_type TEXT, p_notes TEXT)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE v_role TEXT := fn_require_staff(p_actor);
BEGIN
    IF p_type NOT IN ('NOTE','CONTAINMENT','ESCALATION') THEN
        RAISE EXCEPTION 'Action type % must be NOTE, CONTAINMENT or ESCALATION', p_type USING ERRCODE = '22023';
    END IF;
    IF COALESCE(trim(p_notes), '') = '' THEN
        RAISE EXCEPTION 'Notes are required' USING ERRCODE = '22023';
    END IF;
    PERFORM fn_lock_incident(p_incident);
    PERFORM fn_require_owner(p_incident, p_actor, v_role);
    PERFORM set_config('app.analyst_id', p_actor::TEXT, true);
    INSERT INTO investigation_actions (incident_id, analyst_id, action_type, action_notes)
    VALUES (p_incident, p_actor, p_type, p_notes);
END $$;

-- Manually attach an event as evidence -----------------------------------------
CREATE OR REPLACE FUNCTION sp_add_evidence(p_incident INT, p_event BIGINT, p_actor INT, p_notes TEXT DEFAULT '')
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE v_status TEXT; v_seq INT; v_role TEXT := fn_require_staff(p_actor);
BEGIN
    v_status := fn_lock_incident(p_incident);
    PERFORM fn_require_owner(p_incident, p_actor, v_role);
    IF v_status IN ('Closed','False Positive') THEN
        RAISE EXCEPTION 'Incident % is % and cannot take new evidence', p_incident, v_status USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM security_events WHERE event_id = p_event) THEN
        RAISE EXCEPTION 'Event % not found', p_event USING ERRCODE = 'P0002';
    END IF;
    IF EXISTS (SELECT 1 FROM incident_events WHERE incident_id = p_incident AND event_id = p_event) THEN
        RAISE EXCEPTION 'Event % is already evidence for incident %', p_event, p_incident USING ERRCODE = '23505';
    END IF;
    PERFORM set_config('app.analyst_id', p_actor::TEXT, true);
    SELECT COALESCE(MAX(step_sequence), 0) + 1 INTO v_seq FROM incident_events WHERE incident_id = p_incident;
    INSERT INTO incident_events (incident_id, event_id, step_sequence, correlation_rule)
    VALUES (p_incident, p_event, v_seq, 'manual_analyst');
    INSERT INTO investigation_actions (incident_id, analyst_id, action_type, action_notes)
    VALUES (p_incident, p_actor, 'EVIDENCE_ADDED', 'event ' || p_event ||
            CASE WHEN COALESCE(p_notes,'') <> '' THEN ': ' || p_notes ELSE '' END);
    PERFORM fn_refresh_incident(p_incident);
END $$;

-- Materialized view refresh for non-owner roles --------------------------------
CREATE OR REPLACE FUNCTION sp_refresh_risk() RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    REFRESH MATERIALIZED VIEW mv_incident_risk;
END $$;


-- ---------------------------------------------------------------------
-- Response / containment
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_is_internal_ip(p_ip INET) RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE AS $$
    SELECT p_ip << '10.0.0.0/8' OR p_ip << '172.16.0.0/12' OR p_ip << '192.168.0.0/16' OR p_ip << '127.0.0.0/8';
$$;

-- Brute-force break-in: an outside IP failed 5+ times and then logged in.
-- Unambiguous enough to contain at once, before any risk threshold is reached.
CREATE OR REPLACE FUNCTION fn_takeover_pattern(p_incident INT) RETURNS BOOLEAN
LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM incident_events ie JOIN security_events s ON s.event_id = ie.event_id
         WHERE ie.incident_id = p_incident AND s.event_category = 'successful_login'
           AND s.source_ip IS NOT NULL AND NOT fn_is_internal_ip(s.source_ip)
           AND (SELECT COUNT(*) FROM incident_events ie2 JOIN security_events f ON f.event_id = ie2.event_id
                 WHERE ie2.incident_id = p_incident AND f.event_category = 'failed_login'
                   AND f.source_ip = s.source_ip AND f.event_timestamp <= s.event_timestamp) >= 5);
$$;

-- Automated containment of one incident. Idempotent. Never disables Analyst or
-- Admin accounts (automation must not lock out the responders); those are
-- flagged in the audit trail for a human decision instead.
CREATE OR REPLACE FUNCTION sp_auto_contain(p_incident INT) RETURNS INT
LANGUAGE plpgsql AS $$
DECLARE pol response_policy%ROWTYPE; r RECORD; n INT := 0;
        v_user INT; v_urole TEXT; v_role TEXT; v_name TEXT;
BEGIN
    SELECT * INTO pol FROM response_policy WHERE is_active LIMIT 1;
    IF NOT FOUND THEN RETURN 0; END IF;
    PERFORM set_config('app.actor', 'auto-response', true);
    IF pol.block_external_ips THEN
        FOR r IN SELECT DISTINCT host(e.source_ip) AS ip
                   FROM incident_events ie JOIN security_events e ON e.event_id = ie.event_id
                  WHERE ie.incident_id = p_incident AND e.source_ip IS NOT NULL
                    AND NOT fn_is_internal_ip(e.source_ip) LOOP
            IF NOT EXISTS (SELECT 1 FROM blocked_entities WHERE entity_type='ip' AND entity_value=r.ip AND active) THEN
                INSERT INTO blocked_entities (entity_type, entity_value, incident_id, reason)
                VALUES ('ip', r.ip, p_incident, CASE WHEN fn_takeover_pattern(p_incident)
                        THEN 'automatic: brute-force break-in in incident #' ELSE 'automatic: critical incident #' END || p_incident);
                n := n + 1;
            END IF;
        END LOOP;
    END IF;
    IF pol.disable_accounts THEN
        SELECT user_id, user_entity_role INTO v_user, v_urole FROM incidents WHERE incident_id = p_incident;
        IF v_user IS NOT NULL AND v_urole IN ('compromised_account','insider_suspect') THEN
            SELECT role, username INTO v_role, v_name FROM users WHERE user_id = v_user;
            IF v_role IN ('Analyst','Admin') THEN
                IF NOT EXISTS (SELECT 1 FROM audit_logs WHERE incident_id = p_incident AND field_changed = 'auto_response_review') THEN
                    INSERT INTO audit_logs (incident_id, actor, operation, field_changed, new_value)
                    VALUES (p_incident, 'auto-response', 'INSERT', 'auto_response_review',
                            'privileged account ' || v_name || ' NOT disabled automatically; manual review required');
                END IF;
            ELSIF NOT EXISTS (SELECT 1 FROM blocked_entities WHERE entity_type='user' AND entity_value=v_user::TEXT AND active) THEN
                INSERT INTO blocked_entities (entity_type, entity_value, incident_id, reason)
                VALUES ('user', v_user::TEXT, p_incident, 'automatic: ' || v_urole || ' in critical incident #' || p_incident);
                UPDATE users SET is_active = FALSE WHERE user_id = v_user;
                n := n + 1;
            END IF;
        END IF;
    END IF;
    RETURN n;
END $$;

-- Manual containment by the incident owner (or an Admin).
CREATE OR REPLACE FUNCTION sp_block_entity(p_incident INT, p_type TEXT, p_value TEXT, p_actor INT, p_reason TEXT)
RETURNS INT LANGUAGE plpgsql AS $$
DECLARE v_role TEXT := fn_require_staff(p_actor); v_uid INT; v_target_role TEXT; v_val TEXT; v_id INT;
BEGIN
    PERFORM fn_lock_incident(p_incident);
    PERFORM fn_require_owner(p_incident, p_actor, v_role);
    IF length(trim(COALESCE(p_reason,''))) < 5 THEN
        RAISE EXCEPTION 'A reason (at least 5 characters) is required' USING ERRCODE = '22023';
    END IF;
    IF p_type = 'ip' THEN
        BEGIN
            v_val := host(p_value::INET);
        EXCEPTION WHEN others THEN
            RAISE EXCEPTION 'Invalid IP address: %', p_value USING ERRCODE = '22023';
        END;
        IF fn_is_internal_ip(v_val::INET) AND v_role <> 'Admin' THEN
            RAISE EXCEPTION 'Only an Admin can block an internal address' USING ERRCODE = '42501';
        END IF;
    ELSIF p_type = 'user' THEN
        SELECT user_id, role INTO v_uid, v_target_role FROM users WHERE username = p_value;
        IF v_uid IS NULL THEN RAISE EXCEPTION 'Unknown user %', p_value USING ERRCODE = 'P0002'; END IF;
        IF v_uid = p_actor THEN RAISE EXCEPTION 'You cannot disable your own account' USING ERRCODE = '42501'; END IF;
        IF v_target_role IN ('Analyst','Admin') AND v_role <> 'Admin' THEN
            RAISE EXCEPTION 'Only an Admin can disable a staff account' USING ERRCODE = '42501';
        END IF;
        v_val := v_uid::TEXT;
    ELSE
        RAISE EXCEPTION 'Block type must be ip or user' USING ERRCODE = '22023';
    END IF;
    IF EXISTS (SELECT 1 FROM blocked_entities WHERE entity_type = p_type AND entity_value = v_val AND active) THEN
        RAISE EXCEPTION '% % is already blocked', p_type, p_value USING ERRCODE = '23505';
    END IF;
    PERFORM set_config('app.analyst_id', p_actor::TEXT, true);
    INSERT INTO blocked_entities (entity_type, entity_value, incident_id, reason, actor, blocked_by)
    VALUES (p_type, v_val, p_incident, p_reason, 'analyst', p_actor) RETURNING block_id INTO v_id;
    IF p_type = 'user' THEN UPDATE users SET is_active = FALSE WHERE user_id = v_uid; END IF;
    INSERT INTO investigation_actions (incident_id, analyst_id, action_type, action_notes)
    VALUES (p_incident, p_actor, 'CONTAINMENT', 'blocked ' || p_type || ' ' || p_value || ': ' || p_reason);
    RETURN v_id;
END $$;

-- Lifting a block is an Admin decision and needs a reason.
CREATE OR REPLACE FUNCTION sp_lift_block(p_block INT, p_actor INT, p_reason TEXT) RETURNS VOID
LANGUAGE plpgsql AS $$
DECLARE v_role TEXT := fn_require_staff(p_actor); b blocked_entities%ROWTYPE;
BEGIN
    IF v_role <> 'Admin' THEN RAISE EXCEPTION 'Only an Admin can lift a block' USING ERRCODE = '42501'; END IF;
    IF length(trim(COALESCE(p_reason,''))) < 5 THEN
        RAISE EXCEPTION 'A reason (at least 5 characters) is required' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO b FROM blocked_entities WHERE block_id = p_block FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Block % not found', p_block USING ERRCODE = 'P0002'; END IF;
    IF NOT b.active THEN RAISE EXCEPTION 'Block % is already lifted', p_block USING ERRCODE = '23514'; END IF;
    PERFORM set_config('app.analyst_id', p_actor::TEXT, true);
    UPDATE blocked_entities SET active = FALSE, lifted_at = clock_timestamp(), lifted_by = p_actor, lift_reason = p_reason
     WHERE block_id = p_block;
    IF b.entity_type = 'user' THEN
        UPDATE users SET is_active = TRUE WHERE user_id = b.entity_value::INT;
    END IF;
END $$;
