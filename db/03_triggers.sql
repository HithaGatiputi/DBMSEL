-- =====================================================================
-- 03_triggers.sql : scoring, alerting, state machine, immutable evidence
--                   and tamper-proof auditing (all inside the database)
-- =====================================================================

-- ---- Security events: BEFORE INSERT = owner lookup + scoring -----------
CREATE OR REPLACE FUNCTION trg_score_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.user_id IS NULL THEN          -- DFD 1.0 "device / owner lookup"
        SELECT owner_id INTO NEW.user_id FROM devices WHERE device_id = NEW.device_id;
    END IF;
    IF NEW.risk_score IS NULL THEN
        NEW.risk_score := fn_event_risk(NEW.event_category, NEW.anomaly_score,
                                        NEW.device_id, NEW.event_timestamp);
    END IF;
    NEW.severity := fn_severity_label(NEW.risk_score);
    -- containment: anything from a blocked IP or a disabled account is flagged
    NEW.blocked := EXISTS (
        SELECT 1 FROM blocked_entities b
         WHERE b.active AND ((b.entity_type = 'ip' AND NEW.source_ip IS NOT NULL AND b.entity_value = host(NEW.source_ip))
                          OR (b.entity_type = 'user' AND NEW.user_id IS NOT NULL AND b.entity_value = NEW.user_id::TEXT)));
    RETURN NEW;
END $$;
CREATE TRIGGER trg_events_score BEFORE INSERT ON security_events
    FOR EACH ROW EXECUTE FUNCTION trg_score_event();

-- ---- AFTER INSERT: device.last_seen + SYSTEM_ALERT generation ----------
-- An alert fires when the active rule for the category is met:
--   ML flag   : risk >= 25 and anomaly >= rule.min_anomaly   -> ML_ANOMALY
--   Rule only : risk >= 90                                    -> RULE_THRESHOLD
CREATE OR REPLACE FUNCTION trg_event_after() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r detection_rules%ROWTYPE;
BEGIN
    UPDATE devices SET last_seen = NEW.event_timestamp
     WHERE device_id = NEW.device_id AND (last_seen IS NULL OR last_seen < NEW.event_timestamp);

    IF NEW.blocked THEN      -- a contained attacker trying again is always worth an alert
        INSERT INTO system_alerts (event_id, alert_type, rule_matched, risk_impact, created_at)
        VALUES (NEW.event_id, 'BLOCKED_ATTEMPT', 'RESPONSE-BLOCK', NEW.risk_score, NEW.event_timestamp);
        RETURN NULL;
    END IF;
    SELECT * INTO r FROM detection_rules WHERE event_category = NEW.event_category AND is_active;
    IF FOUND THEN
        IF NEW.risk_score >= 25 AND NEW.anomaly_score >= r.min_anomaly THEN
            INSERT INTO system_alerts (event_id, alert_type, rule_matched, risk_impact, created_at)
            VALUES (NEW.event_id, 'ML_ANOMALY', r.rule_name, NEW.risk_score, NEW.event_timestamp);
        ELSIF NEW.risk_score >= 90 THEN
            INSERT INTO system_alerts (event_id, alert_type, rule_matched, risk_impact, created_at)
            VALUES (NEW.event_id, 'RULE_THRESHOLD', r.rule_name, NEW.risk_score, NEW.event_timestamp);
        END IF;
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER trg_events_after AFTER INSERT ON security_events
    FOR EACH ROW EXECUTE FUNCTION trg_event_after();

-- ---- Append-only tables (evidence, actions, alerts, audit) --------------
CREATE OR REPLACE FUNCTION trg_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% is append-only (% blocked)', TG_TABLE_NAME, TG_OP USING ERRCODE = '42501';
END $$;

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['security_events','login_events','network_events','file_access_events',
                             'privilege_events','system_alerts','investigation_actions','audit_logs',
                             'entity_audit_log'] LOOP
        EXECUTE format('CREATE TRIGGER trg_%1$s_no_change BEFORE UPDATE OR DELETE ON %1$I
                        FOR EACH ROW EXECUTE FUNCTION trg_append_only()', t);
        EXECUTE format('CREATE TRIGGER trg_%1$s_no_truncate BEFORE TRUNCATE ON %1$I
                        FOR EACH STATEMENT EXECUTE FUNCTION trg_append_only()', t);
    END LOOP;
END $$;

-- ---- Incidents: state machine, updated_at, no deletes -------------------
CREATE OR REPLACE FUNCTION trg_incident_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Incidents cannot be deleted; close them or mark False Positive'
            USING ERRCODE = '42501';
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        IF NOT fn_valid_transition(OLD.status, NEW.status) THEN
            RAISE EXCEPTION 'Illegal status transition: % -> %', OLD.status, NEW.status USING ERRCODE = '23514';
        END IF;
        IF NEW.status IN ('Resolved','Closed','False Positive') THEN
            NEW.resolved_at := COALESCE(OLD.resolved_at, GREATEST(now(), NEW.created_at));
        ELSE
            NEW.resolved_at := NULL;
        END IF;
    END IF;
    NEW.updated_at := GREATEST(now(), NEW.created_at);
    RETURN NEW;
END $$;
CREATE TRIGGER trg_incidents_guard BEFORE UPDATE OR DELETE ON incidents
    FOR EACH ROW EXECUTE FUNCTION trg_incident_guard();

-- ---- AUDIT_LOG: one row per changed incident column ----------------------
CREATE OR REPLACE FUNCTION fn_audit_actor(OUT o_analyst INT, OUT o_actor TEXT) LANGUAGE plpgsql STABLE AS $$
BEGIN
    o_analyst := NULLIF(current_setting('app.analyst_id', true), '')::INT;
    o_actor := COALESCE(NULLIF(current_setting('app.actor', true), ''),
                        CASE WHEN o_analyst IS NOT NULL THEN 'analyst' ELSE 'system' END);
END $$;

CREATE OR REPLACE FUNCTION trg_audit_incidents() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a RECORD; v_old JSONB := to_jsonb(OLD); v_new JSONB := to_jsonb(NEW); k TEXT;
BEGIN
    SELECT * INTO a FROM fn_audit_actor();
    FOR k IN SELECT jsonb_object_keys(v_new) LOOP
        IF k NOT IN ('created_at','updated_at') AND v_old->k IS DISTINCT FROM v_new->k THEN
            INSERT INTO audit_logs (incident_id, analyst_id, actor, operation, field_changed, old_value, new_value)
            VALUES (NEW.incident_id, a.o_analyst, a.o_actor, 'UPDATE', k, v_old->>k, v_new->>k);
        END IF;
    END LOOP;
    RETURN NULL;
END $$;
CREATE TRIGGER trg_incidents_audit AFTER UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION trg_audit_incidents();

CREATE OR REPLACE FUNCTION trg_audit_incident_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a RECORD;
BEGIN
    SELECT * INTO a FROM fn_audit_actor();
    INSERT INTO audit_logs (incident_id, analyst_id, actor, operation, field_changed, new_value)
    VALUES (NEW.incident_id, a.o_analyst, a.o_actor, 'INSERT', 'incident_created', NEW.status);
    RETURN NULL;
END $$;
CREATE TRIGGER trg_incidents_audit_ins AFTER INSERT ON incidents
    FOR EACH ROW EXECUTE FUNCTION trg_audit_incident_insert();

-- evidence linked/unlinked
CREATE OR REPLACE FUNCTION trg_audit_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a RECORD;
BEGIN
    SELECT * INTO a FROM fn_audit_actor();
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_logs (incident_id, analyst_id, actor, operation, field_changed, new_value)
        VALUES (NEW.incident_id, a.o_analyst, a.o_actor, 'INSERT', 'evidence_added',
                'event ' || NEW.event_id || ' (' || NEW.correlation_rule || ')');
    ELSE
        INSERT INTO audit_logs (incident_id, analyst_id, actor, operation, field_changed, old_value)
        VALUES (OLD.incident_id, a.o_analyst, a.o_actor, 'DELETE', 'evidence_removed', 'event ' || OLD.event_id);
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER trg_evidence_audit AFTER INSERT OR DELETE ON incident_events
    FOR EACH ROW EXECUTE FUNCTION trg_audit_evidence();

-- analyst actions (incl. assignments) are mirrored into the audit trail
CREATE OR REPLACE FUNCTION trg_audit_action() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a RECORD;
BEGIN
    SELECT * INTO a FROM fn_audit_actor();
    INSERT INTO audit_logs (incident_id, analyst_id, actor, operation, field_changed, new_value)
    VALUES (NEW.incident_id, COALESCE(a.o_analyst, NEW.analyst_id), 'analyst', 'INSERT',
            CASE WHEN NEW.action_type = 'ASSIGN' THEN 'assigned_analyst' ELSE 'action:' || lower(NEW.action_type) END,
            CASE WHEN NEW.action_type = 'ASSIGN' THEN (SELECT username FROM users WHERE user_id = NEW.analyst_id)
                 ELSE NEW.action_notes END);
    RETURN NULL;
END $$;
CREATE TRIGGER trg_actions_audit AFTER INSERT ON investigation_actions
    FOR EACH ROW EXECUTE FUNCTION trg_audit_action();

-- ---- Entity administration audit (DFD 4.0) --------------------------------
CREATE OR REPLACE FUNCTION trg_entity_audit() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a RECORD; v_old JSONB; v_new JSONB; pk TEXT;
BEGIN
    SELECT * INTO a FROM fn_audit_actor();
    v_old := CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END;
    v_new := CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END;
    -- ignore pure telemetry bookkeeping (last_seen) on devices
    IF TG_OP = 'UPDATE' AND (v_old - 'last_seen') = (v_new - 'last_seen') THEN
        RETURN NULL;
    END IF;
    pk := COALESCE(v_new, v_old) ->> (TG_ARGV[0]);
    INSERT INTO entity_audit_log (table_name, row_pk, operation, old_row, new_row, changed_by)
    VALUES (TG_TABLE_NAME, pk, TG_OP, v_old, v_new, a.o_analyst);
    RETURN NULL;
END $$;
CREATE TRIGGER trg_users_audit AFTER INSERT OR UPDATE OR DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION trg_entity_audit('user_id');
CREATE TRIGGER trg_devices_audit AFTER INSERT OR UPDATE OR DELETE ON devices
    FOR EACH ROW EXECUTE FUNCTION trg_entity_audit('device_id');
CREATE TRIGGER trg_rules_audit AFTER INSERT OR UPDATE OR DELETE ON detection_rules
    FOR EACH ROW EXECUTE FUNCTION trg_entity_audit('rule_id');
CREATE TRIGGER trg_policy_audit AFTER INSERT OR UPDATE OR DELETE ON response_policy
    FOR EACH ROW EXECUTE FUNCTION trg_entity_audit('policy_id');

-- ---- Containment decisions go into the incident's audit trail ------------
CREATE OR REPLACE FUNCTION trg_audit_block() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a RECORD; v_label TEXT;
BEGIN
    IF NEW.incident_id IS NULL THEN RETURN NULL; END IF;
    SELECT * INTO a FROM fn_audit_actor();
    v_label := NEW.entity_type || ' ' || CASE WHEN NEW.entity_type = 'user'
               THEN COALESCE((SELECT username FROM users WHERE user_id = NEW.entity_value::INT), NEW.entity_value)
               ELSE NEW.entity_value END;
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_logs (incident_id, analyst_id, actor, operation, field_changed, new_value)
        VALUES (NEW.incident_id, a.o_analyst, NEW.actor, 'INSERT', 'containment', 'blocked ' || v_label || ': ' || NEW.reason);
    ELSIF OLD.active AND NOT NEW.active THEN
        INSERT INTO audit_logs (incident_id, analyst_id, actor, operation, field_changed, old_value, new_value)
        VALUES (NEW.incident_id, NEW.lifted_by, 'analyst', 'UPDATE', 'containment', 'blocked ' || v_label,
                'lifted: ' || NEW.lift_reason);
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER trg_blocks_audit AFTER INSERT OR UPDATE ON blocked_entities
    FOR EACH ROW EXECUTE FUNCTION trg_audit_block();

-- a lifted block is history: only active -> lifted is allowed, never back or deleted
CREATE OR REPLACE FUNCTION trg_block_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Blocks are never deleted; lift them instead' USING ERRCODE = '42501';
    END IF;
    IF NOT OLD.active OR (NEW.entity_type, NEW.entity_value, NEW.incident_id, NEW.reason, NEW.created_at)
                         IS DISTINCT FROM (OLD.entity_type, OLD.entity_value, OLD.incident_id, OLD.reason, OLD.created_at) THEN
        RAISE EXCEPTION 'A block can only be lifted once, and its original details cannot change' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER trg_blocks_guard BEFORE UPDATE OR DELETE ON blocked_entities
    FOR EACH ROW EXECUTE FUNCTION trg_block_guard();

-- ---- ISA total participation: every security event must have exactly the
-- sub-type row its event_kind demands, checked at COMMIT (the parent row is
-- inserted first, the sub-type row a moment later in the same transaction).
CREATE OR REPLACE FUNCTION trg_isa_complete() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ok BOOLEAN;
BEGIN
    ok := CASE NEW.event_kind
        WHEN 'login'     THEN EXISTS (SELECT 1 FROM login_events       WHERE event_id = NEW.event_id)
        WHEN 'network'   THEN EXISTS (SELECT 1 FROM network_events     WHERE event_id = NEW.event_id)
        WHEN 'file'      THEN EXISTS (SELECT 1 FROM file_access_events WHERE event_id = NEW.event_id)
        WHEN 'privilege' THEN EXISTS (SELECT 1 FROM privilege_events   WHERE event_id = NEW.event_id)
    END;
    IF NOT ok THEN
        RAISE EXCEPTION 'security event % (%) has no % sub-type row', NEW.event_id, NEW.event_category, NEW.event_kind
            USING ERRCODE = '23503';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER trg_events_isa_complete
    AFTER INSERT ON security_events
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION trg_isa_complete();
