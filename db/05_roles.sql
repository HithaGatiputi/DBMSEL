-- =====================================================================
-- 05_roles.sql : least-privilege roles
--   dbmsel_app : application (ingestion, analyst workflow, admin)
--   dbmsel_ro  : read-only role used ONLY by the AI / text-to-SQL layer
-- Passwords are random per machine (scripts/_secrets.sh -> ~/.dbmsel/secrets.env)
-- and are passed in as psql variables by scripts/setup_db.sh.
-- =====================================================================
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbmsel_app') THEN
        CREATE ROLE dbmsel_app LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbmsel_ro') THEN
        CREATE ROLE dbmsel_ro LOGIN;
    END IF;
END $$;
ALTER ROLE dbmsel_app PASSWORD :'app_pw';
ALTER ROLE dbmsel_ro  PASSWORD :'ro_pw';

GRANT USAGE ON SCHEMA public TO dbmsel_app, dbmsel_ro;

-- application role -----------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO dbmsel_app;
REVOKE UPDATE, DELETE ON security_events, login_events, network_events, file_access_events,
                         privilege_events, system_alerts, investigation_actions, audit_logs,
                         entity_audit_log FROM dbmsel_app;      -- append-only (also trigger-enforced)
REVOKE DELETE ON incidents FROM dbmsel_app;
REVOKE UPDATE, DELETE ON login_attempts FROM dbmsel_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO dbmsel_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO dbmsel_app;

-- read-only investigation role -----------------------------------------
GRANT SELECT ON ALL TABLES IN SCHEMA public TO dbmsel_ro;
REVOKE SELECT ON raw_logs_fallback, user_credentials, login_attempts FROM dbmsel_ro;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, dbmsel_ro;
GRANT EXECUTE ON FUNCTION fn_severity_label(NUMERIC), fn_org_timezone(), fn_is_internal_ip(INET), fn_incident_risk_components(INT),
                          fn_incident_risk(INT), fn_current_analyst(INT),
                          fn_event_window(BIGINT, INTERVAL) TO dbmsel_ro;
ALTER ROLE dbmsel_ro SET default_transaction_read_only = on;
ALTER ROLE dbmsel_ro SET statement_timeout = '5s';
ALTER ROLE dbmsel_ro SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE dbmsel_ro SET search_path = public;
