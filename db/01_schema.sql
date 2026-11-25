-- =====================================================================
-- Cybersecurity Incident Management & Investigation System
-- 01_schema.sql : relational mapping of the Chen ER diagram (PostgreSQL 14+)
--
-- Mapping rules: strong entity -> relation; 1:N -> FK on N side
-- (relationship attributes move with it, e.g. entity_role); M:N -> junction
-- with composite PK; weak entity -> owner PK + partial key; ISA -> sub-type
-- PK is also FK to the super-type.
-- Additions beyond the diagram are marked [EXT] and explained in docs/DESIGN.md
-- =====================================================================

DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;

-- USER ------------------------------------------------------------------
CREATE TABLE users (
    user_id     INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username    VARCHAR(50)  NOT NULL UNIQUE,
    email       VARCHAR(120) NOT NULL UNIQUE,
    role        VARCHAR(20)  NOT NULL
                CHECK (role IN ('Employee','Analyst','Admin','Executive','Service')),
    department  VARCHAR(50)  NOT NULL,
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- [EXT] login credentials for Analyst/Admin accounts (scrypt hashes)
--   token_version: bumped on password change/reset -> all old sessions die
--   must_change  : user must set a new password at next sign-in
CREATE TABLE user_credentials (
    user_id       INT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    token_version INT NOT NULL DEFAULT 1,
    must_change   BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- [EXT] every sign-in attempt (persistent lockout + security audit)
CREATE TABLE login_attempts (
    attempt_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username     VARCHAR(50) NOT NULL,
    success      BOOLEAN NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- DEVICE  (User 1 --Owns/Uses-- N Device) -------------------------------
CREATE TABLE devices (
    device_id   INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_id    INT REFERENCES users(user_id) ON DELETE SET NULL,
    hostname    VARCHAR(80) NOT NULL UNIQUE,
    ip_address  INET        NOT NULL,
    mac_address MACADDR     NOT NULL UNIQUE,
    os_version  VARCHAR(60) NOT NULL,
    device_type VARCHAR(20) NOT NULL DEFAULT 'workstation'
                CHECK (device_type IN ('workstation','server','database','firewall','laptop')),
    last_seen   TIMESTAMPTZ,                                   -- maintained by trigger
    criticality SMALLINT    NOT NULL DEFAULT 2 CHECK (criticality BETWEEN 1 AND 5)  -- [EXT]
);

-- [EXT] administrator-managed detection rules (DFD level 0: "detection rules")
CREATE TABLE detection_rules (
    rule_id        INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_name      VARCHAR(60) NOT NULL UNIQUE,
    event_category VARCHAR(30) NOT NULL UNIQUE,
    base_risk      NUMERIC(5,2) NOT NULL CHECK (base_risk BETWEEN 0 AND 100),
    min_anomaly    NUMERIC(4,3) NOT NULL DEFAULT 0.300 CHECK (min_anomaly BETWEEN 0 AND 1),
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    description    TEXT NOT NULL DEFAULT ''
);

-- SECURITY_EVENT (Device 1 --Generates-- N Security Event) --------------
CREATE TABLE security_events (
    event_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id       INT NOT NULL REFERENCES devices(device_id),
    user_id         INT REFERENCES users(user_id),             -- [EXT] acting account
    event_timestamp TIMESTAMPTZ NOT NULL,
    event_category  VARCHAR(30) NOT NULL CHECK (event_category IN (
                        'failed_login','successful_login','new_device_access',
                        'file_access','confidential_file_access','privilege_escalation',
                        'data_transfer','port_scan','malware_alert')),
    -- discriminator for the disjoint ISA, derived from the category
    event_kind      VARCHAR(10) GENERATED ALWAYS AS (CASE
                        WHEN event_category IN ('failed_login','successful_login','new_device_access') THEN 'login'
                        WHEN event_category IN ('data_transfer','port_scan','malware_alert') THEN 'network'
                        WHEN event_category IN ('file_access','confidential_file_access') THEN 'file'
                        ELSE 'privilege' END) STORED,
    source_ip       INET,
    severity        VARCHAR(10) CHECK (severity IN ('Low','Medium','High','Critical')),
    anomaly_score   NUMERIC(4,3) NOT NULL DEFAULT 0 CHECK (anomaly_score BETWEEN 0 AND 1),   -- [EXT] ML
    risk_score      NUMERIC(5,2) CHECK (risk_score BETWEEN 0 AND 100),                       -- [EXT]
    raw_log_ref     TEXT,                                       -- MongoDB ObjectId
    raw_log_sha256  CHAR(64),                                   -- [EXT] tamper-evidence for the raw document
    event_source    VARCHAR(12) NOT NULL DEFAULT 'sensor'       -- [EXT] provenance of the evidence
                    CHECK (event_source IN ('sensor','simulator','ctu13')),
    blocked         BOOLEAN NOT NULL DEFAULT FALSE,             -- [EXT] came from a contained IP / disabled account
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (event_id, event_kind)                               -- target of sub-type FKs
);

-- ISA (disjoint): each sub-type row can only reference a parent of its own kind,
-- enforced by the composite FK (event_id, event_kind).
CREATE TABLE login_events (
    event_id       BIGINT PRIMARY KEY,
    event_kind     VARCHAR(10) NOT NULL DEFAULT 'login' CHECK (event_kind = 'login'),
    auth_method    VARCHAR(20) NOT NULL DEFAULT 'password',
    login_status   VARCHAR(10) NOT NULL CHECK (login_status IN ('success','failure')),
    failure_reason VARCHAR(60),
    location_geo   CHAR(2),
    FOREIGN KEY (event_id, event_kind) REFERENCES security_events(event_id, event_kind),
    CHECK (login_status = 'failure' OR failure_reason IS NULL)
);

CREATE TABLE network_events (
    event_id         BIGINT PRIMARY KEY,
    event_kind       VARCHAR(10) NOT NULL DEFAULT 'network' CHECK (event_kind = 'network'),
    destination_ip   INET,
    destination_port INT CHECK (destination_port BETWEEN 0 AND 65535),
    protocol         VARCHAR(10) NOT NULL DEFAULT 'tcp',
    bytes_sent       BIGINT NOT NULL DEFAULT 0 CHECK (bytes_sent >= 0),
    bytes_received   BIGINT NOT NULL DEFAULT 0 CHECK (bytes_received >= 0),
    duration_s       NUMERIC(10,3) NOT NULL DEFAULT 0 CHECK (duration_s >= 0),   -- [EXT] flow feature
    packets          INT NOT NULL DEFAULT 1 CHECK (packets >= 0),                -- [EXT] flow feature
    FOREIGN KEY (event_id, event_kind) REFERENCES security_events(event_id, event_kind)
);

CREATE TABLE file_access_events (
    event_id     BIGINT PRIMARY KEY,
    event_kind   VARCHAR(10) NOT NULL DEFAULT 'file' CHECK (event_kind = 'file'),
    file_path    TEXT NOT NULL,
    action_type  VARCHAR(15) NOT NULL DEFAULT 'read'
                 CHECK (action_type IN ('read','write','delete','copy','download')),
    is_sensitive BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (event_id, event_kind) REFERENCES security_events(event_id, event_kind)
);

-- [EXT] fourth sub-type: privilege escalation has no home in the diagram's ISA
CREATE TABLE privilege_events (
    event_id   BIGINT PRIMARY KEY,
    event_kind VARCHAR(10) NOT NULL DEFAULT 'privilege' CHECK (event_kind = 'privilege'),
    old_role   VARCHAR(30) NOT NULL,
    new_role   VARCHAR(30) NOT NULL,
    method     VARCHAR(30) NOT NULL DEFAULT 'sudo',
    FOREIGN KEY (event_id, event_kind) REFERENCES security_events(event_id, event_kind)
);

-- SYSTEM_ALERT (Security Event 1 --Triggers-- N System Alert) -----------
CREATE TABLE system_alerts (
    alert_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id     BIGINT NOT NULL REFERENCES security_events(event_id),
    alert_type   VARCHAR(20) NOT NULL CHECK (alert_type IN ('ML_ANOMALY','RULE_THRESHOLD','BLOCKED_ATTEMPT')),
    rule_matched VARCHAR(60) NOT NULL,
    risk_impact  NUMERIC(5,2) NOT NULL CHECK (risk_impact BETWEEN 0 AND 100),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- INCIDENT (User/Device 1 --Involves-- N Incident, attribute entity_role)
CREATE TABLE incidents (
    incident_id        INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id            INT REFERENCES users(user_id),
    device_id          INT REFERENCES devices(device_id),
    title              VARCHAR(200) NOT NULL,
    severity_level     VARCHAR(10)  NOT NULL DEFAULT 'Low'
                       CHECK (severity_level IN ('Low','Medium','High','Critical')),
    status             VARCHAR(20)  NOT NULL DEFAULT 'New'
                       CHECK (status IN ('New','Investigating','Contained','Resolved','Closed','False Positive')),
    risk_score         NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at        TIMESTAMPTZ,
    user_entity_role   VARCHAR(30),
    device_entity_role VARCHAR(30),
    CHECK (resolved_at IS NULL OR resolved_at >= created_at),
    CHECK (user_id IS NOT NULL OR user_entity_role IS NULL),
    CHECK (device_id IS NOT NULL OR device_entity_role IS NULL)
);

-- INCIDENT_EVENT (Security Event M --Correlates Into-- N Incident) --------
CREATE TABLE incident_events (
    incident_id      INT    NOT NULL REFERENCES incidents(incident_id),
    event_id         BIGINT NOT NULL REFERENCES security_events(event_id),
    correlated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    step_sequence    INT NOT NULL CHECK (step_sequence > 0),
    correlation_rule VARCHAR(40) NOT NULL,
    PRIMARY KEY (incident_id, event_id),
    UNIQUE (incident_id, step_sequence)
);

-- INVESTIGATION_ACTION (User 1 --Performs-- N; Incident 1 --Has Timeline Of-- N)
CREATE TABLE investigation_actions (
    action_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id  INT NOT NULL REFERENCES incidents(incident_id),
    analyst_id   INT NOT NULL REFERENCES users(user_id),
    action_type  VARCHAR(20) NOT NULL CHECK (action_type IN
                 ('ASSIGN','STATUS_CHANGE','NOTE','EVIDENCE_ADDED','CONTAINMENT','ESCALATION')),
    action_notes TEXT NOT NULL DEFAULT '',
    performed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- AUDIT_LOG (weak entity, identifying relationship "Generates" with Incident)
-- PK = owner PK (incident_id) + partial key (audit_id); total participation.
CREATE TABLE audit_logs (
    incident_id   INT NOT NULL REFERENCES incidents(incident_id),
    audit_id      BIGINT GENERATED ALWAYS AS IDENTITY,
    field_changed VARCHAR(60) NOT NULL,
    old_value     TEXT,
    new_value     TEXT,
    changed_at    TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    analyst_id    INT REFERENCES users(user_id),               -- [EXT] who
    actor         VARCHAR(60) NOT NULL DEFAULT 'system',       -- [EXT] analyst/system/engine
    operation     VARCHAR(10) NOT NULL,                        -- [EXT]
    PRIMARY KEY (incident_id, audit_id)
);

-- [EXT] Response / containment (DFD level 0: "response decisions").
-- An active block marks every later event from that IP or account as blocked.
CREATE TABLE blocked_entities (
    block_id     INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    entity_type  VARCHAR(10) NOT NULL CHECK (entity_type IN ('ip','user')),
    entity_value VARCHAR(64) NOT NULL,                 -- IP text, or user_id for accounts
    incident_id  INT REFERENCES incidents(incident_id),
    reason       TEXT NOT NULL,
    actor        VARCHAR(20) NOT NULL DEFAULT 'auto-response' CHECK (actor IN ('auto-response','analyst')),
    blocked_by   INT REFERENCES users(user_id),         -- NULL when automated
    created_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    lifted_at    TIMESTAMPTZ,
    lifted_by    INT REFERENCES users(user_id),
    lift_reason  TEXT,
    CHECK (active OR (lifted_at IS NOT NULL AND lift_reason IS NOT NULL))
);
CREATE UNIQUE INDEX uq_active_block ON blocked_entities (entity_type, entity_value) WHERE active;

-- [EXT] when the database contains incidents on its own (single active policy)
CREATE TABLE response_policy (
    policy_id          INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name               VARCHAR(60) NOT NULL UNIQUE,
    min_risk           NUMERIC(5,2) NOT NULL DEFAULT 75 CHECK (min_risk BETWEEN 0 AND 100),
    block_external_ips BOOLEAN NOT NULL DEFAULT TRUE,
    disable_accounts   BOOLEAN NOT NULL DEFAULT TRUE,
    contain_on_takeover BOOLEAN NOT NULL DEFAULT TRUE,   -- brute-force break-in: contain at once, whatever the score
    is_active          BOOLEAN NOT NULL DEFAULT TRUE
);

-- [EXT] audit of user/device administration (DFD process 4.0). Kept separate
-- because AUDIT_LOG is a weak entity owned by INCIDENT.
CREATE TABLE entity_audit_log (
    entity_audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    table_name      VARCHAR(30) NOT NULL,
    row_pk          TEXT NOT NULL,
    operation       VARCHAR(10) NOT NULL,
    old_row         JSONB,
    new_row         JSONB,
    changed_by      INT REFERENCES users(user_id),
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- [EXT] RAG knowledge base (PostgreSQL full-text search)
CREATE TABLE kb_documents (
    doc_id     INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source     VARCHAR(30)  NOT NULL,
    ref_id     VARCHAR(20),
    title      VARCHAR(160) NOT NULL,
    body       TEXT NOT NULL,
    categories TEXT[] NOT NULL DEFAULT '{}',
    tsv        TSVECTOR GENERATED ALWAYS AS
               (setweight(to_tsvector('english', title),'A') ||
                setweight(to_tsvector('english', body),'B')) STORED
);

-- [EXT] fallback raw-log store, used only when MongoDB is unavailable
CREATE TABLE raw_logs_fallback (
    raw_log_ref TEXT PRIMARY KEY,
    payload     JSONB NOT NULL
);

-- INDEXES ----------------------------------------------------------------
CREATE INDEX idx_events_user_ts   ON security_events (user_id,   event_timestamp);
CREATE INDEX idx_events_device_ts ON security_events (device_id, event_timestamp);
CREATE INDEX idx_events_ip_ts     ON security_events (source_ip, event_timestamp);
CREATE INDEX idx_events_category  ON security_events (event_category);
CREATE INDEX idx_alerts_event     ON system_alerts (event_id);
CREATE INDEX idx_inc_events_event ON incident_events (event_id);
CREATE INDEX idx_incidents_status ON incidents (status, severity_level);
CREATE INDEX idx_actions_incident ON investigation_actions (incident_id, performed_at);
CREATE INDEX idx_audit_changed    ON audit_logs (changed_at);
CREATE INDEX idx_devices_owner    ON devices (owner_id);
CREATE INDEX idx_login_attempts  ON login_attempts (username, attempted_at);
CREATE INDEX idx_events_source    ON security_events (event_source);
CREATE INDEX idx_kb_tsv           ON kb_documents USING GIN (tsv);
