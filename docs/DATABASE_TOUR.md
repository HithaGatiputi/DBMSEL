# Database tour

_Generated 2026-11-24 22:37 from the live databases by `scripts/db_tour.py`. Every demo below ran inside a transaction that was **rolled back**, so nothing was changed._

## 0. Opening the databases yourself

| Command | Opens |
|---|---|
| `scripts/db.sh psql` | PostgreSQL as the owner (full access) |
| `scripts/db.sh app` | PostgreSQL as `dbmsel_app`, the role the web app uses |
| `scripts/db.sh ro` | PostgreSQL as `dbmsel_ro`, the read-only role used by Ask AI |
| `scripts/db.sh mongo` | MongoDB shell on the raw-log database |
| `scripts/db.sh sql "SELECT …"` | run one query and print the result |
| `scripts/db.sh info` | host, port, users and passwords for pgAdmin / DBeaver / MongoDB Compass |

Useful commands inside `psql`: `\dt` (tables), `\d security_events` (one table), `\dv` (views), `\df fn_*` (functions), `\dy` (event triggers), `\du` (roles), `\q` (quit).

## 1. Architecture at a glance

| Layer | Technology | Holds |
|---|---|---|
| Relational core | PostgreSQL 16 on 127.0.0.1:5433, database `dbmsel` | users, devices, events + 4 sub-types, alerts, incidents, actions, audit, rules, knowledge base |
| Raw-log store | MongoDB on 127.0.0.1:27018, database `dbmsel_raw`, collection `raw_logs` (mongodb) | original semi-structured log documents |
| Link | `security_events.raw_log_ref` ↔ MongoDB `_id`; MongoDB `sql_event_id` ↔ `event_id`; `raw_log_sha256` pins the document | |
| Security | scram-sha-256 passwords (PostgreSQL), `--auth` (MongoDB); secrets in `~/.dbmsel/secrets.env` | |

## 2. Tables and row counts

| table | rows |
|---|---|
| audit_logs | 1016 |
| blocked_entities | 6 |
| detection_rules | 9 |
| devices | 75 |
| entity_audit_log | 132 |
| file_access_events | 555 |
| incident_events | 794 |
| incidents | 26 |
| investigation_actions | 11 |
| kb_documents | 15 |
| login_attempts | 7 |
| login_events | 295 |
| network_events | 4269 |
| privilege_events | 28 |
| raw_logs_fallback | 0 |
| response_policy | 1 |
| security_events | 5147 |
| system_alerts | 794 |
| user_credentials | 5 |
| users | 44 |

## 3. Table structure (columns, keys, constraints)

The main entities from the ER diagram. Run `\d <table>` in psql for the full detail.

### `users`

| column | type | nullable | default / generated |
|---|---|---|---|
| user_id | integer | NO |  |
| username | character varying | NO |  |
| email | character varying | NO |  |
| role | character varying | NO |  |
| department | character varying | NO |  |
| is_active | boolean | NO | true |
| created_at | timestamp with time zone | NO | now() |

| constraint | kind | definition |
|---|---|---|
| users_role_check | CHECK | CHECK (((role)::text = ANY ((ARRAY['Employee'::character varying, 'Analyst'::character varying, 'Admin'::char… |
| users_pkey | PRIMARY KEY | PRIMARY KEY (user_id) |
| users_email_key | UNIQUE | UNIQUE (email) |
| users_username_key | UNIQUE | UNIQUE (username) |

### `devices`

| column | type | nullable | default / generated |
|---|---|---|---|
| device_id | integer | NO |  |
| owner_id | integer | YES |  |
| hostname | character varying | NO |  |
| ip_address | inet | NO |  |
| mac_address | macaddr | NO |  |
| os_version | character varying | NO |  |
| device_type | character varying | NO | 'workstation'::character varying |
| last_seen | timestamp with time zone | YES |  |
| criticality | smallint | NO | 2 |

| constraint | kind | definition |
|---|---|---|
| devices_criticality_check | CHECK | CHECK (((criticality >= 1) AND (criticality <= 5))) |
| devices_device_type_check | CHECK | CHECK (((device_type)::text = ANY ((ARRAY['workstation'::character varying, 'server'::character varying, 'dat… |
| devices_owner_id_fkey | FOREIGN KEY | FOREIGN KEY (owner_id) REFERENCES users(user_id) ON DELETE SET NULL |
| devices_pkey | PRIMARY KEY | PRIMARY KEY (device_id) |
| devices_hostname_key | UNIQUE | UNIQUE (hostname) |
| devices_mac_address_key | UNIQUE | UNIQUE (mac_address) |

### `security_events`

| column | type | nullable | default / generated |
|---|---|---|---|
| event_id | bigint | NO |  |
| device_id | integer | NO |  |
| user_id | integer | YES |  |
| event_timestamp | timestamp with time zone | NO |  |
| event_category | character varying | NO |  |
| event_kind | character varying | YES | GENERATED:  CASE     WHEN ((event_category)::text = ANY ((ARRAY['fail… |
| source_ip | inet | YES |  |
| severity | character varying | YES |  |
| anomaly_score | numeric | NO | 0 |
| risk_score | numeric | YES |  |
| raw_log_ref | text | YES |  |
| raw_log_sha256 | character | YES |  |
| event_source | character varying | NO | 'sensor'::character varying |
| blocked | boolean | NO | false |
| ingested_at | timestamp with time zone | NO | now() |

| constraint | kind | definition |
|---|---|---|
| security_events_anomaly_score_check | CHECK | CHECK (((anomaly_score >= (0)::numeric) AND (anomaly_score <= (1)::numeric))) |
| security_events_event_category_check | CHECK | CHECK (((event_category)::text = ANY ((ARRAY['failed_login'::character varying, 'successful_login'::character… |
| security_events_event_source_check | CHECK | CHECK (((event_source)::text = ANY ((ARRAY['sensor'::character varying, 'simulator'::character varying, 'ctu1… |
| security_events_risk_score_check | CHECK | CHECK (((risk_score >= (0)::numeric) AND (risk_score <= (100)::numeric))) |
| security_events_severity_check | CHECK | CHECK (((severity)::text = ANY ((ARRAY['Low'::character varying, 'Medium'::character varying, 'High'::charact… |
| security_events_device_id_fkey | FOREIGN KEY | FOREIGN KEY (device_id) REFERENCES devices(device_id) |
| security_events_user_id_fkey | FOREIGN KEY | FOREIGN KEY (user_id) REFERENCES users(user_id) |
| security_events_pkey | PRIMARY KEY | PRIMARY KEY (event_id) |
| trg_events_isa_complete | t | TRIGGER DEFERRABLE INITIALLY DEFERRED |
| security_events_event_id_event_kind_key | UNIQUE | UNIQUE (event_id, event_kind) |

### `login_events`

| column | type | nullable | default / generated |
|---|---|---|---|
| event_id | bigint | NO |  |
| event_kind | character varying | NO | 'login'::character varying |
| auth_method | character varying | NO | 'password'::character varying |
| login_status | character varying | NO |  |
| failure_reason | character varying | YES |  |
| location_geo | character | YES |  |

| constraint | kind | definition |
|---|---|---|
| login_events_check | CHECK | CHECK ((((login_status)::text = 'failure'::text) OR (failure_reason IS NULL))) |
| login_events_event_kind_check | CHECK | CHECK (((event_kind)::text = 'login'::text)) |
| login_events_login_status_check | CHECK | CHECK (((login_status)::text = ANY ((ARRAY['success'::character varying, 'failure'::character varying])::text… |
| login_events_event_id_event_kind_fkey | FOREIGN KEY | FOREIGN KEY (event_id, event_kind) REFERENCES security_events(event_id, event_kind) |
| login_events_pkey | PRIMARY KEY | PRIMARY KEY (event_id) |

### `network_events`

| column | type | nullable | default / generated |
|---|---|---|---|
| event_id | bigint | NO |  |
| event_kind | character varying | NO | 'network'::character varying |
| destination_ip | inet | YES |  |
| destination_port | integer | YES |  |
| protocol | character varying | NO | 'tcp'::character varying |
| bytes_sent | bigint | NO | 0 |
| bytes_received | bigint | NO | 0 |
| duration_s | numeric | NO | 0 |
| packets | integer | NO | 1 |

| constraint | kind | definition |
|---|---|---|
| network_events_bytes_received_check | CHECK | CHECK ((bytes_received >= 0)) |
| network_events_bytes_sent_check | CHECK | CHECK ((bytes_sent >= 0)) |
| network_events_destination_port_check | CHECK | CHECK (((destination_port >= 0) AND (destination_port <= 65535))) |
| network_events_duration_s_check | CHECK | CHECK ((duration_s >= (0)::numeric)) |
| network_events_event_kind_check | CHECK | CHECK (((event_kind)::text = 'network'::text)) |
| network_events_packets_check | CHECK | CHECK ((packets >= 0)) |
| network_events_event_id_event_kind_fkey | FOREIGN KEY | FOREIGN KEY (event_id, event_kind) REFERENCES security_events(event_id, event_kind) |
| network_events_pkey | PRIMARY KEY | PRIMARY KEY (event_id) |

### `file_access_events`

| column | type | nullable | default / generated |
|---|---|---|---|
| event_id | bigint | NO |  |
| event_kind | character varying | NO | 'file'::character varying |
| file_path | text | NO |  |
| action_type | character varying | NO | 'read'::character varying |
| is_sensitive | boolean | NO | false |

| constraint | kind | definition |
|---|---|---|
| file_access_events_action_type_check | CHECK | CHECK (((action_type)::text = ANY ((ARRAY['read'::character varying, 'write'::character varying, 'delete'::ch… |
| file_access_events_event_kind_check | CHECK | CHECK (((event_kind)::text = 'file'::text)) |
| file_access_events_event_id_event_kind_fkey | FOREIGN KEY | FOREIGN KEY (event_id, event_kind) REFERENCES security_events(event_id, event_kind) |
| file_access_events_pkey | PRIMARY KEY | PRIMARY KEY (event_id) |

### `privilege_events`

| column | type | nullable | default / generated |
|---|---|---|---|
| event_id | bigint | NO |  |
| event_kind | character varying | NO | 'privilege'::character varying |
| old_role | character varying | NO |  |
| new_role | character varying | NO |  |
| method | character varying | NO | 'sudo'::character varying |

| constraint | kind | definition |
|---|---|---|
| privilege_events_event_kind_check | CHECK | CHECK (((event_kind)::text = 'privilege'::text)) |
| privilege_events_event_id_event_kind_fkey | FOREIGN KEY | FOREIGN KEY (event_id, event_kind) REFERENCES security_events(event_id, event_kind) |
| privilege_events_pkey | PRIMARY KEY | PRIMARY KEY (event_id) |

### `system_alerts`

| column | type | nullable | default / generated |
|---|---|---|---|
| alert_id | bigint | NO |  |
| event_id | bigint | NO |  |
| alert_type | character varying | NO |  |
| rule_matched | character varying | NO |  |
| risk_impact | numeric | NO |  |
| created_at | timestamp with time zone | NO | now() |

| constraint | kind | definition |
|---|---|---|
| system_alerts_alert_type_check | CHECK | CHECK (((alert_type)::text = ANY ((ARRAY['ML_ANOMALY'::character varying, 'RULE_THRESHOLD'::character varying… |
| system_alerts_risk_impact_check | CHECK | CHECK (((risk_impact >= (0)::numeric) AND (risk_impact <= (100)::numeric))) |
| system_alerts_event_id_fkey | FOREIGN KEY | FOREIGN KEY (event_id) REFERENCES security_events(event_id) |
| system_alerts_pkey | PRIMARY KEY | PRIMARY KEY (alert_id) |

### `incidents`

| column | type | nullable | default / generated |
|---|---|---|---|
| incident_id | integer | NO |  |
| user_id | integer | YES |  |
| device_id | integer | YES |  |
| title | character varying | NO |  |
| severity_level | character varying | NO | 'Low'::character varying |
| status | character varying | NO | 'New'::character varying |
| risk_score | numeric | NO | 0 |
| created_at | timestamp with time zone | NO | now() |
| updated_at | timestamp with time zone | NO | now() |
| resolved_at | timestamp with time zone | YES |  |
| user_entity_role | character varying | YES |  |
| device_entity_role | character varying | YES |  |

| constraint | kind | definition |
|---|---|---|
| incidents_check | CHECK | CHECK (((resolved_at IS NULL) OR (resolved_at >= created_at))) |
| incidents_check1 | CHECK | CHECK (((user_id IS NOT NULL) OR (user_entity_role IS NULL))) |
| incidents_check2 | CHECK | CHECK (((device_id IS NOT NULL) OR (device_entity_role IS NULL))) |
| incidents_risk_score_check | CHECK | CHECK (((risk_score >= (0)::numeric) AND (risk_score <= (100)::numeric))) |
| incidents_severity_level_check | CHECK | CHECK (((severity_level)::text = ANY ((ARRAY['Low'::character varying, 'Medium'::character varying, 'High'::c… |
| incidents_status_check | CHECK | CHECK (((status)::text = ANY ((ARRAY['New'::character varying, 'Investigating'::character varying, 'Contained… |
| incidents_device_id_fkey | FOREIGN KEY | FOREIGN KEY (device_id) REFERENCES devices(device_id) |
| incidents_user_id_fkey | FOREIGN KEY | FOREIGN KEY (user_id) REFERENCES users(user_id) |
| incidents_pkey | PRIMARY KEY | PRIMARY KEY (incident_id) |

### `incident_events`

| column | type | nullable | default / generated |
|---|---|---|---|
| incident_id | integer | NO |  |
| event_id | bigint | NO |  |
| correlated_at | timestamp with time zone | NO | now() |
| step_sequence | integer | NO |  |
| correlation_rule | character varying | NO |  |

| constraint | kind | definition |
|---|---|---|
| incident_events_step_sequence_check | CHECK | CHECK ((step_sequence > 0)) |
| incident_events_event_id_fkey | FOREIGN KEY | FOREIGN KEY (event_id) REFERENCES security_events(event_id) |
| incident_events_incident_id_fkey | FOREIGN KEY | FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) |
| incident_events_pkey | PRIMARY KEY | PRIMARY KEY (incident_id, event_id) |
| incident_events_incident_id_step_sequence_key | UNIQUE | UNIQUE (incident_id, step_sequence) |

### `investigation_actions`

| column | type | nullable | default / generated |
|---|---|---|---|
| action_id | bigint | NO |  |
| incident_id | integer | NO |  |
| analyst_id | integer | NO |  |
| action_type | character varying | NO |  |
| action_notes | text | NO | ''::text |
| performed_at | timestamp with time zone | NO | clock_timestamp() |

| constraint | kind | definition |
|---|---|---|
| investigation_actions_action_type_check | CHECK | CHECK (((action_type)::text = ANY ((ARRAY['ASSIGN'::character varying, 'STATUS_CHANGE'::character varying, 'N… |
| investigation_actions_analyst_id_fkey | FOREIGN KEY | FOREIGN KEY (analyst_id) REFERENCES users(user_id) |
| investigation_actions_incident_id_fkey | FOREIGN KEY | FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) |
| investigation_actions_pkey | PRIMARY KEY | PRIMARY KEY (action_id) |

### `audit_logs`

| column | type | nullable | default / generated |
|---|---|---|---|
| incident_id | integer | NO |  |
| audit_id | bigint | NO |  |
| field_changed | character varying | NO |  |
| old_value | text | YES |  |
| new_value | text | YES |  |
| changed_at | timestamp with time zone | NO | clock_timestamp() |
| analyst_id | integer | YES |  |
| actor | character varying | NO | 'system'::character varying |
| operation | character varying | NO |  |

| constraint | kind | definition |
|---|---|---|
| audit_logs_analyst_id_fkey | FOREIGN KEY | FOREIGN KEY (analyst_id) REFERENCES users(user_id) |
| audit_logs_incident_id_fkey | FOREIGN KEY | FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) |
| audit_logs_pkey | PRIMARY KEY | PRIMARY KEY (incident_id, audit_id) |

### `detection_rules`

| column | type | nullable | default / generated |
|---|---|---|---|
| rule_id | integer | NO |  |
| rule_name | character varying | NO |  |
| event_category | character varying | NO |  |
| base_risk | numeric | NO |  |
| min_anomaly | numeric | NO | 0.300 |
| is_active | boolean | NO | true |
| description | text | NO | ''::text |

| constraint | kind | definition |
|---|---|---|
| detection_rules_base_risk_check | CHECK | CHECK (((base_risk >= (0)::numeric) AND (base_risk <= (100)::numeric))) |
| detection_rules_min_anomaly_check | CHECK | CHECK (((min_anomaly >= (0)::numeric) AND (min_anomaly <= (1)::numeric))) |
| detection_rules_pkey | PRIMARY KEY | PRIMARY KEY (rule_id) |
| detection_rules_event_category_key | UNIQUE | UNIQUE (event_category) |
| detection_rules_rule_name_key | UNIQUE | UNIQUE (rule_name) |

### `blocked_entities`

| column | type | nullable | default / generated |
|---|---|---|---|
| block_id | integer | NO |  |
| entity_type | character varying | NO |  |
| entity_value | character varying | NO |  |
| incident_id | integer | YES |  |
| reason | text | NO |  |
| actor | character varying | NO | 'auto-response'::character varying |
| blocked_by | integer | YES |  |
| created_at | timestamp with time zone | NO | clock_timestamp() |
| active | boolean | NO | true |
| lifted_at | timestamp with time zone | YES |  |
| lifted_by | integer | YES |  |
| lift_reason | text | YES |  |

| constraint | kind | definition |
|---|---|---|
| blocked_entities_actor_check | CHECK | CHECK (((actor)::text = ANY ((ARRAY['auto-response'::character varying, 'analyst'::character varying])::text[… |
| blocked_entities_check | CHECK | CHECK ((active OR ((lifted_at IS NOT NULL) AND (lift_reason IS NOT NULL)))) |
| blocked_entities_entity_type_check | CHECK | CHECK (((entity_type)::text = ANY ((ARRAY['ip'::character varying, 'user'::character varying])::text[]))) |
| blocked_entities_blocked_by_fkey | FOREIGN KEY | FOREIGN KEY (blocked_by) REFERENCES users(user_id) |
| blocked_entities_incident_id_fkey | FOREIGN KEY | FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) |
| blocked_entities_lifted_by_fkey | FOREIGN KEY | FOREIGN KEY (lifted_by) REFERENCES users(user_id) |
| blocked_entities_pkey | PRIMARY KEY | PRIMARY KEY (block_id) |

### `response_policy`

| column | type | nullable | default / generated |
|---|---|---|---|
| policy_id | integer | NO |  |
| name | character varying | NO |  |
| min_risk | numeric | NO | 75 |
| block_external_ips | boolean | NO | true |
| disable_accounts | boolean | NO | true |
| is_active | boolean | NO | true |

| constraint | kind | definition |
|---|---|---|
| response_policy_min_risk_check | CHECK | CHECK (((min_risk >= (0)::numeric) AND (min_risk <= (100)::numeric))) |
| response_policy_pkey | PRIMARY KEY | PRIMARY KEY (policy_id) |
| response_policy_name_key | UNIQUE | UNIQUE (name) |

**Indexes (B-tree, composite and GIN full-text)**

```sql
SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname='public'
             AND indexname NOT LIKE '%_pkey' ORDER BY tablename, indexname
```
| tablename | indexname | indexdef |
|---|---|---|
| audit_logs | idx_audit_changed | CREATE INDEX idx_audit_changed ON public.audit_logs USING b… |
| blocked_entities | uq_active_block | CREATE UNIQUE INDEX uq_active_block ON public.blocked_entit… |
| detection_rules | detection_rules_event_category_key | CREATE UNIQUE INDEX detection_rules_event_category_key ON p… |
| detection_rules | detection_rules_rule_name_key | CREATE UNIQUE INDEX detection_rules_rule_name_key ON public… |
| devices | devices_hostname_key | CREATE UNIQUE INDEX devices_hostname_key ON public.devices … |
| devices | devices_mac_address_key | CREATE UNIQUE INDEX devices_mac_address_key ON public.devic… |
| devices | idx_devices_owner | CREATE INDEX idx_devices_owner ON public.devices USING btre… |
| incident_events | idx_inc_events_event | CREATE INDEX idx_inc_events_event ON public.incident_events… |
| incident_events | incident_events_incident_id_step_sequence_key | CREATE UNIQUE INDEX incident_events_incident_id_step_sequen… |
| incidents | idx_incidents_status | CREATE INDEX idx_incidents_status ON public.incidents USING… |
| investigation_actions | idx_actions_incident | CREATE INDEX idx_actions_incident ON public.investigation_a… |
| kb_documents | idx_kb_tsv | CREATE INDEX idx_kb_tsv ON public.kb_documents USING gin (t… |
| login_attempts | idx_login_attempts | CREATE INDEX idx_login_attempts ON public.login_attempts US… |
| mv_incident_risk | idx_mv_incident_risk | CREATE UNIQUE INDEX idx_mv_incident_risk ON public.mv_incid… |
| response_policy | response_policy_name_key | CREATE UNIQUE INDEX response_policy_name_key ON public.resp… |
| security_events | idx_events_category | CREATE INDEX idx_events_category ON public.security_events … |
| security_events | idx_events_device_ts | CREATE INDEX idx_events_device_ts ON public.security_events… |
| security_events | idx_events_ip_ts | CREATE INDEX idx_events_ip_ts ON public.security_events USI… |
| security_events | idx_events_source | CREATE INDEX idx_events_source ON public.security_events US… |
| security_events | idx_events_user_ts | CREATE INDEX idx_events_user_ts ON public.security_events U… |
| security_events | security_events_event_id_event_kind_key | CREATE UNIQUE INDEX security_events_event_id_event_kind_key… |
| system_alerts | idx_alerts_event | CREATE INDEX idx_alerts_event ON public.system_alerts USING… |
| users | users_email_key | CREATE UNIQUE INDEX users_email_key ON public.users USING b… |
| users | users_username_key | CREATE UNIQUE INDEX users_username_key ON public.users USIN… |

## 4. Functions, procedures and triggers

**Functions and stored procedures**

```sql
SELECT p.proname AS name, pg_get_function_identity_arguments(p.oid) AS arguments,
                   pg_get_function_result(p.oid) AS returns,
                   CASE WHEN p.proname LIKE 'sp\_%' THEN 'procedure (writes)'
                        WHEN p.proname LIKE 'trg\_%' THEN 'trigger function' ELSE 'function' END AS kind
              FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname='public' ORDER BY kind, name
```
| name | arguments | returns | kind |
|---|---|---|---|
| fn_audit_actor | OUT o_analyst integer, OUT o_actor text | record | function |
| fn_correlate_events | p_window interval | TABLE(incidents_created integer, events_linked integer, inc… | function |
| fn_current_analyst | p_incident integer | integer | function |
| fn_event_risk | p_category character varying, p_anomaly numeric, p_device i… | numeric | function |
| fn_event_window | p_event bigint, p_window interval | TABLE(event_id bigint, event_timestamp timestamp with time … | function |
| fn_incident_entities | p_incident integer, OUT o_user integer, OUT o_user_role tex… | record | function |
| fn_incident_risk | p_incident integer | numeric | function |
| fn_incident_risk_components | p_incident integer | TABLE(component text, raw_value numeric, weight text, contr… | function |
| fn_incident_title | p_incident integer | text | function |
| fn_is_internal_ip | p_ip inet | boolean | function |
| fn_lock_incident | p_incident integer | text | function |
| fn_org_timezone |  | text | function |
| fn_refresh_incident | p_incident integer | void | function |
| fn_require_owner | p_incident integer, p_actor integer, p_role text | void | function |
| fn_require_staff | p_user integer | text | function |
| fn_severity_label | p_score numeric | character varying | function |
| fn_valid_transition | p_old text, p_new text | boolean | function |
| sp_add_action | p_incident integer, p_actor integer, p_type text, p_notes t… | void | procedure (writes) |
| sp_add_evidence | p_incident integer, p_event bigint, p_actor integer, p_note… | void | procedure (writes) |
| sp_assign_incident | p_incident integer, p_assignee integer, p_actor integer | void | procedure (writes) |
| sp_auto_contain | p_incident integer | integer | procedure (writes) |
| sp_block_entity | p_incident integer, p_type text, p_value text, p_actor inte… | integer | procedure (writes) |
| sp_lift_block | p_block integer, p_actor integer, p_reason text | void | procedure (writes) |
| sp_refresh_risk |  | void | procedure (writes) |
| sp_set_incident_status | p_incident integer, p_status text, p_actor integer, p_notes… | void | procedure (writes) |
| trg_append_only |  | trigger | trigger function |
| trg_audit_action |  | trigger | trigger function |
| trg_audit_block |  | trigger | trigger function |
| trg_audit_evidence |  | trigger | trigger function |
| trg_audit_incident_insert |  | trigger | trigger function |
| trg_audit_incidents |  | trigger | trigger function |
| trg_block_guard |  | trigger | trigger function |
| trg_entity_audit |  | trigger | trigger function |
| trg_event_after |  | trigger | trigger function |
| trg_incident_guard |  | trigger | trigger function |
| trg_isa_complete |  | trigger | trigger function |
| trg_score_event |  | trigger | trigger function |

**Triggers: what fires, when, on which table**

```sql
SELECT event_object_table AS "table", trigger_name, action_timing AS timing,
                   string_agg(event_manipulation, ' OR ' ORDER BY event_manipulation) AS events,
                   regexp_replace(action_statement, 'EXECUTE FUNCTION ', '') AS runs
              FROM information_schema.triggers WHERE trigger_schema='public'
             GROUP BY 1,2,3,5 ORDER BY 1,2
```
TRUNCATE triggers and the deferred ISA constraint trigger are included below:

| table | trigger_name | timing | events | runs |
|---|---|---|---|---|
| audit_logs | trg_audit_logs_no_change | BEFORE | DELETE OR UPDATE | trg_append_only() |
| blocked_entities | trg_blocks_audit | AFTER | INSERT OR UPDATE | trg_audit_block() |
| blocked_entities | trg_blocks_guard | BEFORE | DELETE OR UPDATE | trg_block_guard() |
| detection_rules | trg_rules_audit | AFTER | DELETE OR INSERT OR UPDATE | trg_entity_audit('rule_id') |
| devices | trg_devices_audit | AFTER | DELETE OR INSERT OR UPDATE | trg_entity_audit('device_id') |
| entity_audit_log | trg_entity_audit_log_no_change | BEFORE | DELETE OR UPDATE | trg_append_only() |
| file_access_events | trg_file_access_events_no_change | BEFORE | DELETE OR UPDATE | trg_append_only() |
| incident_events | trg_evidence_audit | AFTER | DELETE OR INSERT | trg_audit_evidence() |
| incidents | trg_incidents_audit | AFTER | UPDATE | trg_audit_incidents() |
| incidents | trg_incidents_audit_ins | AFTER | INSERT | trg_audit_incident_insert() |
| incidents | trg_incidents_guard | BEFORE | DELETE OR UPDATE | trg_incident_guard() |
| investigation_actions | trg_actions_audit | AFTER | INSERT | trg_audit_action() |
| investigation_actions | trg_investigation_actions_no_change | BEFORE | DELETE OR UPDATE | trg_append_only() |
| login_events | trg_login_events_no_change | BEFORE | DELETE OR UPDATE | trg_append_only() |
| network_events | trg_network_events_no_change | BEFORE | DELETE OR UPDATE | trg_append_only() |
| privilege_events | trg_privilege_events_no_change | BEFORE | DELETE OR UPDATE | trg_append_only() |
| response_policy | trg_policy_audit | AFTER | DELETE OR INSERT OR UPDATE | trg_entity_audit('policy_id') |
| security_events | trg_events_after | AFTER | INSERT | trg_event_after() |
| security_events | trg_events_isa_complete | AFTER | INSERT | trg_isa_complete() |
| security_events | trg_events_score | BEFORE | INSERT | trg_score_event() |
| security_events | trg_security_events_no_change | BEFORE | DELETE OR UPDATE | trg_append_only() |
| system_alerts | trg_system_alerts_no_change | BEFORE | DELETE OR UPDATE | trg_append_only() |
| users | trg_users_audit | AFTER | DELETE OR INSERT OR UPDATE | trg_entity_audit('user_id') |

**Statement-level / constraint triggers**

```sql
SELECT tgrelid::regclass AS "table", tgname AS trigger,
                   CASE WHEN tgconstraint <> 0 THEN 'CONSTRAINT, DEFERRABLE INITIALLY DEFERRED'
                        WHEN tgtype & 32 = 32 THEN 'BEFORE TRUNCATE' ELSE '' END AS kind
              FROM pg_trigger WHERE NOT tgisinternal AND (tgconstraint <> 0 OR tgtype & 32 = 32)
             ORDER BY 1,2
```
| table | trigger | kind |
|---|---|---|
| security_events | trg_events_isa_complete | CONSTRAINT, DEFERRABLE INITIALLY DEFERRED |
| security_events | trg_security_events_no_truncate | BEFORE TRUNCATE |
| login_events | trg_login_events_no_truncate | BEFORE TRUNCATE |
| network_events | trg_network_events_no_truncate | BEFORE TRUNCATE |
| file_access_events | trg_file_access_events_no_truncate | BEFORE TRUNCATE |
| privilege_events | trg_privilege_events_no_truncate | BEFORE TRUNCATE |
| system_alerts | trg_system_alerts_no_truncate | BEFORE TRUNCATE |
| investigation_actions | trg_investigation_actions_no_truncate | BEFORE TRUNCATE |
| audit_logs | trg_audit_logs_no_truncate | BEFORE TRUNCATE |
| entity_audit_log | trg_entity_audit_log_no_truncate | BEFORE TRUNCATE |

## 5. Views and the materialized view

**Views**

```sql
SELECT table_name AS view FROM information_schema.views WHERE table_schema='public' ORDER BY 1
```
| view |
|---|
| v_alerts |
| v_blocks |
| v_events_enriched |
| v_incident_summary |
| v_incident_timeline |
| v_user_compromise |

**Explainable risk (materialized view `mv_incident_risk`)**

```sql
SELECT m.incident_id, i.title, m.risk_score, m.breakdown FROM mv_incident_risk m JOIN incidents i USING (incident_id) ORDER BY m.risk_score DESC LIMIT 5;
```
| incident_id | title | risk_score | breakdown |
|---|---|---|---|
| 12 | Reconnaissance followed by credential attack [admin.singh] | 90.52 | {"asset_criticality": 9, "peak_event_severity": 40.0, "attack_stage_diversity": 20, "average_event_severity": 6.52, "en… |
| 7 | Reconnaissance followed by credential attack [admin.singh] | 90.35 | {"asset_criticality": 9, "peak_event_severity": 40.0, "attack_stage_diversity": 20, "average_event_severity": 6.35, "en… |
| 6 | Suspected data exfiltration [neha.singh] | 88.79 | {"asset_criticality": 15, "peak_event_severity": 37.2, "attack_stage_diversity": 15, "average_event_severity": 8.43, "e… |
| 16 | Malware activity [neha.singh] | 83.87 | {"asset_criticality": 6, "peak_event_severity": 40.0, "attack_stage_diversity": 15, "average_event_severity": 7.87, "en… |
| 15 | Account takeover with privilege escalation and data exfiltration [priya.rao] | 76.92 | {"asset_criticality": 12, "peak_event_severity": 38.0, "attack_stage_diversity": 20, "average_event_severity": 6.92, "e… |

**The same score, explained component by component (function fn_incident_risk_components(12))**

```sql
SELECT * FROM fn_incident_risk_components(12)
```
| component | raw_value | weight | contribution |
|---|---|---|---|
| peak_event_severity | 100.00 | 0.40 x max event risk | 40.00 |
| average_event_severity | 65.1600000000000000 | 0.10 x mean event risk | 6.52 |
| attack_stage_diversity | 4 | 5 per distinct stage (cap 20) | 20 |
| asset_criticality | 3 | 3 per criticality level (cap 15) | 9 |
| entity_compromise_history | 0.141 | 15 x min(1, 10 x rate) | 15.00 |

## 6. Roles and privileges (least privilege)

**Login roles and their settings**

```sql
SELECT rolname AS role, rolsuper AS superuser, rolcanlogin AS can_login,
                   array_to_string(rolconfig, ', ') AS settings
              FROM pg_roles WHERE rolname IN ('dbmsel_app','dbmsel_ro') OR rolname = current_user ORDER BY 1
```
| role | superuser | can_login | settings |
|---|---|---|---|
| dbmsel_app | False | True |  |
| dbmsel_ro | False | True | default_transaction_read_only=on, statement_timeout=5s, idl… |
| hithagatiputi | True | True |  |

**What each role may do on the evidence and audit tables**

```sql
SELECT table_name AS "table",
                   string_agg(privilege_type, ', ' ORDER BY privilege_type) FILTER (WHERE grantee='dbmsel_app') AS dbmsel_app,
                   string_agg(privilege_type, ', ' ORDER BY privilege_type) FILTER (WHERE grantee='dbmsel_ro')  AS dbmsel_ro
              FROM information_schema.role_table_grants
             WHERE table_schema='public' AND grantee IN ('dbmsel_app','dbmsel_ro')
               AND table_name IN ('security_events','system_alerts','incidents','incident_events',
                                  'investigation_actions','audit_logs','user_credentials','login_attempts','users')
             GROUP BY table_name ORDER BY 1
```
| table | dbmsel_app | dbmsel_ro |
|---|---|---|
| audit_logs | INSERT, SELECT | SELECT |
| incident_events | DELETE, INSERT, SELECT, UPDATE | SELECT |
| incidents | INSERT, SELECT, UPDATE | SELECT |
| investigation_actions | INSERT, SELECT | SELECT |
| login_attempts | INSERT, SELECT |  |
| security_events | INSERT, SELECT | SELECT |
| system_alerts | INSERT, SELECT | SELECT |
| user_credentials | DELETE, INSERT, SELECT, UPDATE |  |
| users | DELETE, INSERT, SELECT, UPDATE | SELECT |

## 7. Sample data

**users**

```sql
SELECT user_id, username, role, department, is_active FROM users ORDER BY user_id LIMIT 8
```
| user_id | username | role | department | is_active |
|---|---|---|---|---|
| 1 | analyst.rao | Analyst | Security | True |
| 2 | analyst.menon | Analyst | Security | True |
| 3 | analyst.das | Analyst | Security | True |
| 4 | admin.iyer | Admin | IT | True |
| 5 | admin.singh | Admin | IT | True |
| 6 | exec.sharma | Executive | Management | True |
| 7 | svc.vulnscan | Service | Security | True |
| 8 | svc.backup | Service | IT | True |

**devices**

```sql
SELECT device_id, hostname, host(ip_address) AS ip, device_type, criticality, owner_id, last_seen FROM devices ORDER BY criticality DESC, device_id LIMIT 8
```
| device_id | hostname | ip | device_type | criticality | owner_id | last_seen |
|---|---|---|---|---|---|---|
| 1 | db-prod-01 | 10.0.5.10 | database | 5 |  | 2026-11-21 23:31:00+05:30 |
| 2 | file-srv-01 | 10.0.5.20 | server | 4 |  | 2026-11-23 20:49:04+05:30 |
| 4 | vpn-gw-01 | 10.0.0.1 | firewall | 4 |  | 2026-11-24 22:36:33+05:30 |
| 10 | admin-iyer-lt | 10.1.0.13 | laptop | 4 | 4 | 2026-11-23 17:35:00+05:30 |
| 11 | admin-singh-lt | 10.1.0.14 | laptop | 4 | 5 | 2026-11-23 16:08:00+05:30 |
| 12 | exec-sharma-lt | 10.1.0.15 | laptop | 4 | 6 | 2026-11-23 16:34:00+05:30 |
| 3 | web-01 | 10.0.6.10 | server | 3 |  | 2026-11-24 22:36:53+05:30 |
| 6 | backup-01 | 10.0.8.8 | server | 3 |  | 2026-11-23 01:40:00+05:30 |

**detection_rules (editable by Admins)**

```sql
SELECT rule_name, event_category, base_risk, min_anomaly, is_active FROM detection_rules ORDER BY rule_id
```
| rule_name | event_category | base_risk | min_anomaly | is_active |
|---|---|---|---|---|
| AUTH-FAIL | failed_login | 15.00 | 0.300 | True |
| AUTH-OK | successful_login | 5.00 | 0.300 | True |
| AUTH-NEWDEV | new_device_access | 40.00 | 0.300 | True |
| FILE-READ | file_access | 5.00 | 0.500 | True |
| FILE-SENSITIVE | confidential_file_access | 45.00 | 0.300 | True |
| PRIV-ESC | privilege_escalation | 50.00 | 0.300 | True |
| NET-TRANSFER | data_transfer | 30.00 | 0.800 | True |
| NET-SCAN | port_scan | 30.00 | 0.800 | True |
| EDR-MALWARE | malware_alert | 80.00 | 0.300 | True |

**Events per provenance and kind**

```sql
SELECT event_source, event_kind, COUNT(*) AS events, COUNT(*) FILTER (WHERE severity IN ('High','Critical')) AS high_or_critical FROM security_events GROUP BY 1,2 ORDER BY 1,2
```
| event_source | event_kind | events | high_or_critical |
|---|---|---|---|
| ctu13 | network | 3000 | 1057 |
| simulator | file | 555 | 35 |
| simulator | login | 295 | 45 |
| simulator | network | 1269 | 76 |
| simulator | privilege | 28 | 28 |

**security_events joined to its sub-type (one of each kind)**

```sql
SELECT DISTINCT ON (e.event_kind) e.event_id, e.event_kind, e.event_category, e.severity, e.risk_score,
                   e.anomaly_score, l.login_status, n.bytes_sent, f.is_sensitive, p.new_role
              FROM security_events e
              LEFT JOIN login_events l USING (event_id) LEFT JOIN network_events n USING (event_id)
              LEFT JOIN file_access_events f USING (event_id) LEFT JOIN privilege_events p USING (event_id)
             ORDER BY e.event_kind, e.risk_score DESC
```
| event_id | event_kind | event_category | severity | risk_score | anomaly_score | login_status | bytes_sent | is_sensitive | new_role |
|---|---|---|---|---|---|---|---|---|---|
| 1631 | file | confidential_file_access | Critical | 93.00 | 1.000 |  |  | True |  |
| 1697 | login | new_device_access | Critical | 75.98 | 0.999 | success |  |  |  |
| 1219 | network | malware_alert | Critical | 100.00 | 1.000 |  | 3000 |  |  |
| 1629 | privilege | privilege_escalation | Critical | 97.10 | 0.964 |  |  |  | root |

**system_alerts (written by trigger)**

```sql
SELECT alert_id, event_id, alert_type, rule_matched, risk_impact FROM system_alerts ORDER BY risk_impact DESC LIMIT 6
```
| alert_id | event_id | alert_type | rule_matched | risk_impact |
|---|---|---|---|---|
| 65 | 1651 | ML_ANOMALY | EDR-MALWARE | 100.00 |
| 91 | 1703 | ML_ANOMALY | EDR-MALWARE | 100.00 |
| 39 | 1219 | ML_ANOMALY | EDR-MALWARE | 100.00 |
| 45 | 1629 | ML_ANOMALY | PRIV-ESC | 97.10 |
| 90 | 1702 | ML_ANOMALY | PRIV-ESC | 95.00 |
| 16 | 1194 | ML_ANOMALY | FILE-SENSITIVE | 93.00 |

**incidents (v_incident_summary)**

```sql
SELECT incident_id, title, severity_level, status, risk_score, primary_user, user_entity_role, analyst, event_count, sources FROM v_incident_summary ORDER BY risk_score DESC LIMIT 8
```
| incident_id | title | severity_level | status | risk_score | primary_user | user_entity_role | analyst | event_count | sources |
|---|---|---|---|---|---|---|---|---|---|
| 12 | Reconnaissance followed by credential attack [admin.singh] | Critical | Contained | 90.52 | admin.singh | compromised_account | analyst.rao | 17 | ["simulator"] |
| 7 | Reconnaissance followed by credential attack [admin.singh] | Critical | New | 90.35 | admin.singh | compromised_account |  | 17 | ["simulator"] |
| 6 | Suspected data exfiltration [neha.singh] | Critical | New | 88.79 | neha.singh | insider_suspect |  | 8 | ["simulator"] |
| 16 | Malware activity [neha.singh] | Critical | New | 83.87 | neha.singh | insider_suspect |  | 5 | ["simulator"] |
| 15 | Account takeover with privilege escalation and data exfiltr… | Critical | New | 76.92 | priya.rao | compromised_account |  | 23 | ["simulator"] |
| 14 | Suspected data exfiltration [meera.reddy] | Critical | New | 75.50 | meera.reddy | insider_suspect |  | 7 | ["simulator"] |
| 11 | Suspicious privilege escalation [neha.gupta] | High | New | 73.24 | neha.gupta | insider_suspect |  | 4 | ["simulator"] |
| 18 | Account takeover with privilege escalation and data exfiltr… | High | New | 72.72 | rahul.iyer | compromised_account |  | 14 | ["simulator"] |

**How correlation built incident 12: ordered steps (incident_events / v_incident_timeline)**

```sql
SELECT step_sequence, event_timestamp, event_category, username, hostname, host(source_ip) AS src, correlation_rule FROM v_incident_timeline WHERE incident_id=12 ORDER BY step_sequence
```
| step_sequence | event_timestamp | event_category | username | hostname | src | correlation_rule |
|---|---|---|---|---|---|---|
| 1 | 2026-11-21 03:12:14+05:30 | port_scan |  | web-01 | 185.18.159.138 | new_incident_seed |
| 2 | 2026-11-21 03:12:29+05:30 | port_scan |  | web-01 | 185.18.159.138 | same_source_ip_window |
| 3 | 2026-11-21 03:12:37+05:30 | port_scan |  | web-01 | 185.18.159.138 | same_source_ip_window |
| 4 | 2026-11-21 03:12:48+05:30 | port_scan |  | web-01 | 185.18.159.138 | same_source_ip_window |
| 5 | 2026-11-21 03:12:58+05:30 | port_scan |  | web-01 | 185.18.159.138 | same_source_ip_window |
| 6 | 2026-11-21 03:13:03+05:30 | port_scan |  | web-01 | 185.18.159.138 | same_source_ip_window |
| 7 | 2026-11-21 03:13:20+05:30 | port_scan |  | web-01 | 185.18.159.138 | same_source_ip_window |
| 8 | 2026-11-21 03:13:27+05:30 | port_scan |  | web-01 | 185.18.159.138 | same_source_ip_window |
| 9 | 2026-11-21 03:13:42+05:30 | failed_login | admin.singh | web-01 | 185.18.159.138 | same_source_ip_window |
| 10 | 2026-11-21 03:13:52+05:30 | failed_login | admin.singh | web-01 | 185.18.159.138 | same_user_window |
| 11 | 2026-11-21 03:13:57+05:30 | failed_login | admin.singh | web-01 | 185.18.159.138 | same_user_window |
| 12 | 2026-11-21 03:14:03+05:30 | failed_login | admin.singh | web-01 | 185.18.159.138 | same_user_window |

_… 5 more rows_

**investigation_actions**

```sql
SELECT incident_id, action_type, action_notes, analyst_id, performed_at FROM investigation_actions ORDER BY action_id LIMIT 8
```
| incident_id | action_type | action_notes | analyst_id | performed_at |
|---|---|---|---|---|
| 12 | ASSIGN | assigned by admin.iyer | 1 | 2026-11-24 22:36:28.746634+05:30 |
| 12 | CONTAINMENT | Disabled the compromised account, blocked the source IP at … | 1 | 2026-11-24 22:36:28.747703+05:30 |
| 12 | STATUS_CHANGE | Investigating -> Contained: Containment complete | 1 | 2026-11-24 22:36:28.748495+05:30 |
| 3 | ASSIGN | assigned by analyst.das | 3 | 2026-11-24 22:36:28.749020+05:30 |
| 3 | NOTE | User confirmed travel; MFA verified. | 3 | 2026-11-24 22:36:28.749492+05:30 |
| 3 | STATUS_CHANGE | Investigating -> Resolved: Benign after user confirmation | 3 | 2026-11-24 22:36:28.749968+05:30 |
| 3 | STATUS_CHANGE | Resolved -> Closed: Reviewed by admin | 4 | 2026-11-24 22:36:28.750650+05:30 |
| 26 | ASSIGN | assigned by analyst.das | 3 | 2026-11-24 22:36:28.751062+05:30 |

**audit_logs (weak entity, PK = incident_id + audit_id)**

```sql
SELECT incident_id, audit_id, field_changed, old_value, new_value, actor, analyst_id, changed_at FROM audit_logs WHERE field_changed <> 'evidence_added' ORDER BY changed_at DESC LIMIT 10
```
| incident_id | audit_id | field_changed | old_value | new_value | actor | analyst_id | changed_at |
|---|---|---|---|---|---|---|---|
| 15 | 1016 | risk_score | 77.12 | 76.92 | correlation-engine |  | 2026-11-24 22:37:13.934815+05:30 |
| 26 | 1009 | action:status_change |  | Resolved -> Closed: Reviewed by admin | analyst | 4 | 2026-11-24 22:36:28.752446+05:30 |
| 26 | 1008 | status | Resolved | Closed | analyst | 4 | 2026-11-24 22:36:28.752337+05:30 |
| 26 | 1007 | action:status_change |  | Investigating -> Resolved: Benign after user confirmation | analyst | 3 | 2026-11-24 22:36:28.751984+05:30 |
| 26 | 1006 | resolved_at |  | 2026-11-24T22:36:28.751735+05:30 | analyst | 3 | 2026-11-24 22:36:28.751913+05:30 |
| 26 | 1005 | status | Investigating | Resolved | analyst | 3 | 2026-11-24 22:36:28.751900+05:30 |
| 26 | 1004 | action:note |  | User confirmed travel; MFA verified. | analyst | 3 | 2026-11-24 22:36:28.751543+05:30 |
| 26 | 1003 | status | New | Investigating | analyst | 3 | 2026-11-24 22:36:28.751173+05:30 |
| 26 | 1002 | assigned_analyst |  | analyst.das | analyst | 3 | 2026-11-24 22:36:28.751109+05:30 |
| 3 | 1001 | action:status_change |  | Resolved -> Closed: Reviewed by admin | analyst | 4 | 2026-11-24 22:36:28.750708+05:30 |

## 8. Live demos: the database enforcing the rules

Each block runs inside a transaction, shows what happened, then rolls back.

### 8.1 Insert one event and watch the triggers work

One `INSERT` causes: BEFORE trigger scores it (`fn_event_risk` from `detection_rules` + ML score), AFTER trigger raises a `system_alert` and updates `devices.last_seen`, and the deferred constraint trigger checks the ISA sub-type row at commit.

```sql
INSERT INTO security_events (device_id, user_id, event_timestamp, event_category, source_ip, anomaly_score)
VALUES (<file-srv-01>, 10, now(), 'privilege_escalation', '10.1.0.99', 0.92) RETURNING event_id, risk_score, severity, event_kind;
INSERT INTO privilege_events (event_id, old_role, new_role, method) VALUES (<new id>, 'user', 'root', 'exploit');
```
| event_id | user_id | risk_score | severity | event_kind |
|---|---|---|---|---|
| 5149 | 10 | 93.00 | Critical | privilege |

Alert raised automatically:

| alert_type | rule_matched | risk_impact |
|---|---|---|
| ML_ANOMALY | PRIV-ESC | 93.00 |

`devices.last_seen` for file-srv-01: 2026-11-23 20:49:04+05:30 → **2026-11-24 22:37:50.472145+05:30** (then rolled back).

### 8.2 Integrity constraints

**Disjoint ISA: a network event cannot get a login sub-type row**

```sql
INSERT INTO login_events (event_id, login_status) VALUES (1, 'success');
```
Result, rejected by the database: `ForeignKeyViolation`: insert or update on table "login_events" violates foreign key constraint "login_events_event_id_event_kind_fkey"

The composite FK `(event_id, event_kind)` only matches a parent whose generated `event_kind` is 'login'.

**Total participation: an event without its sub-type row cannot be committed**

```sql
INSERT INTO security_events (device_id, event_timestamp, event_category) VALUES (2, now(), 'port_scan');
```
Result, rejected by the database: `ForeignKeyViolation`: security event 5150 (port_scan) has no network sub-type row

The deferred constraint trigger `trg_events_isa_complete` checks at COMMIT.

**CHECK constraint: unknown category**

```sql
INSERT INTO security_events (device_id, event_timestamp, event_category) VALUES (2, now(), 'coffee_break');
```
Result, rejected by the database: `CheckViolation`: new row for relation "security_events" violates check constraint "security_events_event_category_check"

**Foreign key: device must exist**

```sql
INSERT INTO security_events (device_id, event_timestamp, event_category) VALUES (999999, now(), 'port_scan');
```
Result, rejected by the database: `ForeignKeyViolation`: insert or update on table "security_events" violates foreign key constraint "security_events_device_id_fkey"

### 8.3 Analyst workflow, accountability and the audit trail

```sql
SELECT sp_assign_incident(<incident>, <analyst.rao>, <analyst.rao>);
SELECT sp_add_action(<incident>, <analyst.rao>, 'CONTAINMENT', 'Isolated host and reset credentials');
SELECT sp_set_incident_status(<incident>, 'Contained', <analyst.rao>, 'Host isolated');
```
Rows written to `investigation_actions` by the procedures:

| action_type | action_notes | analyst_id |
|---|---|---|
| ASSIGN | assigned by analyst.rao | 1 |
| CONTAINMENT | Isolated host and reset credentials | 1 |
| STATUS_CHANGE | Investigating -> Contained: Host isolated | 1 |

Rows written to `audit_logs` **by triggers** (nobody inserts them directly):

| audit_id | field_changed | old_value | new_value | actor | analyst_id |
|---|---|---|---|---|---|
| 1023 | incident_created |  | New | system |  |
| 1024 | assigned_analyst |  | analyst.rao | analyst | 1 |
| 1025 | status | New | Investigating | analyst | 1 |
| 1026 | action:containment |  | Isolated host and reset credentials | analyst | 1 |
| 1027 | status | Investigating | Contained | analyst | 1 |
| 1028 | action:status_change |  | Investigating -> Contained: Host isolated | analyst | 1 |

**Another analyst cannot take over rao's incident**

```sql
INSERT INTO incidents (title) VALUES ('tour demo');
SELECT sp_assign_incident((SELECT incident_id FROM incidents ORDER BY incident_id DESC LIMIT 1), 1, 1);
SELECT sp_assign_incident((SELECT incident_id FROM incidents ORDER BY incident_id DESC LIMIT 1), 2, 2);
```
Result, rejected by the database: `InsufficientPrivilege`: Incident 30 is already assigned to analyst.rao; ask an Admin to re-assign it

**Illegal status jump (Investigating → Closed skips Resolved; not in the state machine)**

```sql
INSERT INTO incidents (title) VALUES ('tour demo');
SELECT sp_assign_incident((SELECT incident_id FROM incidents ORDER BY incident_id DESC LIMIT 1), 1, 1);
SELECT sp_set_incident_status((SELECT incident_id FROM incidents ORDER BY incident_id DESC LIMIT 1), 'Closed', 1, 'skip it');
```
Result, rejected by the database: `CheckViolation`: Illegal status transition: Investigating -> Closed

**Closing requires a reason**

```sql
INSERT INTO incidents (title) VALUES ('tour demo');
SELECT sp_assign_incident((SELECT incident_id FROM incidents ORDER BY incident_id DESC LIMIT 1), 1, 1);
SELECT sp_set_incident_status((SELECT incident_id FROM incidents ORDER BY incident_id DESC LIMIT 1), 'False Positive', 1, '');
```
Result, rejected by the database: `InvalidParameterValue`: A reason (at least 5 characters) is required to mark an incident False Positive

### 8.4 Append-only evidence and tamper-proof audit

**Even the database owner cannot edit an audit row (trigger)**

```sql
UPDATE audit_logs SET new_value = 'nothing happened';
```
Result, rejected by the database: `InsufficientPrivilege`: audit_logs is append-only (UPDATE blocked)

**…or delete evidence**

```sql
DELETE FROM security_events WHERE event_id = (SELECT MIN(event_id) FROM security_events);
```
Result, rejected by the database: `InsufficientPrivilege`: security_events is append-only (DELETE blocked)

**…or wipe the audit table**

```sql
TRUNCATE audit_logs;
```
Result, rejected by the database: `InsufficientPrivilege`: audit_logs is append-only (TRUNCATE blocked)

**Incidents are never deleted (close them instead)**

```sql
DELETE FROM incidents WHERE incident_id = 1;
```
Result, rejected by the database: `InsufficientPrivilege`: Incidents cannot be deleted; close them or mark False Positive

**The application role has no UPDATE privilege on the audit table at all**

```sql
UPDATE audit_logs SET actor = 'x';
```
Result, rejected by the database: `InsufficientPrivilege`: permission denied for table audit_logs

### 8.5 The read-only role used by Ask AI

**dbmsel_ro cannot write**

```sql
DELETE FROM users;
```
Result, rejected by the database: `ReadOnlySqlTransaction`: cannot execute DELETE in a read-only transaction

**dbmsel_ro cannot read password hashes**

```sql
SELECT * FROM user_credentials;
```
Result, rejected by the database: `InsufficientPrivilege`: permission denied for table user_credentials

**And the SQL validator in front of it (app/sqlguard.py)**

| question SQL | verdict | detail |
|---|---|---|
| SELECT username, COUNT(*) FROM v_events_enriched GROUP BY 1 | allowed | SELECT username, COUNT(*) FROM v_events_enriched GROUP BY 1 LIMIT 500 |
| DROP TABLE users | blocked | only SELECT statements are allowed |
| SELECT pg_sleep(10) | blocked | function not permitted: pg_sleep |
| SELECT * FROM pg_catalog.pg_user | blocked | schema-qualified tables are not allowed |
| SELECT 1; DELETE FROM incidents | blocked | exactly one statement is allowed |

## 9. MongoDB: the raw-log store

Collection `dbmsel_raw.raw_logs`: **5147** documents.

Indexes:

| name | keys |
|---|---|
| _id_ | [('_id', 1)] |
| fulltext | [('_fts', 'text'), ('_ftsx', 1)] |
| sql_event_id_1 | [('sql_event_id', 1)] |

**SQL → NoSQL: the event row points at its document**

| event_id | event_category | event_source | raw_log_ref | raw_log_sha256 |
|---|---|---|---|---|
| 1219 | malware_alert | simulator | 6b05c41220165d6ad5cf0bc6 | 5af56e8740133fad75952982f2dc3db87424a3db77c7dbf10f8a81d021d45808 |

```js
db.raw_logs.findOne({_id: ObjectId("6b05c41220165d6ad5cf0bc6")})
```
```json
{
  "_id": "6b05c41220165d6ad5cf0bc6",
  "event_category": "malware_alert",
  "@timestamp": "2026-11-19T22:28:24+00:00",
  "message": "AV: Linux/Mirai.B detected in /tmp/.x",
  "stack_trace": [
    "at dropper.run(dropper.c:88)",
    "at sh.exec(sh.c:12)",
    "at sshd.session(sshd.c:410)"
  ],
  "sha256": "ad0991a5c0c602d451b374c5f99e5722f0272567d277b393613c777c3c2f48fa",
  "ml": {
    "behaviour_score": 1.0,
    "flow_score": 0.81
  },
  "user_id": 5,
  "device_id": 3,
  "source_ip": "45.145.173.138",
  "anomaly_score": 1.0,
  "event_source": "simulator",
  "sql_event_id": 1219
}
```

**NoSQL → SQL:** the document's `sql_event_id` = 1219 = the row's `event_id`.

**Integrity:** SHA-256 recomputed now = `5af56e8740133fad75952982f2dc3db87424a3db77c7dbf10f8a81d021d45808`; stored in PostgreSQL at ingest = `5af56e8740133fad75952982f2dc3db87424a3db77c7dbf10f8a81d021d45808` → **verified**.

**Full-text search (wildcard text index)**

```js
db.raw_logs.find({$text: {$search: "polkit"}})
```
| _id | sql_event_id | message |
|---|---|---|
| 6b05c41220165d6ad5cf0f5e | 2139 | rahul.iyer gained uid=0 via polkit |
| 6b05c41220165d6ad5cf0da9 | 1702 | priya.rao gained uid=0 via polkit |

**Aggregation: documents per provenance**

```js
db.raw_logs.aggregate([{$group: {_id: "$event_source", documents: {$sum: 1}}}])
```
| event_source | documents |
|---|---|
| ctu13 | 3000 |
| simulator | 2147 |

