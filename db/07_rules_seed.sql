-- =====================================================================
-- 07_rules_seed.sql : default detection rules (editable by Admins)
-- =====================================================================
INSERT INTO detection_rules (rule_name, event_category, base_risk, min_anomaly, description) VALUES
('AUTH-FAIL',     'failed_login',             15, 0.30, 'Failed authentication; alerts when ML sees a burst or unusual source'),
('AUTH-OK',       'successful_login',          5, 0.30, 'Successful login; alerts when it follows failures or comes from an unusual source'),
('AUTH-NEWDEV',   'new_device_access',        40, 0.30, 'Login from a device never seen for this account'),
('FILE-READ',     'file_access',               5, 0.50, 'Ordinary file access'),
('FILE-SENSITIVE','confidential_file_access', 45, 0.30, 'Access to confidential/restricted data'),
('PRIV-ESC',      'privilege_escalation',     50, 0.30, 'Account elevated to admin/root/SYSTEM'),
('NET-TRANSFER',  'data_transfer',            30, 0.80, 'Network flow; ML threshold 0.80 chosen on validation data (~0.1% false positives, CIC-IDS2017 + CTU-13 training scenarios)'),
('NET-SCAN',      'port_scan',                30, 0.80, 'Port / service probes; ML threshold 0.80 chosen on validation data (~0.1% false positives)'),
('EDR-MALWARE',   'malware_alert',            80, 0.30, 'Endpoint malware detection');

INSERT INTO response_policy (name, min_risk, block_external_ips, disable_accounts) VALUES
('Contain critical incidents', 75, TRUE, TRUE);
