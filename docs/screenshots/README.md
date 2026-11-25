# Validation & security screenshots (Component 8)

Captured from the running app by `scripts/capture_screenshots.py`.

### Login form: submitting empty fields is rejected in the browser

![Login form: submitting empty fields is rejected in the browser](01_login_required_fields.png)

### Login form: wrong password rejected by the server (scrypt hash check)

![Login form: wrong password rejected by the server (scrypt hash check)](02_login_wrong_password.png)

### Brute-force protection: 5 failures in 5 minutes lock the account

![Brute-force protection: 5 failures in 5 minutes lock the account](03_login_lockout.png)

### Admin › Add user: username, email, department and password-strength rules

![Admin › Add user: username, email, department and password-strength rules](04_add_user_validation.png)

### Admin › Register device: hostname, IPv4, MAC, OS and criticality (1–5) checks

![Admin › Register device: hostname, IPv4, MAC, OS and criticality (1–5) checks](05_device_validation.png)

### Server-side validation: the API rejects invalid data even when the web form is bypassed

![Server-side validation: the API rejects invalid data even when the web form is bypassed](06_server_side_validation.png)

### Incident workflow: marking False Positive without a written reason is refused

![Incident workflow: marking False Positive without a written reason is refused](07_reason_required.png)

### Record action: notes shorter than 3 characters are rejected

![Record action: notes shorter than 3 characters are rejected](08_action_notes_validation.png)

### Ask AI: 'drop table users' → only a harmless read-only query runs

![Ask AI: 'drop table users' → only a harmless read-only query runs](09_ask_ai_sql_injection_blocked.png)

### Evidence integrity: SHA-256 of the MongoDB raw log re-checked → verified

![Evidence integrity: SHA-256 of the MongoDB raw log re-checked → verified](10_raw_log_integrity.png)

### Security self-test: 13 attacks on the system, all blocked

![Security self-test: 13 attacks on the system, all blocked](11_security_self_test.png)

### Access control: analyst.menon cannot change, annotate or take over analyst.rao's incident

![Access control: analyst.menon cannot change, annotate or take over analyst.rao's incident](12_role_based_access.png)
