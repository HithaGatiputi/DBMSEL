import pytest
from app.sqlguard import validate

GOOD = [
    "SELECT * FROM v_events_enriched WHERE risk_score > 50 AND (event_category = 'port_scan' OR NOT severity = 'Low')",
    "SELECT * FROM incidents",
    "SELECT severity_level, COUNT(*) AS n FROM incidents GROUP BY 1 ORDER BY n DESC",
    "WITH x AS (SELECT user_id, COUNT(*) c FROM security_events WHERE event_category='failed_login' GROUP BY 1) SELECT u.username, x.c FROM x JOIN users u USING (user_id)",
    "SELECT date_trunc('hour', event_timestamp) h, count(*) FROM security_events WHERE event_timestamp > now() - interval '1 day' GROUP BY 1",
    "SELECT host(source_ip), ROUND(AVG(risk_score),1) FROM security_events GROUP BY 1",
    "SELECT * FROM fn_incident_risk_components(3)",
    "SELECT incident_id, EXTRACT(EPOCH FROM (last_event-first_event))/60 FROM v_incident_summary",
]
BAD = [
    "DROP TABLE users",
    "DELETE FROM incidents",
    "UPDATE incidents SET status='Closed'",
    "INSERT INTO users(username) VALUES ('x')",
    "SELECT 1; DROP TABLE users",
    "SELECT pg_sleep(10)",
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT * FROM pg_catalog.pg_user",
    "SELECT * FROM pg_shadow",
    "SELECT * FROM raw_logs_fallback",
    "SELECT * INTO newt FROM users",
    "SELECT * FROM incidents FOR UPDATE",
    "SELECT set_config('app.analyst_id','1',false)",
    "SELECT fn_correlate_events()",
    "COPY users TO '/tmp/x'",
    "",
    "SELECT * FROM information_schema.tables",
]


@pytest.mark.parametrize("q", GOOD)
def test_good(q):
    v = validate(q)
    assert v.ok, v.reason
    assert "LIMIT" in v.sql.upper()


@pytest.mark.parametrize("q", BAD)
def test_bad(q):
    assert not validate(q).ok


def test_limit_capped():
    assert "LIMIT 500" in validate("SELECT * FROM users LIMIT 100000").sql


def test_flow_features_shape_and_ports():
    from app.flowml import FEATURE_NAMES, features
    X = features([53, 443, 6667, 50000], [0.1, 2, 30, 0], [100, 5000, 0, 10], [200, 90000, 0, 0], [2, 40, 1, 1])
    assert X.shape == (4, len(FEATURE_NAMES))
    names = FEATURE_NAMES
    assert X[0, names.index("port_dns")] == 1 and X[2, names.index("port_irc")] == 1 and X[3, names.index("port_high")] == 1


def test_ctu_port_parsing():
    from app.ctu13 import _port
    assert _port("0x0303") == 771 and _port("80") == 80 and _port("") == 0 and _port(None) == 0
