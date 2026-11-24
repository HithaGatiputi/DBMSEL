"""SQL validation layer for AI-generated queries.

Defence in depth: (1) this AST validator, (2) a dedicated PostgreSQL role
with SELECT-only grants, default_transaction_read_only and a statement
timeout, (3) an explicit READ ONLY transaction and row cap at execution.
"""
from __future__ import annotations

from dataclasses import dataclass

import sqlglot
from sqlglot import exp

from . import config, db

ALLOWED_TABLES = {
    "users", "devices", "security_events", "login_events", "network_events", "file_access_events",
    "privilege_events", "system_alerts", "incidents", "incident_events", "investigation_actions",
    "audit_logs", "entity_audit_log", "detection_rules", "kb_documents",
    "v_events_enriched", "v_incident_timeline", "v_incident_summary", "v_user_compromise",
    "v_alerts", "mv_incident_risk", "blocked_entities", "response_policy", "v_blocks",
}
ALLOWED_FUNCS = {
    "count", "sum", "avg", "min", "max", "coalesce", "nullif", "greatest", "least", "abs", "round",
    "ceil", "ceiling", "floor", "lower", "upper", "length", "substring", "concat", "trim", "date_trunc",
    "extract", "now", "current_date", "current_timestamp", "date", "to_char", "array_agg", "string_agg",
    "row_number", "rank", "dense_rank", "lag", "lead", "host", "family", "cast", "case", "if",
    "fn_severity_label", "fn_incident_risk_components", "fn_incident_risk", "make_interval",
    "fn_current_analyst", "fn_event_window", "fn_org_timezone",
    "count_distinct", "date_diff", "trycast", "timestamp_trunc", "datetrunc", "stddev", "variance", "left", "right", "position", "replace",
    "split_part", "any", "bool_or", "bool_and", "ln", "log", "sqrt", "power", "mod",
}
FORBIDDEN_NODES = (exp.Insert, exp.Update, exp.Delete, exp.Drop, exp.Create, exp.Alter, exp.Command,
                   exp.Merge, exp.Copy, exp.Set, exp.Transaction, exp.Commit, exp.Rollback, exp.Into,
                   exp.Lock, exp.Use, exp.Grant, exp.TruncateTable, exp.Pragma, exp.Describe,
                   exp.Analyze, exp.Declare, exp.Show)
MAX_LEN = 4000


@dataclass
class Verdict:
    ok: bool
    sql: str = ""
    reason: str = ""


def validate(sql: str) -> Verdict:
    sql = (sql or "").strip().rstrip(";").strip()
    if not sql:
        return Verdict(False, reason="empty query")
    if len(sql) > MAX_LEN:
        return Verdict(False, reason="query too long")
    try:
        stmts = sqlglot.parse(sql, read="postgres")
    except sqlglot.errors.ParseError as e:
        return Verdict(False, reason=f"syntax error: {str(e)[:120]}")
    stmts = [s for s in stmts if s is not None]
    if len(stmts) != 1:
        return Verdict(False, reason="exactly one statement is allowed")
    tree = stmts[0]
    if not isinstance(tree, (exp.Select, exp.Union, exp.Subquery)):
        return Verdict(False, reason="only SELECT statements are allowed")
    for node in tree.walk():
        if isinstance(node, FORBIDDEN_NODES):
            return Verdict(False, reason=f"forbidden construct: {type(node).__name__}")
    ctes = {c.alias_or_name.lower() for c in tree.find_all(exp.CTE)}
    for t in tree.find_all(exp.Table):
        name = t.name.lower()
        if t.args.get("db") or t.args.get("catalog"):
            return Verdict(False, reason="schema-qualified tables are not allowed")
        if name in ctes:
            continue
        if isinstance(t.this, exp.Anonymous) or isinstance(t.this, exp.Func):
            continue            # table-function; checked below as a function
        if name not in ALLOWED_TABLES:
            return Verdict(False, reason=f"table not permitted: {name}")
    for f in tree.find_all(exp.Func):
        if isinstance(f, (exp.Cast, exp.Case, exp.If, exp.Coalesce, exp.Binary, exp.Unary, exp.Connector)):
            continue
        name = (f.name if isinstance(f, exp.Anonymous) else f.sql_name()).lower()
        if name not in ALLOWED_FUNCS:
            return Verdict(False, reason=f"function not permitted: {name}")
    # cap result size
    lim = tree.args.get("limit")
    cap = config.MAX_QUERY_ROWS
    if lim is None:
        tree = tree.limit(cap)
    else:
        try:
            n = int(lim.expression.name)
            if n > cap:
                tree = tree.limit(cap)
        except Exception:
            tree = tree.limit(cap)
    return Verdict(True, sql=tree.sql(dialect="postgres"))


def run_readonly(sql: str) -> tuple[list[str], list[dict]]:
    """Validate then execute on the read-only role."""
    v = validate(sql)
    if not v.ok:
        raise ValueError(v.reason)
    with db.conn("ro") as c:
        with c.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")
            cur.execute("SET LOCAL statement_timeout = '5s'")
            cur.execute(v.sql)
            cols = [d.name for d in cur.description]
            rows = cur.fetchmany(config.MAX_QUERY_ROWS)
        c.rollback()
    return cols, rows
