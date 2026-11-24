"""Ingestion: features -> ML anomaly score -> raw log to NoSQL -> normalized
rows into PostgreSQL (parent + 1:1 sub-type tables) in one transaction."""
from __future__ import annotations

import json
from datetime import timedelta

from . import db, ml
from .features import FeatureBuilder
from .rawstore import store

SUB_SQL = {
    "login": ("INSERT INTO login_events (event_id, auth_method, login_status, failure_reason, location_geo) "
              "VALUES (%s,%s,%s,%s,%s)",
              lambda i, s: (i, s.get("auth_method", "password"), s["login_status"],
                            s.get("failure_reason") if s["login_status"] == "failure" else None, s.get("location_geo"))),
    "network": ("INSERT INTO network_events (event_id, destination_ip, destination_port, protocol, bytes_sent, "
                "bytes_received, duration_s, packets) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                lambda i, s: (i, s.get("destination_ip"), s.get("destination_port"), s.get("protocol", "tcp"),
                              s.get("bytes_sent", 0), s.get("bytes_received", 0),
                              round(float(s.get("duration_s", 0) or 0), 3), int(s.get("packets", 1) or 1))),
    "file": ("INSERT INTO file_access_events (event_id, file_path, action_type, is_sensitive) VALUES (%s,%s,%s,%s)",
             lambda i, s: (i, s["file_path"], s.get("action_type", "read"), bool(s.get("is_sensitive")))),
    "privilege": ("INSERT INTO privilege_events (event_id, old_role, new_role, method) VALUES (%s,%s,%s,%s)",
                  lambda i, s: (i, s["old_role"], s["new_role"], s.get("method", "sudo"))),
}
KIND = {"failed_login": "login", "successful_login": "login", "new_device_access": "login",
        "file_access": "file", "confidential_file_access": "file", "privilege_escalation": "privilege",
        "data_transfer": "network", "port_scan": "network", "malware_alert": "network"}


def _history(cur, first_ts):
    """Recent DB events so sliding-window features are right for live ingestion."""
    cur.execute("""SELECT e.event_timestamp AS ts, e.event_category AS category, e.user_id,
                          host(e.source_ip) AS source_ip, n.destination_port
                     FROM security_events e LEFT JOIN network_events n USING (event_id)
                    WHERE e.event_timestamp BETWEEN %s AND %s ORDER BY e.event_timestamp""",
                (first_ts - timedelta(minutes=15), first_ts))
    return [{"ts": r["ts"], "category": r["category"], "user_id": r["user_id"],
             "source_ip": r["source_ip"], "sub": {"destination_port": r["destination_port"]}} for r in cur.fetchall()]


def doc_sha256(doc: dict) -> str:
    """Canonical SHA-256 of a raw log document. Fields added by the store
    itself (_id, sql_event_id back-link) are excluded."""
    import hashlib
    import json as _json
    body = {k: v for k, v in doc.items() if k not in ("_id", "sql_event_id")}
    return hashlib.sha256(_json.dumps(body, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


def fill_flow_defaults(sub: dict) -> dict:
    """Synthetic network events may lack duration/packets; estimate them."""
    tot = (sub.get("bytes_sent") or 0) + (sub.get("bytes_received") or 0)
    sub.setdefault("packets", max(1, int(tot // 900) + 1))
    sub.setdefault("duration_s", round(min(120.0, 0.05 + tot / 2_000_000), 3))
    return sub


def flow_scores(events: list[dict]):
    """Flow-model score for network events, NaN for others / when no model."""
    import numpy as np
    from . import flowml
    out = np.full(len(events), np.nan)
    det = flowml.load()
    idx = [i for i, e in enumerate(events) if KIND[e["category"]] == "network"]
    if det is None or not idx:
        return out
    subs = [fill_flow_defaults(events[i]["sub"]) for i in idx]
    X = flowml.features([s.get("destination_port") or 0 for s in subs], [s["duration_s"] for s in subs],
                        [s.get("bytes_sent") or 0 for s in subs], [s.get("bytes_received") or 0 for s in subs],
                        [s["packets"] for s in subs])
    out[idx] = det.score(X)
    return out


def ingest_events(events: list[dict], use_history: bool = False) -> list[int]:
    """Returns the new event_ids (same order as the time-sorted input)."""
    if not events:
        return []
    events = sorted(events, key=lambda e: e["ts"])
    fb = FeatureBuilder()
    if use_history:
        with db.conn() as c, c.cursor() as cur:
            for h in _history(cur, events[0]["ts"]):
                fb.observe(h)
    X = [fb.vector(e) for e in events]
    import numpy as np
    behaviour = ml.load().score(np.array(X))
    flow = flow_scores(events)
    # Fusion rule:
    #  * non-network events          -> behaviour model (user/session sequences)
    #  * network events with a user  -> max(behaviour, flow)
    #  * network events with no user -> flow model only (trained on real CIC-IDS2017
    #    traffic); the behaviour model has no session context to judge them and is
    #    out of distribution there (verified on CTU-13: it scored everything ~0.5)
    has_user = np.array([e.get("user_id") is not None for e in events])
    scores = np.where(np.isnan(flow), behaviour,
                      np.where(has_user, np.maximum(behaviour, np.nan_to_num(flow)), np.nan_to_num(flow)))
    for e, b, f in zip(events, behaviour, flow):
        e["raw"]["ml"] = {"behaviour_score": float(b), "flow_score": None if np.isnan(f) else float(f)}

    rs = store()
    docs = [{**e["raw"], "user_id": e["user_id"], "device_id": e["device_id"], "source_ip": e["source_ip"],
             "anomaly_score": float(s), "event_source": e.get("event_source", "sensor")}
            for e, s in zip(events, scores)]
    hashes = [doc_sha256(d) for d in docs]          # computed BEFORE the document leaves our hands
    refs = rs.put_many(docs)
    ids: list[int] = []
    with db.conn() as c, c.cursor() as cur:
        cur.executemany(
            "INSERT INTO security_events (device_id,user_id,event_timestamp,event_category,source_ip,"
            "anomaly_score,raw_log_ref,raw_log_sha256,event_source) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            "RETURNING event_id",
            [(e["device_id"], e["user_id"], e["ts"], e["category"], e["source_ip"], float(s), r, h,
              e.get("event_source", "sensor"))
             for e, s, r, h in zip(events, scores, refs, hashes)], returning=True)
        while True:
            ids.append(cur.fetchone()["event_id"])
            if not cur.nextset():
                break
        by_kind: dict[str, list] = {}
        for i, e in zip(ids, events):
            k = KIND[e["category"]]
            by_kind.setdefault(k, []).append(SUB_SQL[k][1](i, e["sub"]))
        for k, rows in by_kind.items():
            cur.executemany(SUB_SQL[k][0], rows)
        c.commit()
    rs.link(refs, ids)
    return ids


def seed_org(org: dict) -> None:
    """Insert the generated org with explicit ids (into an empty, freshly reset DB)
    and give every Analyst/Admin a login with the demo password."""
    from .auth import DEFAULT_PASSWORD, hash_password
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT set_config('app.actor', 'seed', true)")
        cur.executemany(
            "INSERT INTO users (user_id,username,email,role,department) OVERRIDING SYSTEM VALUE VALUES (%s,%s,%s,%s,%s)",
            [(u["user_id"], u["username"], u["email"], u["role"], u["department"]) for u in org["users"]])
        cur.executemany(
            "INSERT INTO devices (device_id,owner_id,hostname,ip_address,mac_address,os_version,device_type,criticality) "
            "OVERRIDING SYSTEM VALUE VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            [(d["device_id"], d["owner_id"], d["hostname"], d["ip_address"], d["mac_address"],
              d["os_version"], d["device_type"], d["criticality"]) for d in org["devices"]])
        cur.execute("SELECT setval(pg_get_serial_sequence('users','user_id'), (SELECT MAX(user_id) FROM users))")
        cur.execute("SELECT setval(pg_get_serial_sequence('devices','device_id'), (SELECT MAX(device_id) FROM devices))")
        h = hash_password(DEFAULT_PASSWORD)
        import os
        force = os.environ.get("FORCE_PASSWORD_CHANGE") == "1"
        cur.executemany("INSERT INTO user_credentials (user_id, password_hash, must_change) VALUES (%s,%s,%s)",
                        [(u["user_id"], h, force) for u in org["users"] if u["role"] in ("Analyst", "Admin")])
        c.commit()
