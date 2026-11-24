"""Command line: python -m app.cli reset|train|train-flow|seed|ctu-replay N|correlate|evaluate|evaluate-ctu|serve"""
from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from collections import Counter, defaultdict

from . import config, db, ingest, ml
from .generator import Generator, build_org
from .rawstore import store

GT_FILE = config.DATA_DIR / "ground_truth.json"


def correlate(window_min: int = 30):
    r = db.one("SELECT * FROM fn_correlate_events(make_interval(mins => %s))", (window_min,))
    db.query("SELECT sp_refresh_risk()")
    return r


def seed(days: int = 7, attacks: int = 10, seed_no: int = 42):
    org = build_org(random.Random(7))
    ingest.seed_org(org)
    store().clear()
    gen = Generator(seed=seed_no, org=org)
    events = gen.dataset(days=days, n_attacks=attacks)
    ids = ingest.ingest_events(events)
    ordered = sorted(events, key=lambda e: e["ts"])
    gt = {str(i): e["label"]["scenario"] for i, e in zip(ids, ordered) if e["label"].get("attack")}
    config.DATA_DIR.mkdir(exist_ok=True)
    GT_FILE.write_text(json.dumps(gt))
    print(f"ingested {len(ids)} events ({len(gt)} attack events, {len(set(gt.values()))} scenarios); "
          f"raw store: {store().backend}")
    print("correlation:", correlate())
    CTU_GT_FILE.unlink(missing_ok=True)
    try:   # real botnet traffic from CTU-13, ending 2 days ago so it sits inside the 7-day window
        from datetime import datetime, timedelta, timezone
        end = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=2)
        from .ctu13 import HELDOUT
        for i, sc in enumerate(int(x) for x in os.environ.get("CTU_SCENARIOS", ",".join(map(str, HELDOUT))).split(",")):
            info = ctu_replay(sc, end=end - timedelta(hours=6 * i))
            print(f"CTU-13 replay: scenario {info['scenario']} ({info['botnet_family']}), {info['events']} real flows "
                  f"({info['botnet_events']} botnet) from {info['hosts']} hosts")
    except FileNotFoundError:
        print("CTU-13 not found - skipped real botnet replay")
    print("analyst workflow history seeded for", seed_workflow(), "incidents")
    from .auth import DEFAULT_PASSWORD
    print(f"logins: analyst.rao / admin.iyer (password {DEFAULT_PASSWORD})")


def _call(sql, params):
    with db.conn() as c, c.cursor() as cur:
        cur.execute(sql, params)
        c.commit()


def seed_workflow() -> int:
    """Replay some realistic analyst work so audit/report screens have history."""
    uid = {r["username"]: r["user_id"] for r in db.query("SELECT user_id, username FROM users WHERE role IN ('Analyst','Admin')")}
    n = 0
    benign = db.query("""SELECT incident_id, title FROM incidents
                          WHERE title ILIKE '%%svc.vulnscan%%' OR title ILIKE '%%svc.backup%%' ORDER BY incident_id LIMIT 4""")
    for b in benign:
        _call("SELECT sp_assign_incident(%s,%s,%s)", (b["incident_id"], uid["analyst.menon"], uid["analyst.menon"]))
        _call("SELECT sp_add_action(%s,%s,'NOTE',%s)", (b["incident_id"], uid["analyst.menon"],
              "Verified against change calendar: authorised scheduled job (vuln scan / nightly backup)."))
        _call("SELECT sp_set_incident_status(%s,'False Positive',%s,%s)", (b["incident_id"], uid["analyst.menon"],
              "Authorised activity"))
        n += 1
    top = db.one("SELECT incident_id FROM incidents WHERE status='New' ORDER BY risk_score DESC LIMIT 1")
    if top:
        i = top["incident_id"]
        _call("SELECT sp_assign_incident(%s,%s,%s)", (i, uid["analyst.rao"], uid["admin.iyer"]))
        _call("SELECT sp_add_action(%s,%s,'CONTAINMENT',%s)", (i, uid["analyst.rao"],
              "Disabled the compromised account, blocked the source IP at the VPN gateway, isolated file-srv-01."))
        _call("SELECT sp_set_incident_status(%s,'Contained',%s,%s)", (i, uid["analyst.rao"], "Containment complete"))
        n += 1
    med = db.query("SELECT incident_id FROM incidents WHERE status='New' AND severity_level IN ('Medium','High') "
                   "ORDER BY risk_score LIMIT 2")
    for m in med:
        i = m["incident_id"]
        _call("SELECT sp_assign_incident(%s,%s,%s)", (i, uid["analyst.das"], uid["analyst.das"]))
        _call("SELECT sp_add_action(%s,%s,'NOTE',%s)", (i, uid["analyst.das"], "User confirmed travel; MFA verified."))
        _call("SELECT sp_set_incident_status(%s,'Resolved',%s,%s)", (i, uid["analyst.das"], "Benign after user confirmation"))
        _call("SELECT sp_set_incident_status(%s,'Closed',%s,%s)", (i, uid["admin.iyer"], "Reviewed by admin"))
        n += 1
    db.query("SELECT sp_refresh_risk()")
    return n


CTU_GT_FILE = config.DATA_DIR / "ctu13_ground_truth.json"


def ctu_replay(scenario: int = 3, minutes: int = 90, end=None) -> dict:
    """Replay a slice of a real CTU-13 capture through the full pipeline."""
    from . import ctu13
    hosts, events, info = ctu13.replay(scenario, minutes, end=end)
    with db.conn() as c, c.cursor() as cur:
        cur.execute("SELECT set_config('app.actor', 'ctu13-loader', true)")
        cur.executemany("""INSERT INTO devices (hostname, ip_address, mac_address, os_version, device_type, criticality)
                           VALUES (%(hostname)s, %(ip_address)s, %(mac_address)s, %(os_version)s, %(device_type)s, %(criticality)s)
                           ON CONFLICT (hostname) DO NOTHING""", hosts)
        c.commit()
    ids = {r["ip"]: r["device_id"] for r in db.query(
        "SELECT host(ip_address) AS ip, device_id FROM devices WHERE hostname LIKE %s", (f"ctu{scenario}-%",))}
    for e in events:
        e["device_id"] = ids[e.pop("host_ip")]
    new_ids = ingest.ingest_events(events)
    ordered = sorted(events, key=lambda e: e["ts"])
    gt = json.loads(CTU_GT_FILE.read_text()) if CTU_GT_FILE.exists() else {}
    for i, e in zip(new_ids, ordered):
        gt[str(i)] = bool(e["label"]["attack"])
    CTU_GT_FILE.write_text(json.dumps(gt))
    info["correlation"] = correlate()
    return info


def evaluate_ctu() -> dict:
    """Real ground truth: how CTU-13 botnet vs normal flows fared in the pipeline."""
    if not CTU_GT_FILE.exists():
        return {}
    gt = json.loads(CTU_GT_FILE.read_text())
    ids = [int(k) for k in gt]
    alerted = {r["event_id"] for r in db.query("SELECT event_id FROM system_alerts WHERE event_id = ANY(%s)", (ids,))}
    linked = {r["event_id"]: r["incident_id"] for r in db.query(
        "SELECT event_id, incident_id FROM incident_events WHERE event_id = ANY(%s)", (ids,))}
    bot = [int(k) for k, v in gt.items() if v]
    norm = [int(k) for k, v in gt.items() if not v]
    tp = sum(1 for i in bot if i in alerted)
    fp = sum(1 for i in norm if i in alerted)
    incs: dict[int, list[bool]] = {}
    for e, inc in linked.items():
        incs.setdefault(inc, []).append(gt[str(e)])
    pure = [sum(v) / len(v) for v in incs.values()]
    # host level: was every infected machine flagged, and no clean machine?
    hosts = db.query("""SELECT e.device_id, d.hostname, bool_or(a.event_id IS NOT NULL) AS alerted, array_agg(e.event_id) AS ids
                          FROM security_events e JOIN devices d USING (device_id)
                          LEFT JOIN system_alerts a ON a.event_id = e.event_id
                         WHERE e.event_id = ANY(%s) GROUP BY e.device_id, d.hostname""", (ids,))
    inf = [h for h in hosts if any(gt[str(i)] for i in h["ids"])]
    clean = [h for h in hosts if not any(gt[str(i)] for i in h["ids"])]
    return {"botnet_flows": len(bot), "normal_flows": len(norm),
            "botnet_alert_rate (recall)": round(tp / max(1, len(bot)), 3),
            "normal_alert_rate (false positive rate)": round(fp / max(1, len(norm)), 3),
            "alert_precision": round(tp / max(1, tp + fp), 3),
            "incidents_from_ctu": len(incs),
            "mean_incident_purity": round(sum(pure) / max(1, len(pure)), 3),
            "infected_hosts_flagged": f"{sum(h['alerted'] for h in inf)}/{len(inf)}",
            "clean_hosts_flagged": f"{sum(h['alerted'] for h in clean)}/{len(clean)}"}


def evaluate() -> dict:
    gt = json.loads(GT_FILE.read_text())
    rows = db.query("SELECT event_id, incident_id FROM incident_events")
    ev2inc = {str(r["event_id"]): r["incident_id"] for r in rows}
    inc_members = defaultdict(list)
    for e, i in ev2inc.items():
        inc_members[i].append(e)
    by_sc = defaultdict(list)
    for e, sc in gt.items():
        by_sc[sc].append(e)
    out = {}
    for sc, evs in sorted(by_sc.items()):
        linked = [ev2inc[e] for e in evs if e in ev2inc]
        if not linked:
            out[sc] = {"events": len(evs), "linked": 0, "completeness": 0.0, "purity": 0.0}
            continue
        top, n = Counter(linked).most_common(1)[0]
        members = inc_members[top]
        out[sc] = {"events": len(evs), "linked": len(linked), "incident": top,
                   "completeness": round(n / len(evs), 3),
                   "purity": round(sum(1 for m in members if gt.get(m) == sc) / len(members), 3)}
    return out


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "reset":
        subprocess.run([str(config.ROOT / "scripts" / "setup_db.sh")], check=True)
    elif cmd == "train":
        print(json.dumps(ml.train(), indent=2))
    elif cmd == "seed":
        seed()
    elif cmd == "correlate":
        print(correlate())
    elif cmd == "evaluate":
        res = evaluate()
        for k, v in res.items():
            print(k, v)
        if res:
            print("mean completeness", round(sum(v["completeness"] for v in res.values()) / len(res), 3),
                  "mean purity", round(sum(v["purity"] for v in res.values()) / len(res), 3))
    elif cmd == "train-flow":
        from . import flowml
        print(json.dumps(flowml.train(), indent=2))
    elif cmd == "ctu-replay":
        print(json.dumps(ctu_replay(int(sys.argv[2]) if len(sys.argv) > 2 else 3), indent=2, default=str))
    elif cmd == "evaluate-ctu":
        print(json.dumps(evaluate_ctu(), indent=2))
    elif cmd == "serve":
        import uvicorn
        uvicorn.run("app.main:app", host="127.0.0.1", port=8765, reload=False)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
