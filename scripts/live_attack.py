"""Live attack demo: run this in a Terminal while the website is open.

An "attacker" carries out a multi-step attack one step at a time. Each step
goes through the real pipeline (ML score -> MongoDB -> PostgreSQL triggers ->
alerts -> correlation -> automatic containment) and the Terminal narrates
what the attacker did and how the system reacted. The website updates live.

    .venv/bin/python scripts/live_attack.py                      # account takeover (default)
    .venv/bin/python scripts/live_attack.py --scenario recon_bruteforce --delay 1.5

Scenarios: account_takeover_exfil, recon_bruteforce, insider_data_theft, malware_outbreak, privilege_abuse
All events are tagged 'simulated'.
"""
from __future__ import annotations

import argparse
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import cli, db, ingest  # noqa: E402
from app.generator import SCENARIOS, Generator, attacker_returns  # noqa: E402

R, G, Y, B, D, BOLD, X = "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[2m", "\033[1m", "\033[0m"
SAY = {
    "failed_login": "tries a password for {user}… wrong",
    "successful_login": "logs in as {user}",
    "new_device_access": "registers a new device on {user}'s account",
    "confidential_file_access": "opens a confidential file",
    "file_access": "opens a file",
    "privilege_escalation": "gives themselves admin/root rights",
    "data_transfer": "uploads {mb} to an outside server",
    "port_scan": "probes a server port",
    "malware_alert": "runs malware on the machine",
}


def pick_attack(scenario: str):
    """An attack whose victim account and attacker IP are not already blocked."""
    blocked_users = {r["entity_value"] for r in db.query("SELECT entity_value FROM blocked_entities WHERE active AND entity_type='user'")}
    for _ in range(50):
        gen = Generator(seed=random.randint(1, 10 ** 6))
        events = gen.attack(scenario, datetime.now(timezone.utc))
        users = {str(e["user_id"]) for e in events if e.get("user_id")}
        if not users & blocked_users:
            return gen, events
    return gen, events


def describe(e, names):
    sub = e.get("sub") or {}
    mb = f"{(sub.get('bytes_sent') or 0) / 1e6:,.0f} MB" if (sub.get("bytes_sent") or 0) > 1e6 else f"{(sub.get('bytes_sent') or 0):,} bytes"
    return SAY.get(e["category"], e["category"]).format(user=names.get(e.get("user_id"), "an account"), mb=mb)


def report(event_id: int, seen_incident: dict, seen_blocks: set):
    ev = db.one("""SELECT e.risk_score, e.severity, e.blocked, e.anomaly_score,
                          (SELECT alert_type FROM system_alerts a WHERE a.event_id = e.event_id LIMIT 1) AS alert,
                          (SELECT incident_id FROM incident_events ie WHERE ie.event_id = e.event_id) AS incident
                     FROM security_events e WHERE e.event_id = %s""", (event_id,))
    if ev["blocked"]:
        print(f"   {R}{BOLD}⛔ BLOCKED{X}{R} — this attacker is already contained; attempt recorded as evidence{X}")
    elif ev["alert"]:
        print(f"   {Y}⚠  ALERT raised{X}  risk {ev['risk_score']} ({ev['severity']}), ML anomaly {ev['anomaly_score']}")
    else:
        print(f"   {D}·  recorded, risk {ev['risk_score']} ({ev['severity']}) — not suspicious on its own{X}")
    if ev["incident"]:
        inc = db.one("SELECT incident_id, title, severity_level, risk_score, status FROM incidents WHERE incident_id=%s", (ev["incident"],))
        key = inc["incident_id"]
        if key not in seen_incident:
            print(f"   {B}{BOLD}📁 INCIDENT #{key} opened{X}{B}: {inc['title']}{X}")
        elif seen_incident[key] != inc["severity_level"]:
            print(f"   {B}📁 incident #{key} is now {BOLD}{inc['severity_level']}{X}{B} (risk {inc['risk_score']}){X}")
        seen_incident[key] = inc["severity_level"]
        for b in db.query("SELECT block_id, entity_type, entity FROM v_blocks WHERE incident_id=%s AND active", (key,)):
            if b["block_id"] not in seen_blocks:
                seen_blocks.add(b["block_id"])
                what = "attacker IP" if b["entity_type"] == "ip" else "compromised account"
                print(f"   {G}{BOLD}🛡  AUTO-CONTAINED{X}{G}: {what} {b['entity']} blocked by the database{X}")
        return key
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", default="account_takeover_exfil", choices=SCENARIOS)
    ap.add_argument("--delay", type=float, default=2.0, help="seconds between attack steps (default 2)")
    ap.add_argument("--returns", type=int, default=4, help="attempts after containment (default 4)")
    a = ap.parse_args()

    names = {r["user_id"]: r["username"] for r in db.query("SELECT user_id, username FROM users")}
    gen, events = pick_attack(a.scenario)
    ip = next((e["source_ip"] for e in events if e.get("source_ip")), "?")
    print(f"\n{BOLD}🎯 Live attack: {a.scenario.replace('_', ' ')}{X}  — attacker at {ip}, {len(events)} steps\n"
          f"{D}   Keep the website open on the Dashboard or Alerts page to watch it react.{X}\n")
    seen_incident: dict = {}
    seen_blocks: set = set()
    incident = None
    for i, e in enumerate(events, 1):
        e["ts"] = datetime.now(timezone.utc).replace(microsecond=0)
        print(f"{R}🕵  attacker{X} [{i}/{len(events)}] {describe(e, names)}")
        eid = ingest.ingest_events([e], use_history=True)[0]
        cli.correlate()
        incident = report(eid, seen_incident, seen_blocks) or incident
        time.sleep(a.delay)

    blocked_ip = db.one("SELECT entity_value FROM blocked_entities WHERE active AND entity_type='ip' AND entity_value=%s", (ip,))
    if blocked_ip and a.returns:
        print(f"\n{BOLD}🔁 The attacker comes back and tries again…{X}")
        victim = next((e["user_id"] for e in events if e.get("user_id")), None)
        for k, e in enumerate(attacker_returns(gen, ip, victim, datetime.now(timezone.utc), n=a.returns), 1):
            e["ts"] = datetime.now(timezone.utc).replace(microsecond=0)
            print(f"{R}🕵  attacker{X} [retry {k}] {describe(e, names)}")
            eid = ingest.ingest_events([e], use_history=True)[0]
            cli.correlate()
            report(eid, seen_incident, seen_blocks)
            time.sleep(a.delay / 2)

    if incident:
        inc = db.one("SELECT title, severity_level, risk_score, status FROM incidents WHERE incident_id=%s", (incident,))
        blocked = db.one("SELECT COUNT(*) n FROM security_events WHERE blocked AND host(source_ip)=%s", (ip,))["n"]
        print(f"\n{BOLD}✅ Result{X}: incident #{incident} — {inc['title']} — {inc['severity_level']}, risk {inc['risk_score']}\n"
              f"   {blocked} attacker attempt(s) blocked.  Open it: website → Incidents → #{incident}\n")
    else:
        print(f"\n{Y}No incident was opened (the steps were not suspicious enough).{X}\n")


if __name__ == "__main__":
    main()
