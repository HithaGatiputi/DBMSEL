"""Synthetic organisation and multi-stage attack simulator overlaid on REAL
network traffic.

Background flows, port-scan probes and C2 beacons are sampled from the real
CIC-IDS2017 dataset (data/raw/cicids2017) when it is present; otherwise a
log-normal approximation is used. Attack scenarios are overlaid on top and
carry ground-truth labels (kept outside the database) so correlation quality
can be evaluated. Real botnet traffic from CTU-13 is replayed by app/ctu13.py.
"""
from __future__ import annotations

import os
import random
from datetime import datetime, timedelta, timezone

FIRST = ["aarav", "diya", "kabir", "meera", "rohan", "ananya", "vikram", "isha", "arjun", "neha",
         "rahul", "priya", "siddharth", "kavya", "nikhil", "sneha", "aditya", "tanvi", "manish", "pooja",
         "varun", "riya", "karan", "shruti", "ishaan", "divya", "harsh", "anjali", "yash", "nandini"]
LAST = ["sharma", "rao", "iyer", "nair", "patel", "reddy", "gupta", "menon", "singh", "das"]
DEPTS = ["Engineering", "Finance", "HR", "Sales", "Operations", "Legal"]
OS = ["Windows 11 23H2", "Windows 10 22H2", "Ubuntu 22.04", "macOS 14.5"]
EXT_COUNTRIES = ["RU", "CN", "NG", "BR", "KP", "IR", "VN"]
SCENARIOS = ["account_takeover_exfil", "recon_bruteforce", "insider_data_theft",
             "malware_outbreak", "privilege_abuse"]


def _mac(rng):
    return ":".join(f"{rng.randint(0, 255):02x}" for _ in range(6))


def build_org(rng: random.Random, n_employees: int = 36) -> dict:
    """In-memory org with deterministic sequential ids (users 1..N, devices 1..M)."""
    users, devices = [], []

    def add_user(name, role, dept):
        users.append({"user_id": len(users) + 1, "username": name,
                      "email": f"{name}@rvce-corp.example", "role": role, "department": dept})
        return users[-1]

    def add_dev(owner, host, ip, os_, typ, crit):
        devices.append({"device_id": len(devices) + 1, "owner_id": owner, "hostname": host,
                        "ip_address": ip, "mac_address": _mac(rng), "os_version": os_,
                        "device_type": typ, "criticality": crit})
        return devices[-1]

    for n in ("analyst.rao", "analyst.menon", "analyst.das"):
        add_user(n, "Analyst", "Security")
    adm = [add_user(n, "Admin", "IT") for n in ("admin.iyer", "admin.singh")]
    add_user("exec.sharma", "Executive", "Management")
    svc = add_user("svc.vulnscan", "Service", "Security")
    backup = add_user("svc.backup", "Service", "IT")
    names = set()
    while len(names) < n_employees:
        names.add(f"{rng.choice(FIRST)}.{rng.choice(LAST)}")
    emps = [add_user(n, "Employee", rng.choice(DEPTS)) for n in sorted(names)]

    servers = {}
    for host, ip, typ, crit in [("db-prod-01", "10.0.5.10", "database", 5),
                                ("file-srv-01", "10.0.5.20", "server", 4),
                                ("web-01", "10.0.6.10", "server", 3),
                                ("vpn-gw-01", "10.0.0.1", "firewall", 4),
                                ("scanner-01", "10.0.9.5", "server", 2),
                                ("backup-01", "10.0.8.8", "server", 3)]:
        servers[host] = add_dev(None, host, ip, "Ubuntu 22.04", typ, crit)
    for i, u in enumerate(users):
        if u["role"] == "Service":
            continue
        crit = 4 if u["role"] in ("Admin", "Executive") else 2
        d = add_dev(u["user_id"], f"{u['username'].replace('.', '-')}-lt",
                    f"10.1.{i // 200}.{(i % 200) + 10}", rng.choice(OS), "laptop", crit)
        u["device_id"], u["home_ip"] = d["device_id"], d["ip_address"]
    rogue = [add_dev(None, f"unregistered-{i}", f"172.16.{i}.77", "Unknown", "workstation", 1)
             for i in range(1, 5)]
    return {"users": users, "devices": devices, "servers": servers, "rogue": rogue,
            "employees": emps, "admins": adm, "svc": svc, "backup": backup}


# ---------------------------------------------------------------------------
def _ext_ip(rng):
    return f"{rng.choice([45, 91, 103, 185, 194, 203])}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"


IST = timedelta(hours=5, minutes=30)     # organisation time zone offset (Asia/Kolkata, no DST)


def _ev(ts, cat, user, dev, ip, sub, raw, label=None):
    d = dev if isinstance(dev, dict) else {"device_id": dev, "criticality": 2}
    raw = {"event_category": cat, "@timestamp": ts.isoformat(), **raw}
    return {"ts": ts, "category": cat, "event_source": "simulator", "user_id": user["user_id"] if user else None,
            "device_id": d["device_id"], "crit": d["criticality"], "source_ip": ip,
            "sub": sub, "raw": raw, "label": label or {"attack": False}}


def _hexdump(rng, n=48):
    return bytes(rng.randint(0, 255) for _ in range(n)).hex()


class Generator:
    def __init__(self, seed: int = 42, org: dict | None = None):
        self.rng = random.Random(seed)
        self.org = org or build_org(random.Random(7))
        self._flows = self._load_real_flows()
        self._atk_n = 0

    def _load_real_flows(self):
        """Real CIC-IDS2017 flows (grouped by label) if the dataset is present."""
        try:
            from .flowml import flow_pool
            return flow_pool()
        except Exception:
            return None

    def real_flow(self, label: str = "BENIGN") -> dict | None:
        """One real CIC-IDS2017 flow of the given label as network-event fields."""
        if not self._flows or label not in self._flows:
            return None
        g = self._flows[label]
        r = g.iloc[self.rng.randrange(len(g))]
        return {"bytes_sent": int(r["bytes_sent"]), "bytes_received": int(r["bytes_received"]),
                "duration_s": round(float(r["duration_us"]) / 1e6, 3),
                "packets": int(r["fwd_pkts"] + r["bwd_pkts"]), "destination_port": int(r["dst_port"]),
                "cic_label": label}

    def flow_bytes(self):
        f = self.real_flow("BENIGN")
        if f:
            return f["bytes_sent"], f["bytes_received"]
        return int(self.rng.lognormvariate(8.5, 1.4)), int(self.rng.lognormvariate(9.0, 1.5))

    # ------------------------- benign traffic ------------------------------
    def benign(self, start: datetime, days: int) -> list[dict]:
        r, o, out = self.rng, self.org, []
        S = o["servers"]
        for day in range(days):
            # midnight in organisation time (IST), expressed in UTC
            base = (start + timedelta(days=day)).replace(hour=0, minute=0, second=0, microsecond=0) - IST
            weekend = (base + IST).weekday() >= 5
            for u in o["users"]:
                if u["role"] == "Service" or (weekend and r.random() < 0.8):
                    continue
                lt = o["devices"][u["device_id"] - 1]
                t = base + timedelta(hours=9, minutes=r.randint(-40, 60))
                if r.random() < 0.12:       # honest typo
                    out.append(_ev(t - timedelta(seconds=40), "failed_login", u, S["vpn-gw-01"], u["home_ip"],
                                   {"auth_method": "password", "login_status": "failure",
                                    "failure_reason": "wrong_password", "location_geo": "IN"},
                                   {"message": f"Failed password for {u['username']}", "service": "sshd"}))
                out.append(_ev(t, "successful_login", u, S["vpn-gw-01"], u["home_ip"],
                               {"auth_method": r.choice(["password", "mfa", "sso"]), "login_status": "success",
                                "failure_reason": None, "location_geo": "IN"},
                               {"message": f"Accepted login for {u['username']}", "service": "sshd"}))
                for _ in range(r.randint(1, 4)):
                    out.append(self._file(u, S["file-srv-01"], t + timedelta(minutes=r.randint(5, 420)),
                                          r.choice(["public", "internal", "internal"])))
                if u["department"] in ("Finance", "HR", "Legal") and r.random() < 0.15:
                    out.append(self._file(u, S["file-srv-01"], t + timedelta(minutes=r.randint(30, 400)),
                                          "confidential"))
                for _ in range(r.randint(3, 8)):
                    ts = t + timedelta(minutes=r.randint(1, 480))
                    f = self.real_flow("BENIGN")
                    if f:
                        # most real benign traffic (web, DNS, SaaS) goes to the internet
                        internet = f["destination_port"] in (53, 80, 443, 8080, 123) or r.random() < 0.3
                        dst = _ext_ip(r) if internet and r.random() < 0.85 else f"10.0.{r.randint(5, 6)}.{r.randint(10, 40)}"
                        out.append(self._transfer(u, lt, u["home_ip"], ts, f["bytes_sent"], f["bytes_received"],
                                                  dst, f["destination_port"],
                                                  extra={"cic_label": "BENIGN"}, flow=f))
                    else:
                        bo, bi = self.flow_bytes()
                        out.append(self._transfer(u, lt, u["home_ip"], ts, bo, bi,
                                                  f"10.0.{r.randint(5, 6)}.{r.randint(10, 40)}",
                                                  r.choice([80, 443, 443, 22, 3306, 445])))
                if r.random() < 0.07:       # legit upload to cloud
                    out.append(self._transfer(u, lt, u["home_ip"], t + timedelta(minutes=r.randint(60, 400)),
                                              r.randint(5, 30) * 10 ** 6, 20000, _ext_ip(r), 443))
                if u["role"] == "Admin":
                    for _ in range(r.randint(1, 3)):
                        out.append(_ev(t + timedelta(minutes=r.randint(10, 400)), "privilege_escalation", u,
                                       S[r.choice(["web-01", "file-srv-01"])], u["home_ip"],
                                       {"old_role": "admin", "new_role": "root", "method": "sudo"},
                                       {"message": f"{u['username']} : COMMAND=/usr/bin/systemctl", "service": "sudo"}))
            # nightly authorised vulnerability scan (benign but alert-worthy)
            sc = o["svc"]
            ts = base + timedelta(hours=2, minutes=r.randint(0, 20))
            out.append(_ev(ts, "port_scan", sc, S["web-01"], S["scanner-01"]["ip_address"],
                           {"destination_ip": S["web-01"]["ip_address"], "destination_port": 443, "protocol": "tcp",
                            "bytes_sent": 4000, "bytes_received": 900},
                           {"message": "Scheduled authenticated vulnerability scan", "tool": "nessus-agent",
                            "ports_probed": 1024}))
            # nightly backup job: large transfer to an external backup provider (benign)
            bk = o["backup"]
            ts = base + timedelta(hours=1, minutes=r.randint(20, 40))
            out.append(self._transfer(bk, S["backup-01"], S["backup-01"]["ip_address"], ts,
                                      r.randint(250, 600) * 10 ** 6, 40000, "52.95.110.12", 443,
                                      extra={"job": "nightly-backup", "vendor": "s3-compatible"}))
            # travelling employee: logs in from abroad on a new phone (benign but suspicious-looking)
            if r.random() < 0.5:
                u = r.choice(o["employees"])
                t = base + timedelta(hours=r.randint(4, 16), minutes=r.randint(0, 59))
                ip, geo = _ext_ip(r), r.choice(["DE", "SG", "US", "AE"])
                if r.random() < 0.5:
                    out.append(_ev(t - timedelta(seconds=50), "failed_login", u, S["vpn-gw-01"], ip,
                                   {"auth_method": "mfa", "login_status": "failure",
                                    "failure_reason": "mfa_timeout", "location_geo": geo},
                                   {"message": f"MFA timeout for {u['username']} from {ip}", "service": "idp"}))
                out.append(_ev(t, "successful_login", u, S["vpn-gw-01"], ip,
                               {"auth_method": "mfa", "login_status": "success", "failure_reason": None, "location_geo": geo},
                               {"message": f"Accepted MFA login for {u['username']} from {ip} ({geo})", "service": "idp"}))
                out.append(_ev(t + timedelta(minutes=1), "new_device_access", u, r.choice(o["rogue"]), ip,
                               {"auth_method": "mfa", "login_status": "success", "failure_reason": None, "location_geo": geo},
                               {"message": f"New phone registered for {u['username']} (MFA verified)", "service": "idp"}))
        return out

    def _file(self, u, srv, ts, cls):
        r = self.rng
        sensitive = cls in ("confidential", "restricted")
        cat = "confidential_file_access" if sensitive else "file_access"
        path = f"/shares/{u['department'].lower()}/{r.choice(['report', 'budget', 'notes', 'roster', 'contract'])}_{r.randint(1, 99)}.xlsx"
        return _ev(ts, cat, u, srv, u["home_ip"],
                   {"file_path": path, "is_sensitive": sensitive, "action_type": r.choice(["read", "read", "write", "copy"])},
                   {"message": f"{u['username']} read {cls} file {path}", "service": "smbd", "file": path})

    def _transfer(self, u, dev, ip, ts, bo, bi, dst, port, label=None, extra=None, flow=None):
        sub = {"destination_ip": dst, "destination_port": port, "protocol": "tcp", "bytes_sent": bo, "bytes_received": bi}
        if flow:
            sub.update(duration_s=flow["duration_s"], packets=flow["packets"])
        return _ev(ts, "data_transfer", u, dev, ip, sub,
                   {"message": f"flow {ip} -> {dst}:{port} out={bo}B in={bi}B", "packet_sample_hex": _hexdump(self.rng),
                    **(extra or {})}, label)

    # ----------------------------- attacks ---------------------------------
    def attack(self, scenario: str, t0: datetime) -> list[dict]:
        self._atk_n += 1
        sid = f"ATK-{self._atk_n:03d}-{scenario}"
        return getattr(self, "_atk_" + scenario)(sid, t0)

    def _lab(self, sid, stage):
        return {"attack": True, "scenario": sid, "stage": stage}

    def _fails(self, sid, t, user, dev, ip, n, gap=(15, 40), geo="RU", svc="sshd"):
        out = []
        for _ in range(n):
            t += timedelta(seconds=self.rng.randint(*gap))
            out.append(_ev(t, "failed_login", user, dev, ip,
                           {"auth_method": "password", "login_status": "failure",
                            "failure_reason": "wrong_password", "location_geo": geo},
                           {"message": f"Failed password for {user['username']} from {ip}", "service": svc},
                           self._lab(sid, "credential_access")))
        return out, t

    def _atk_account_takeover_exfil(self, sid, t):
        r, o = self.rng, self.org
        v = r.choice([u for u in o["employees"] if u["department"] in ("Finance", "Engineering", "Legal")])
        ip, geo = _ext_ip(r), r.choice(EXT_COUNTRIES)
        vpn, fs = o["servers"]["vpn-gw-01"], o["servers"]["file-srv-01"]
        ev, t = self._fails(sid, t, v, vpn, ip, r.randint(7, 12), geo=geo)
        t += timedelta(seconds=30)
        ev.append(_ev(t, "successful_login", v, vpn, ip,
                      {"auth_method": "password", "login_status": "success", "failure_reason": None, "location_geo": geo},
                      {"message": f"Accepted password for {v['username']} from {ip}", "service": "sshd"},
                      self._lab(sid, "initial_access")))
        t += timedelta(minutes=2)
        ev.append(_ev(t, "new_device_access", v, r.choice(o["rogue"]), ip,
                      {"auth_method": "password", "login_status": "success", "failure_reason": None, "location_geo": geo},
                      {"message": f"New device enrolled for {v['username']}", "service": "idp",
                       "device_fingerprint": _hexdump(r, 16)}, self._lab(sid, "persistence")))
        for _ in range(r.randint(2, 4)):
            t += timedelta(minutes=r.randint(2, 6))
            p = f"/shares/{v['department'].lower()}/restricted/{r.choice(['payroll', 'm&a', 'source', 'customers'])}_{r.randint(1, 50)}.zip"
            ev.append(_ev(t, "confidential_file_access", v, fs, ip,
                          {"file_path": p, "is_sensitive": True, "action_type": "read"},
                          {"message": f"{v['username']} read restricted file {p}", "service": "smbd"},
                          self._lab(sid, "collection")))
        t += timedelta(minutes=3)
        ev.append(_ev(t, "privilege_escalation", v, fs, ip,
                      {"old_role": "user", "new_role": "root", "method": "exploit"},
                      {"message": f"{v['username']} gained uid=0 via polkit", "service": "kernel"},
                      self._lab(sid, "privilege_escalation")))
        for _ in range(r.randint(1, 2)):
            t += timedelta(minutes=r.randint(3, 6))
            ev.append(self._transfer(v, fs, ip, t, r.randint(200, 900) * 10 ** 6, 5000, _ext_ip(r), 443,
                                     self._lab(sid, "exfiltration")))
        return ev

    def _atk_recon_bruteforce(self, sid, t):
        r, o = self.rng, self.org
        web = o["servers"]["web-01"]
        ip = _ext_ip(r)
        adm = r.choice(o["admins"])
        ev = []
        for port in r.sample([21, 22, 23, 25, 80, 110, 139, 443, 445, 3306, 3389, 8080], r.randint(6, 9)):
            t += timedelta(seconds=r.randint(5, 20))
            f = self.real_flow("PortScan") or {"bytes_sent": 0, "bytes_received": 6, "duration_s": 0.0, "packets": 2}
            ev.append(_ev(t, "port_scan", None, web, ip,
                          {"destination_ip": web["ip_address"], "destination_port": port, "protocol": "tcp",
                           "bytes_sent": f["bytes_sent"], "bytes_received": f["bytes_received"],
                           "duration_s": f["duration_s"], "packets": f["packets"]},
                          {"message": f"SYN probe {ip} -> {web['ip_address']}:{port}", "flags": "S"},
                          self._lab(sid, "reconnaissance")))
        f, t = self._fails(sid, t, adm, web, ip, r.randint(6, 10), gap=(5, 15), geo="CN")
        ev += f
        t += timedelta(seconds=20)
        ev.append(_ev(t, "successful_login", adm, web, ip,
                      {"auth_method": "password", "login_status": "success", "failure_reason": None, "location_geo": "CN"},
                      {"message": f"Accepted password for {adm['username']} from {ip}", "service": "sshd"},
                      self._lab(sid, "initial_access")))
        t += timedelta(minutes=2)
        ev.append(_ev(t, "malware_alert", adm, web, ip,
                      {"destination_ip": _ext_ip(r), "destination_port": 4444, "protocol": "tcp", "bytes_sent": 3000,
                       "bytes_received": 90000},
                      {"message": "AV: Linux/Mirai.B detected in /tmp/.x", "stack_trace":
                       ["at dropper.run(dropper.c:88)", "at sh.exec(sh.c:12)", "at sshd.session(sshd.c:410)"],
                       "sha256": _hexdump(r, 32)}, self._lab(sid, "execution")))
        return ev

    def _atk_insider_data_theft(self, sid, t):
        r, o = self.rng, self.org
        v = r.choice(o["employees"])
        start = t
        local = (t + IST).replace(hour=23, minute=r.randint(0, 40))   # 23:xx organisation time
        t = local - IST
        if t > start:                      # never place an insider session in the future
            t -= timedelta(days=1)
        db_, fs = o["servers"]["db-prod-01"], o["servers"]["file-srv-01"]
        lt = o["devices"][v["device_id"] - 1]
        ev = [_ev(t, "successful_login", v, o["servers"]["vpn-gw-01"], v["home_ip"],
                  {"auth_method": "password", "login_status": "success", "failure_reason": None, "location_geo": "IN"},
                  {"message": f"Accepted password for {v['username']} (after hours)", "service": "sshd"},
                  self._lab(sid, "initial_access"))]
        for _ in range(r.randint(4, 6)):
            t += timedelta(minutes=r.randint(1, 4))
            p = f"/db/exports/{r.choice(['customers', 'salaries', 'ip_designs'])}_{r.randint(1, 99)}.csv"
            ev.append(_ev(t, "confidential_file_access", v, db_, v["home_ip"],
                          {"file_path": p, "is_sensitive": True, "action_type": "read"},
                          {"message": f"{v['username']} read restricted file {p}", "service": "postgres-audit"},
                          self._lab(sid, "collection")))
        t += timedelta(minutes=5)
        ev.append(self._transfer(v, lt, v["home_ip"], t, r.randint(150, 400) * 10 ** 6, 8000, _ext_ip(r), 443,
                                 self._lab(sid, "exfiltration")))
        return ev

    def _atk_malware_outbreak(self, sid, t):
        r, o = self.rng, self.org
        v = r.choice(o["employees"])
        lt = o["devices"][v["device_id"] - 1]
        c2 = _ext_ip(r)
        ev = [_ev(t, "malware_alert", v, lt, v["home_ip"],
                  {"destination_ip": c2, "destination_port": 8443, "protocol": "tcp", "bytes_sent": 2200,
                   "bytes_received": 61000},
                  {"message": "EDR: Trojan.Win32.Emotet execution blocked", "stack_trace":
                   ["at invoice.docm!AutoOpen+0x42", "at powershell.exe -enc JABz...", "at rundll32.exe"],
                   "sha256": _hexdump(r, 32)}, self._lab(sid, "execution"))]
        t += timedelta(minutes=3)
        ev.append(_ev(t, "privilege_escalation", v, lt, v["home_ip"],
                      {"old_role": "user", "new_role": "SYSTEM", "method": "token_theft"},
                      {"message": "Token impersonation detected", "service": "sysmon"},
                      self._lab(sid, "privilege_escalation")))
        for _ in range(3):
            t += timedelta(minutes=r.randint(2, 5))
            f = self.real_flow("Bot")
            if f:
                ev.append(self._transfer(v, lt, v["home_ip"], t, f["bytes_sent"], f["bytes_received"], c2,
                                         f["destination_port"], self._lab(sid, "command_and_control"),
                                         extra={"cic_label": "Bot"}, flow=f))
            else:
                ev.append(self._transfer(v, lt, v["home_ip"], t, r.randint(800, 5000), r.randint(20000, 90000), c2, 8443,
                                         self._lab(sid, "command_and_control")))
        return ev

    def _atk_privilege_abuse(self, sid, t):
        r, o = self.rng, self.org
        v = r.choice(o["employees"])
        db_ = o["servers"]["db-prod-01"]
        ev = [_ev(t, "privilege_escalation", v, db_, v["home_ip"],
                  {"old_role": "user", "new_role": "root", "method": "sudo"},
                  {"message": f"{v['username']} : COMMAND=/bin/bash (not in sudoers)", "service": "sudo"},
                  self._lab(sid, "privilege_escalation"))]
        for _ in range(3):
            t += timedelta(minutes=r.randint(1, 3))
            p = f"/db/dumps/{r.choice(['users', 'payments'])}_{r.randint(1, 20)}.sql"
            ev.append(_ev(t, "confidential_file_access", v, db_, v["home_ip"],
                          {"file_path": p, "is_sensitive": True, "action_type": "read"},
                          {"message": f"{v['username']} read restricted file {p}", "service": "postgres-audit"},
                          self._lab(sid, "collection")))
        return ev

    # ------------------------------ driver ---------------------------------
    def dataset(self, days: int = 7, n_attacks: int = 8, end: datetime | None = None) -> list[dict]:
        end = end or datetime.now(timezone.utc).replace(microsecond=0)
        start = (end - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
        ev = self.benign(start, days)
        for i in range(n_attacks):
            sc = SCENARIOS[i % len(SCENARIOS)]
            t0 = start - IST + timedelta(days=self.rng.randint(0, days - 1), hours=self.rng.choice([1, 3, 10, 14, 20]),
                                   minutes=self.rng.randint(0, 59))
            if t0 > end - timedelta(hours=1):
                t0 = end - timedelta(days=1)
            ev += self.attack(sc, t0)
        ev = [e for e in ev if e["ts"] <= end]
        ev.sort(key=lambda e: e["ts"])
        return ev


def live_batch(gen: "Generator", now: datetime, n: int = 6) -> list[dict]:
    """A small batch of benign 'live' telemetry stamped around `now`."""
    r, o, S, out = gen.rng, gen.org, gen.org["servers"], []
    for _ in range(n):
        u = r.choice(o["employees"])
        t = now - timedelta(seconds=r.randint(0, 50))
        lt = o["devices"][u["device_id"] - 1]
        k = r.random()
        if k < 0.3:
            out.append(_ev(t, "successful_login", u, S["vpn-gw-01"], u["home_ip"],
                           {"auth_method": "sso", "login_status": "success", "failure_reason": None, "location_geo": "IN"},
                           {"message": f"Accepted SSO login for {u['username']}", "service": "idp"}))
        elif k < 0.6:
            out.append(gen._file(u, S["file-srv-01"], t, "internal"))
        else:
            f = gen.real_flow("BENIGN")
            if f:
                out.append(gen._transfer(u, lt, u["home_ip"], t, f["bytes_sent"], f["bytes_received"], _ext_ip(r),
                                         f["destination_port"], extra={"cic_label": "BENIGN"}, flow=f))
            else:
                bo, bi = gen.flow_bytes()
                out.append(gen._transfer(u, lt, u["home_ip"], t, bo, bi, f"10.0.6.{r.randint(10, 40)}", 443))
    return out


def attacker_returns(gen: "Generator", ip: str, user_id: int | None, now: datetime, n: int = 6) -> list[dict]:
    """The same attacker comes back after containment: more password guesses
    from the blocked IP and a few probes. Used to show containment working."""
    r, S = gen.rng, gen.org["servers"]
    user = {"user_id": user_id} if user_id else None
    out = []
    for k in range(n):
        t = now - timedelta(seconds=(n - k) * 20)
        if k % 3 == 2:
            out.append(_ev(t, "port_scan", None, S["web-01"], ip,
                           {"destination_ip": S["web-01"]["ip_address"], "destination_port": r.choice([22, 443, 3389]),
                            "protocol": "tcp", "bytes_sent": 0, "bytes_received": 6, "duration_s": 0.0, "packets": 2},
                           {"message": f"SYN probe from previously contained source {ip}", "flags": "S"},
                           {"attack": True, "scenario": "attacker-return", "stage": "reconnaissance"}))
        else:
            out.append(_ev(t, "failed_login", user, S["vpn-gw-01"], ip,
                           {"auth_method": "password", "login_status": "failure",
                            "failure_reason": "account_disabled" if user_id else "wrong_password", "location_geo": "RU"},
                           {"message": f"Login attempt from contained source {ip}", "service": "sshd"},
                           {"attack": True, "scenario": "attacker-return", "stage": "credential_access"}))
    return out
