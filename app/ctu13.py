"""CTU-13 botnet NetFlow (.binetflow) support.

* labelled_sample(): Botnet vs Normal flows for cross-dataset testing of the
  flow model (Background flows are unlabelled and excluded).
* replay(): turns a time slice of one real capture into security events so
  real botnet hosts flow through MongoDB -> PostgreSQL -> alerts -> correlation.
  Timestamps are shifted to the recent past; relative timing is preserved.

Only the .binetflow text files are used. The malware binaries and pcaps that
ship with CTU-13 are never extracted.
"""
from __future__ import annotations

import glob
import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from . import config

CTU_DIR = config.DATA_DIR / "raw" / "ctu13" / "CTU-13-Dataset"
SAMPLE_CACHE = config.DATA_DIR / "ctu13_sample.csv"
USECOLS = ["StartTime", "Dur", "Proto", "SrcAddr", "Sport", "DstAddr", "Dport", "TotPkts", "TotBytes", "SrcBytes", "Label"]
LOCAL_NET = ipaddress.ip_network("147.32.0.0/16")          # CTU university network
# Scenarios never used for training; they are replayed through the pipeline for evaluation.
HELDOUT = (5, 11, 12)
SCENARIOS = {1: "Neris", 2: "Neris", 3: "Rbot", 4: "Rbot", 5: "Virut", 6: "Menti", 7: "Sogou",
             8: "Murlo", 9: "Neris", 10: "Rbot", 11: "Rbot", 12: "NSIS.ay", 13: "Virut"}


def files() -> dict[int, Path]:
    out = {}
    for f in glob.glob(str(CTU_DIR / "*" / "*.binetflow")):
        out[int(Path(f).parent.name)] = Path(f)
    if not out:
        raise FileNotFoundError(f"CTU-13 .binetflow files not found under {CTU_DIR}")
    return dict(sorted(out.items()))


def _port(v) -> int:
    try:
        s = str(v).strip()
        return int(s, 16) if s.lower().startswith("0x") else int(float(s))
    except (ValueError, TypeError):
        return 0


def _clean(df: pd.DataFrame) -> pd.DataFrame:
    lab = df["Label"].astype(str)
    df = df.assign(kind=np.where(lab.str.contains("Botnet"), "botnet",
                         np.where(lab.str.contains("Normal"), "normal", "background")))
    df["dport"] = df["Dport"].map(_port)
    df["dur"] = pd.to_numeric(df["Dur"], errors="coerce").fillna(0)
    df["pkts"] = pd.to_numeric(df["TotPkts"], errors="coerce").fillna(1)
    tot = pd.to_numeric(df["TotBytes"], errors="coerce").fillna(0)
    df["bytes_sent"] = pd.to_numeric(df["SrcBytes"], errors="coerce").fillna(0)
    df["bytes_received"] = (tot - df["bytes_sent"]).clip(lower=0)
    return df


def read(scenario: int, nrows: int | None = None) -> pd.DataFrame:
    df = pd.read_csv(files()[scenario], usecols=USECOLS, dtype=str, nrows=nrows)
    return _clean(df)


def labelled_sample(per_class: int = 25000, scenarios=None, with_scenario: bool = False):
    """(X, y) of real Botnet (1) vs Normal (0) flows from all 13 scenarios."""
    from .flowml import features
    if not SAMPLE_CACHE.exists():
        parts = []
        for sc, f in files().items():       # chunked: the big captures have millions of rows
            keep = []
            for ch in pd.read_csv(f, usecols=USECOLS, dtype=str, chunksize=500_000):
                ch = ch[ch["Label"].str.contains("Botnet|Normal", na=False)]
                if len(ch):
                    keep.append(_clean(ch))
            df = pd.concat(keep)
            for k, g in df.groupby("kind"):
                parts.append(g.sample(n=min(len(g), per_class // 13 + 1), random_state=0).assign(scenario=sc))
        pd.concat(parts).to_csv(SAMPLE_CACHE, index=False)
    s = pd.read_csv(SAMPLE_CACHE)
    if scenarios is not None:
        s = s[s["scenario"].isin(scenarios)]
    X = features(s["dport"], s["dur"], s["bytes_sent"], s["bytes_received"], s["pkts"])
    y = (s["kind"] == "botnet").astype(int).to_numpy()
    return (X, y, s["scenario"].to_numpy()) if with_scenario else (X, y)


# ------------------------------------------------------------------ replay
def _is_local(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in LOCAL_NET
    except ValueError:
        return False


def _mac(ip: str) -> str:
    h = hashlib.md5(ip.encode()).hexdigest()
    return "02:" + ":".join(h[i:i + 2] for i in range(0, 10, 2))   # locally administered MAC


def pick_slice(scenario: int, minutes: int = 90, max_botnet: int = 400, max_normal: int = 600) -> pd.DataFrame:
    """A window that starts at the first botnet flow of the capture."""
    df = read(scenario)
    df = df[df["kind"] != "background"].copy()
    df["ts"] = pd.to_datetime(df["StartTime"], format="%Y/%m/%d %H:%M:%S.%f", errors="coerce")
    df = df.dropna(subset=["ts"]).sort_values("ts")
    start = df.loc[df["kind"] == "botnet", "ts"].min()
    win = df[(df["ts"] >= start) & (df["ts"] < start + pd.Timedelta(minutes=minutes))]
    bot, norm = win[win["kind"] == "botnet"], win[win["kind"] == "normal"]
    bot = bot.sample(n=min(len(bot), max_botnet), random_state=0)
    norm = norm.sample(n=min(len(norm), max_normal), random_state=0)
    return pd.concat([bot, norm]).sort_values("ts")


def replay(scenario: int, minutes: int = 90, end: datetime | None = None, max_botnet: int = 400,
           max_normal: int = 600) -> tuple[list[dict], list[dict], dict]:
    """Returns (devices_needed, events, info). Events carry ground-truth labels."""
    sl = pick_slice(scenario, minutes, max_botnet, max_normal)
    if sl.empty:
        raise ValueError(f"scenario {scenario} has no labelled flows")
    end = end or datetime.now(timezone.utc).replace(microsecond=0)
    shift = end - sl["ts"].max().to_pydatetime().replace(tzinfo=timezone.utc)
    hosts = {}
    for r in sl.itertuples():
        for ip in (r.SrcAddr, r.DstAddr):
            if _is_local(ip) and ip not in hosts:
                hosts[ip] = {"hostname": f"ctu{scenario}-" + ip.replace(".", "-"), "ip_address": ip,
                             "mac_address": _mac(f"{scenario}-{ip}"), "os_version": "Windows XP SP2 (CTU-13)",
                             "device_type": "workstation", "criticality": 2}
    events = []
    for r in sl.itertuples():
        local = r.SrcAddr if _is_local(r.SrcAddr) else r.DstAddr
        if not _is_local(local):
            continue
        ts = r.ts.to_pydatetime().replace(tzinfo=timezone.utc) + shift
        scan_like = r.pkts <= 2 and r.bytes_sent < 120 and r.dport not in (53, 80, 443)
        cat = "port_scan" if scan_like else "data_transfer"
        events.append({
            "ts": ts, "category": cat, "event_source": "ctu13", "user_id": None, "host_ip": local, "source_ip": r.SrcAddr,
            "crit": 2,
            "sub": {"destination_ip": r.DstAddr if _valid_ip(r.DstAddr) else None, "destination_port": int(r.dport) % 65536,
                    "protocol": str(r.Proto)[:10], "bytes_sent": int(r.bytes_sent), "bytes_received": int(r.bytes_received),
                    "duration_s": float(r.dur), "packets": int(r.pkts)},
            "raw": {"source": f"CTU-13 scenario {scenario} ({SCENARIOS.get(scenario, '?')})",
                    "message": f"{r.Proto} {r.SrcAddr}:{r.Sport} -> {r.DstAddr}:{r.Dport} pkts={r.pkts} bytes={int(r.bytes_sent + r.bytes_received)}",
                    "ctu_label": r.Label, "original_start_time": str(r.StartTime)},
            "label": {"attack": r.kind == "botnet", "scenario": f"CTU13-{scenario}" if r.kind == "botnet" else None,
                      "stage": "botnet" if r.kind == "botnet" else None, "source": "ctu13"},
        })
    info = {"scenario": scenario, "botnet_family": SCENARIOS.get(scenario), "events": len(events),
            "botnet_events": sum(e["label"]["attack"] for e in events), "hosts": len(hosts),
            "time_shift_days": round(shift.total_seconds() / 86400, 1)}
    return list(hosts.values()), events, info


def _valid_ip(v) -> bool:
    try:
        ipaddress.ip_address(str(v))
        return True
    except ValueError:
        return False
