"""Streaming feature extraction shared by model training and ingestion.

Events must be fed in timestamp order. Sliding windows are kept per
source IP / user so that bursts (brute force, port scans) become
visible to the models.
"""
from __future__ import annotations

import ipaddress
import math
from collections import defaultdict, deque
from datetime import datetime, timedelta

from zoneinfo import ZoneInfo

from .config import ORG_TIMEZONE

_ORG_TZ = ZoneInfo(ORG_TIMEZONE)

CATEGORIES = [
    "failed_login", "successful_login", "new_device_access",
    "file_access", "confidential_file_access", "privilege_escalation",
    "data_transfer", "port_scan", "malware_alert",
]

FEATURE_NAMES = (
    ["hour_sin", "hour_cos", "off_hours"]
    + [f"cat_{c}" for c in CATEGORIES]
    + ["fails_ip_10m", "fails_user_10m", "distinct_ports_ip_5m",
       "log_bytes_out", "log_bytes_in", "external_src", "external_dst",
       "is_sensitive", "user_events_5m", "device_criticality"]
)


def is_external(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


class FeatureBuilder:
    def __init__(self) -> None:
        self.fail_ip: dict[str, deque] = defaultdict(deque)
        self.fail_user: dict[int, deque] = defaultdict(deque)
        self.ports_ip: dict[str, deque] = defaultdict(deque)
        self.user_ev: dict[int, deque] = defaultdict(deque)

    @staticmethod
    def _prune(dq: deque, now: datetime, span: timedelta) -> None:
        while dq and now - dq[0][0] > span:
            dq.popleft()

    def observe(self, e: dict) -> None:
        """Update windows with an event (no vector returned)."""
        ts, ip, uid = e["ts"], e.get("source_ip"), e.get("user_id")
        if e["category"] == "failed_login":
            if ip:
                self.fail_ip[ip].append((ts, 1))
            if uid:
                self.fail_user[uid].append((ts, 1))
        port = (e.get("sub") or {}).get("destination_port")
        if e["category"] in ("port_scan", "data_transfer") and ip and port is not None:
            self.ports_ip[ip].append((ts, port))
        if uid:
            self.user_ev[uid].append((ts, 1))

    def vector(self, e: dict) -> list[float]:
        ts, ip, uid = e["ts"], e.get("source_ip"), e.get("user_id")
        sub = e.get("sub") or {}
        self.observe(e)
        fi = fu = dp = ue = 0
        if ip:
            self._prune(self.fail_ip[ip], ts, timedelta(minutes=10))
            fi = len(self.fail_ip[ip])
            self._prune(self.ports_ip[ip], ts, timedelta(minutes=5))
            dp = len({p for _, p in self.ports_ip[ip]})
        if uid:
            self._prune(self.fail_user[uid], ts, timedelta(minutes=10))
            fu = len(self.fail_user[uid])
            self._prune(self.user_ev[uid], ts, timedelta(minutes=5))
            ue = len(self.user_ev[uid])
        lt = ts.astimezone(_ORG_TZ)                       # organisation local time
        h = lt.hour + lt.minute / 60.0
        off = 1.0 if (lt.hour < 6 or lt.hour >= 22) else 0.0
        onehot = [1.0 if e["category"] == c else 0.0 for c in CATEGORIES]
        return [
            math.sin(2 * math.pi * h / 24), math.cos(2 * math.pi * h / 24), off,
            *onehot,
            float(fi), float(fu), float(dp),
            math.log1p(sub.get("bytes_sent", 0) or 0),
            math.log1p(sub.get("bytes_received", 0) or 0),
            1.0 if is_external(ip) else 0.0,
            1.0 if is_external(sub.get("destination_ip")) else 0.0,
            1.0 if sub.get("is_sensitive") else 0.0,
            float(ue), float(e.get("crit", 2)),
        ]
