"""Automation: background correlation scheduler and an optional live
telemetry stream (benign traffic with occasional injected attacks)."""
from __future__ import annotations

import os
import random
import threading
import time
from datetime import datetime, timedelta, timezone

from . import cli, ingest
from .generator import SCENARIOS, Generator, live_batch

STATE = {"auto_correlate_seconds": int(os.environ.get("AUTO_CORRELATE_SECONDS", "60")),
         "last_correlation": None, "last_result": None,
         "stream_on": False, "stream_events": 0, "stream_attacks": 0, "last_error": None}
_lock = threading.Lock()
_started = False


def correlate_now() -> dict:
    with _lock:
        res = cli.correlate()
        STATE["last_correlation"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        STATE["last_result"] = res
        return res


def _loop():
    gen = Generator(seed=random.randint(1, 10 ** 6))
    last = 0.0
    while True:
        try:
            if STATE["stream_on"]:
                now = datetime.now(timezone.utc).replace(microsecond=0)
                ev = live_batch(gen, now, n=random.randint(3, 8))
                if random.random() < 0.08:          # occasional attack
                    ev += gen.attack(random.choice(SCENARIOS), now - timedelta(minutes=40))
                    STATE["stream_attacks"] += 1
                ingest.ingest_events(ev, use_history=True)
                STATE["stream_events"] += len(ev)
            if time.time() - last >= STATE["auto_correlate_seconds"]:
                correlate_now()
                last = time.time()
            STATE["last_error"] = None
        except Exception as e:  # keep the loop alive; surface the error in /api/health
            STATE["last_error"] = str(e).splitlines()[0][:200]
        time.sleep(10)


def start() -> None:
    global _started
    if not _started and os.environ.get("DISABLE_AUTOMATION") != "1":
        threading.Thread(target=_loop, daemon=True, name="automation").start()
        _started = True
