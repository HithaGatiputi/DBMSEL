"""Network-flow anomaly model trained on REAL traffic (CIC-IDS2017) and
tested cross-dataset on REAL botnet traffic (CTU-13).

Only features that all three sources can supply are used, so the same model
scores CIC-IDS2017 flows, CTU-13 NetFlow records and this system's own
network events:
    destination port, duration, bytes sent, bytes received, packets.
Isolation Forest (fit on benign flows only) is blended with a supervised
XGBoost classifier, exactly like the behaviour model in ml.py.
"""
from __future__ import annotations

import glob
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (average_precision_score, precision_score, recall_score, roc_auc_score)
from xgboost import XGBClassifier

from . import config

CIC_DIR = config.DATA_DIR / "raw" / "cicids2017"
MODEL_FILE = config.MODEL_DIR / "flow_detector.joblib"
METRICS_FILE = config.MODEL_DIR / "flow_metrics.json"
CIC_COLS = {"Destination Port": "dst_port", "Flow Duration": "duration_us", "Total Fwd Packets": "fwd_pkts",
            "Total Backward Packets": "bwd_pkts", "Total Length of Fwd Packets": "bytes_sent",
            "Total Length of Bwd Packets": "bytes_received", "Label": "label"}

PORT_GROUPS = {"web": {80, 443, 8080, 8443}, "remote": {21, 22, 23, 3389}, "mail": {25, 465, 587, 110, 143, 993},
               "dns": {53}, "irc": {6667, 6668, 6669}, "smb": {135, 137, 138, 139, 445}}
FEATURE_NAMES = (["log_duration", "log_bytes_sent", "log_bytes_received", "log_packets", "log_bytes_per_pkt",
                  "recv_sent_ratio", "zero_payload"] + [f"port_{g}" for g in PORT_GROUPS] + ["port_high", "port_other"])


def features(dst_port, duration_s, bytes_sent, bytes_received, packets) -> np.ndarray:
    """Vectorised feature builder (inputs are array-likes of equal length)."""
    port = np.asarray(dst_port, dtype=float)
    dur = np.clip(np.asarray(duration_s, dtype=float), 0, None)
    bs = np.clip(np.asarray(bytes_sent, dtype=float), 0, None)
    br = np.clip(np.asarray(bytes_received, dtype=float), 0, None)
    pk = np.clip(np.asarray(packets, dtype=float), 1, None)
    cols = [np.log1p(dur), np.log1p(bs), np.log1p(br), np.log1p(pk), np.log1p((bs + br) / pk),
            np.log1p(br) - np.log1p(bs), ((bs + br) == 0).astype(float)]
    known = np.zeros(len(port), dtype=bool)
    for ports in PORT_GROUPS.values():
        m = np.isin(port, list(ports))
        cols.append(m.astype(float))
        known |= m
    high = (port > 1024) & ~known
    cols += [high.astype(float), (~known & ~high).astype(float)]
    return np.column_stack(cols)


def load_cic(max_benign_per_file: int = 60000, seed: int = 0) -> pd.DataFrame:
    files = sorted(glob.glob(str(CIC_DIR / "*.csv")))
    if not files:
        raise FileNotFoundError(f"CIC-IDS2017 CSVs not found in {CIC_DIR}")
    parts = []
    for f in files:
        df = pd.read_csv(f, skipinitialspace=True, encoding="latin-1",
                         usecols=lambda c: c.strip() in CIC_COLS)
        df.columns = [CIC_COLS[c.strip()] for c in df.columns]
        df["label"] = df["label"].str.replace("�", "-").str.replace("ï¿½", "-").str.strip()
        df = df[df["duration_us"] >= 0]
        ben = df[df["label"] == "BENIGN"]
        att = df[df["label"] != "BENIGN"]
        ben = ben.sample(n=min(max_benign_per_file, len(ben)), random_state=seed)
        att = pd.concat([g.sample(n=min(len(g), 25000), random_state=seed) for _, g in att.groupby("label")]
                        or [att])
        part = pd.concat([ben, att])
        part["day"] = Path(f).name.split("-")[0]
        parts.append(part)
    df = pd.concat(parts, ignore_index=True)
    df["y"] = (df["label"] != "BENIGN").astype(int)
    return df


def cic_matrix(df: pd.DataFrame) -> np.ndarray:
    return features(df["dst_port"], df["duration_us"] / 1e6, df["bytes_sent"], df["bytes_received"],
                    df["fwd_pkts"] + df["bwd_pkts"])


class FlowDetector:
    def __init__(self, iso, xgb, lo, hi):
        self.iso, self.xgb, self.lo, self.hi = iso, xgb, lo, hi

    def components(self, X):
        raw = -self.iso.score_samples(X)
        return np.clip((raw - self.lo) / (self.hi - self.lo + 1e-9), 0, 1), self.xgb.predict_proba(X)[:, 1]

    def score(self, X) -> np.ndarray:
        if len(X) == 0:
            return np.array([])
        iso_n, p = self.components(X)
        return np.round(0.25 * iso_n + 0.75 * p, 3)


def _metrics(y, s, thr=0.5) -> dict:
    pred = (s >= thr).astype(int)
    return {"n": int(len(y)), "attacks": int(y.sum()),
            "roc_auc": round(float(roc_auc_score(y, s)), 4) if 0 < y.sum() < len(y) else None,
            "avg_precision": round(float(average_precision_score(y, s)), 4) if y.sum() else None,
            "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y, pred, zero_division=0)), 4)}


def _fit(Xtr, ytr) -> FlowDetector:
    iso = IsolationForest(n_estimators=200, max_samples=4096, random_state=0, n_jobs=-1).fit(Xtr[ytr == 0])
    raw = -iso.score_samples(Xtr[ytr == 0])
    lo, hi = float(np.percentile(raw, 5)), float(np.percentile(raw, 99.5))
    xgb = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, tree_method="hist", n_jobs=-1,
                        scale_pos_weight=max(1.0, (ytr == 0).sum() / max(1, (ytr == 1).sum())),
                        eval_metric="logloss", random_state=0).fit(Xtr, ytr)
    return FlowDetector(iso, xgb, lo, hi)


def train() -> dict:
    df = load_cic()
    X, y = cic_matrix(df), df["y"].to_numpy()
    rng = np.random.default_rng(0)
    test_mask = rng.random(len(df)) < 0.3

    # 1) random hold-out on CIC-IDS2017
    det = _fit(X[~test_mask], y[~test_mask])
    s = det.score(X[test_mask])
    m = {"cic_holdout": _metrics(y[test_mask], s)}
    per = {}
    te = df[test_mask].assign(score=s)
    for lab, g in te[te["y"] == 1].groupby("label"):
        per[lab] = {"n": int(len(g)), "detected_at_0.5": round(float((g["score"] >= 0.5).mean()), 3)}
    m["cic_recall_by_attack"] = dict(sorted(per.items(), key=lambda kv: -kv[1]["n"]))
    m["cic_false_positive_rate"] = round(float((te[te["y"] == 0]["score"] >= 0.5).mean()), 4)

    # 2) leave-one-day-out: train without Friday, test on Friday (unseen DDoS/PortScan/Bot day)
    fri = (df["day"] == "Friday").to_numpy()
    det_lodo = _fit(X[~fri], y[~fri])
    m["cic_unseen_day_friday"] = _metrics(y[fri], det_lodo.score(X[fri]))

    # 3) pure cross-dataset transfer: CIC-only model on all CTU-13 scenarios
    cic_only = _fit(X, y)
    final, sources = cic_only, "CIC-IDS2017"
    try:
        from . import ctu13
        Xc, yc, sc = ctu13.labelled_sample(with_scenario=True)
        m["ctu13_cross_dataset"] = _metrics(yc, cic_only.score(Xc))
        # 4) scenario-wise split: train on CIC + 10 CTU-13 scenarios, test on the
        #    3 held-out captures (different infected machines and botnet families)
        held = np.isin(sc, ctu13.HELDOUT)
        final = _fit(np.vstack([X, Xc[~held]]), np.concatenate([y, yc[~held]]))
        m["ctu13_heldout_scenarios"] = {**_metrics(yc[held], final.score(Xc[held])),
                                         "scenarios": list(ctu13.HELDOUT)}
        sources = f"CIC-IDS2017 + CTU-13 scenarios {sorted(set(sc[~held].tolist()))}"
        m["ctu13_training_rows"] = int((~held).sum())
    except FileNotFoundError as e:
        m["ctu13_cross_dataset"] = {"skipped": str(e)}

    m.update({"trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "training_rows": int(len(df)), "attack_rows": int(y.sum()),
              "features": FEATURE_NAMES,
              "feature_importance": {n: round(float(v), 4) for n, v in sorted(
                  zip(FEATURE_NAMES, final.xgb.feature_importances_), key=lambda t: -t[1])[:8]},
              "dataset": sources + " (real traffic)"})
    config.MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(final, MODEL_FILE)
    METRICS_FILE.write_text(json.dumps(m, indent=2))
    return m


_det: FlowDetector | None = None


def available() -> bool:
    return MODEL_FILE.exists()


def load() -> FlowDetector | None:
    global _det
    if _det is None and MODEL_FILE.exists():
        _det = joblib.load(MODEL_FILE)
    return _det


def metrics() -> dict:
    return json.loads(METRICS_FILE.read_text()) if METRICS_FILE.exists() else {}


# ---- real flow sampler used by the simulator ---------------------------------
_pool: dict[str, pd.DataFrame] | None = None


def flow_pool() -> dict[str, pd.DataFrame] | None:
    """Real CIC-IDS2017 flows grouped by label, cached as a small parquet-free CSV."""
    global _pool
    if _pool is not None:
        return _pool
    cache = config.DATA_DIR / "cic_flow_pool.csv"
    if not cache.exists():
        if not CIC_DIR.exists():
            return None
        df = load_cic(max_benign_per_file=4000)
        df = pd.concat([g.sample(n=min(len(g), 4000), random_state=1) for _, g in df.groupby("label")])
        df.to_csv(cache, index=False)
    df = pd.read_csv(cache)
    _pool = {lab: g.reset_index(drop=True) for lab, g in df.groupby("label")}
    return _pool
