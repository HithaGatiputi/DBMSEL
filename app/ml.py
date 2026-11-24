"""Anomaly detection: Isolation Forest (unsupervised, trained on benign
traffic only) blended with an XGBoost classifier (supervised on labelled
simulated telemetry). The blended 0-1 score is stored as anomaly_score
*before* the event reaches PostgreSQL, where rules + criticality add on."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, precision_score, recall_score, roc_auc_score
from xgboost import XGBClassifier

from . import config
from .features import FEATURE_NAMES, FeatureBuilder
from .generator import Generator, build_org
import random

MODEL_FILE = config.MODEL_DIR / "detector.joblib"
METRICS_FILE = config.MODEL_DIR / "metrics.json"


def featurize(events: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    fb = FeatureBuilder()
    X = np.array([fb.vector(e) for e in events], dtype=float)
    y = np.array([1 if e["label"].get("attack") else 0 for e in events])
    return X, y


class Detector:
    def __init__(self, iso, xgb, lo, hi):
        self.iso, self.xgb, self.lo, self.hi = iso, xgb, lo, hi

    def components(self, X: np.ndarray):
        raw = -self.iso.score_samples(X)
        iso_n = np.clip((raw - self.lo) / (self.hi - self.lo + 1e-9), 0, 1)
        return iso_n, self.xgb.predict_proba(X)[:, 1]

    def score(self, X: np.ndarray) -> np.ndarray:
        if len(X) == 0:
            return np.array([])
        iso_n, p = self.components(X)
        return np.round(0.35 * iso_n + 0.65 * p, 3)


def train(seed: int = 1001, days: int = 14, n_attacks: int = 30) -> dict:
    """Train on a simulated dataset (different seed from the demo data)."""
    gen = Generator(seed=seed, org=build_org(random.Random(7)))
    events = gen.dataset(days=days, n_attacks=n_attacks)
    X, y = featurize(events)
    cut = int(len(X) * 0.7)           # chronological split
    Xtr, ytr, Xte, yte = X[:cut], y[:cut], X[cut:], y[cut:]
    iso = IsolationForest(n_estimators=200, contamination="auto", random_state=0).fit(Xtr[ytr == 0])
    raw = -iso.score_samples(Xtr[ytr == 0])
    lo, hi = float(np.percentile(raw, 5)), float(np.percentile(raw, 99.5))
    xgb = XGBClassifier(n_estimators=200, max_depth=4, learning_rate=0.1,
                        scale_pos_weight=max(1.0, (ytr == 0).sum() / max(1, (ytr == 1).sum())),
                        eval_metric="logloss", random_state=0).fit(Xtr, ytr)
    det = Detector(iso, xgb, lo, hi)
    iso_n, p = det.components(Xte)
    blend = det.score(Xte)
    pred = (blend >= 0.5).astype(int)
    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "train_events": int(len(Xtr)), "test_events": int(len(Xte)),
        "test_attack_events": int(yte.sum()),
        "roc_auc_isolation_forest": round(float(roc_auc_score(yte, iso_n)), 4),
        "roc_auc_xgboost": round(float(roc_auc_score(yte, p)), 4),
        "roc_auc_blended": round(float(roc_auc_score(yte, blend)), 4),
        "avg_precision_blended": round(float(average_precision_score(yte, blend)), 4),
        "precision_at_0.5": round(float(precision_score(yte, pred, zero_division=0)), 4),
        "recall_at_0.5": round(float(recall_score(yte, pred, zero_division=0)), 4),
        "feature_importance": {n: round(float(v), 4) for n, v in
                               sorted(zip(FEATURE_NAMES, xgb.feature_importances_), key=lambda t: -t[1])[:8]},
        "note": "Simulated login/file/privilege sequences; network background uses real CIC-IDS2017 flows.",
    }
    config.MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(det, MODEL_FILE)
    METRICS_FILE.write_text(json.dumps(metrics, indent=2))
    return metrics


_det: Detector | None = None


def load() -> Detector:
    global _det
    if _det is None:
        if not MODEL_FILE.exists():
            train()
        _det = joblib.load(MODEL_FILE)
    return _det


def metrics() -> dict:
    return json.loads(METRICS_FILE.read_text()) if METRICS_FILE.exists() else {}
