#!/usr/bin/env bash
# One-shot: start DBs, build schema, train model, seed data, run API+dashboard.
set -euo pipefail
cd "$(dirname "$0")/.."
scripts/services.sh start
PY=.venv/bin/python
[ -d .venv ] || { python3 -m venv .venv; .venv/bin/pip install -q -r requirements.txt; }
$PY -m app.cli reset
$PY -m app.cli train >/dev/null
# real-data flow model (CIC-IDS2017 + CTU-13); trained once, ~4 minutes
[ -f models/flow_detector.joblib ] || $PY -m app.cli train-flow >/dev/null
$PY -m app.cli seed
$PY -m app.cli evaluate
echo "Dashboard: http://127.0.0.1:8765"
exec $PY -m app.cli serve
