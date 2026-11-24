"""Load the raw public datasets into PostgreSQL so they can be browsed and queried.

Creates a separate schema `datasets` (the application never writes to it):
  datasets.cicids2017_flows  all 8 CIC-IDS2017 CSVs, key columns + label + day   (~2.8 M rows)
  datasets.ctu13_flows       CTU-13 NetFlow for the chosen scenarios           (default: 5, 11, 12)
  datasets.ctu13_scenarios   one row per CTU-13 scenario (botnet family, file)

Uses PostgreSQL COPY (bulk load), so it takes about a minute.

    .venv/bin/python -I scripts/import_datasets.py              # CIC + CTU 5,11,12
    .venv/bin/python -I scripts/import_datasets.py --ctu all    # every CTU-13 scenario (~20 M rows, slow)
"""
from __future__ import annotations

import argparse
import csv
import getpass
import glob
import io
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import psycopg  # noqa: E402

from app import config, ctu13  # noqa: E402

DSN = (f"postgresql://{getpass.getuser()}:{os.environ['PG_SUPER_PASSWORD']}"
       f"@{config.PG_HOST}:{config.PG_PORT}/{config.PG_DB}")
CIC_DIR = config.DATA_DIR / "raw" / "cicids2017"
CIC_COLS = ["Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s", "Label"]

DDL = """
CREATE SCHEMA IF NOT EXISTS datasets;
DROP TABLE IF EXISTS datasets.cicids2017_flows, datasets.ctu13_flows, datasets.ctu13_scenarios;
CREATE TABLE datasets.cicids2017_flows (
    flow_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    day              TEXT NOT NULL,          -- capture day / file
    destination_port INT,
    duration_us      BIGINT,                 -- microseconds
    fwd_packets      INT,
    bwd_packets      INT,
    bytes_sent       BIGINT,
    bytes_received   BIGINT,
    flow_bytes_per_s DOUBLE PRECISION,
    label            TEXT NOT NULL,          -- BENIGN or attack name
    is_attack        BOOLEAN GENERATED ALWAYS AS (label <> 'BENIGN') STORED
);
CREATE TABLE datasets.ctu13_scenarios (
    scenario      INT PRIMARY KEY,
    botnet_family TEXT NOT NULL,
    source_file   TEXT NOT NULL
);
CREATE TABLE datasets.ctu13_flows (
    flow_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scenario    INT NOT NULL REFERENCES datasets.ctu13_scenarios(scenario),
    start_time  TIMESTAMP,
    duration_s  DOUBLE PRECISION,
    protocol    TEXT,
    src_addr    TEXT,
    src_port    TEXT,
    direction   TEXT,
    dst_addr    TEXT,
    dst_port    TEXT,
    state       TEXT,
    total_pkts  BIGINT,
    total_bytes BIGINT,
    src_bytes   BIGINT,
    label       TEXT NOT NULL,
    kind        TEXT GENERATED ALWAYS AS (CASE WHEN label LIKE '%Botnet%' THEN 'botnet'
                                              WHEN label LIKE '%Normal%' THEN 'normal' ELSE 'background' END) STORED
);
"""
INDEXES = """
CREATE INDEX ON datasets.cicids2017_flows (label);
CREATE INDEX ON datasets.cicids2017_flows (day);
CREATE INDEX ON datasets.ctu13_flows (scenario, kind);
CREATE INDEX ON datasets.ctu13_flows (src_addr);
GRANT USAGE ON SCHEMA datasets TO dbmsel_ro, dbmsel_app;
GRANT SELECT ON ALL TABLES IN SCHEMA datasets TO dbmsel_ro, dbmsel_app;
ANALYZE datasets.cicids2017_flows; ANALYZE datasets.ctu13_flows;
"""


def num(v, cast=int):
    try:
        return cast(float(v))
    except (TypeError, ValueError):
        return None


def load_cic(cur):
    files = sorted(glob.glob(str(CIC_DIR / "*.csv")))
    if not files:
        print("CIC-IDS2017 not found, skipped"); return 0
    total = 0
    for f in files:
        day = Path(f).name.split(".pcap")[0]
        with open(f, encoding="latin-1", newline="") as fh, cur.copy(
                "COPY datasets.cicids2017_flows (day, destination_port, duration_us, fwd_packets, bwd_packets, "
                "bytes_sent, bytes_received, flow_bytes_per_s, label) FROM STDIN") as cp:
            rd = csv.reader(fh)
            hdr = [h.strip() for h in next(rd)]
            idx = [hdr.index(c) for c in CIC_COLS]
            n = 0
            for row in rd:
                if len(row) < len(hdr):
                    continue
                v = [row[i].strip() for i in idx]
                fbs = num(v[6], float)
                if fbs is not None and fbs != fbs or fbs in (float("inf"), float("-inf")):
                    fbs = None                              # CIC has NaN / Infinity values
                label = v[7].replace("�", "-").replace("ï¿½", "-")
                cp.write_row((day, num(v[0]), num(v[1]), num(v[2]), num(v[3]), num(v[4]), num(v[5]), fbs, label))
                n += 1
        total += n
        print(f"  CIC-IDS2017 {day}: {n:,} flows")
    return total


def load_ctu(cur, scenarios):
    files = ctu13.files()
    cur.executemany("INSERT INTO datasets.ctu13_scenarios VALUES (%s,%s,%s)",
                    [(s, ctu13.SCENARIOS.get(s, "?"), files[s].name) for s in files])
    total = 0
    for s in scenarios:
        n = 0
        with open(files[s], newline="") as fh, cur.copy(
                "COPY datasets.ctu13_flows (scenario, start_time, duration_s, protocol, src_addr, src_port, direction, "
                "dst_addr, dst_port, state, total_pkts, total_bytes, src_bytes, label) FROM STDIN") as cp:
            rd = csv.reader(fh)
            next(rd)
            for r in rd:
                if len(r) < 15:
                    continue
                cp.write_row((s, r[0].replace("/", "-") or None, num(r[1], float), r[2], r[3], r[4], r[5].strip(),
                              r[6], r[7], r[8], num(r[11]), num(r[12]), num(r[13]), r[14]))
                n += 1
        total += n
        print(f"  CTU-13 scenario {s} ({ctu13.SCENARIOS.get(s)}): {n:,} flows")
    return total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ctu", default="5,11,12", help="comma list of scenarios, or 'all'")
    a = ap.parse_args()
    scen = sorted(ctu13.files()) if a.ctu == "all" else [int(x) for x in a.ctu.split(",")]
    t = time.time()
    with psycopg.connect(DSN) as c, c.cursor() as cur:
        cur.execute(DDL)
        n1 = load_cic(cur)
        n2 = load_ctu(cur, scen)
        cur.execute(INDEXES)
        c.commit()
    print(f"loaded {n1:,} CIC-IDS2017 + {n2:,} CTU-13 flows into schema 'datasets' in {time.time() - t:.0f}s")


if __name__ == "__main__":
    main()
