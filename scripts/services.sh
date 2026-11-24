#!/usr/bin/env bash
# Start / stop project-local PostgreSQL (port 5433) and MongoDB (port 27018),
# both with password authentication. Usage: scripts/services.sh start|stop|status
set -euo pipefail
export LC_ALL="${LC_ALL:-en_US.UTF-8}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/_secrets.sh"
PGBIN="${PGBIN:-/opt/homebrew/opt/postgresql@16/bin}"
PGDATA="$ROOT/.pgdata"
MONGODATA="$ROOT/.mongodata"
export PGPORT="${PGPORT:-5433}" MONGOPORT="${MONGOPORT:-27018}"
PY="$ROOT/.venv/bin/python"
SUPER="$(whoami)"

secure_pg() {   # migrate an old trust-auth cluster to scram-sha-256
  if grep -qE '^[^#].*[[:space:]]trust[[:space:]]*$' "$PGDATA/pg_hba.conf"; then
    "$PGBIN/psql" -h /tmp -p "$PGPORT" -U "$SUPER" -d postgres -qc \
      "ALTER ROLE \"$SUPER\" PASSWORD '$PG_SUPER_PASSWORD'"
    sed -i.bak -E 's/[[:space:]]trust[[:space:]]*$/ scram-sha-256/' "$PGDATA/pg_hba.conf" && rm -f "$PGDATA/pg_hba.conf.bak"
    "$PGBIN/pg_ctl" -D "$PGDATA" reload >/dev/null
    echo "postgres switched from trust to scram-sha-256 password authentication"
  fi
}

case "${1:-start}" in
  start)
    if [ ! -d "$PGDATA" ]; then
      pw="$(mktemp)"; printf '%s\n' "$PG_SUPER_PASSWORD" > "$pw"
      "$PGBIN/initdb" -D "$PGDATA" -U "$SUPER" -A scram-sha-256 --pwfile="$pw" -E UTF8 >/dev/null
      rm -f "$pw"
    fi
    "$PGBIN/pg_ctl" -D "$PGDATA" status >/dev/null 2>&1 || \
      "$PGBIN/pg_ctl" -D "$PGDATA" -o "-p $PGPORT -k /tmp" -l "$ROOT/.pg.log" -w start >/dev/null
    secure_pg
    echo "postgres up on :$PGPORT (password auth)"
    if command -v mongod >/dev/null; then
      mkdir -p "$MONGODATA"
      if ! (echo > /dev/tcp/127.0.0.1/$MONGOPORT) 2>/dev/null; then
        nohup mongod --auth --dbpath "$MONGODATA" --port "$MONGOPORT" --bind_ip 127.0.0.1 \
               >"$ROOT/.mongo.log" 2>&1 &
        for _ in $(seq 1 15); do (echo > /dev/tcp/127.0.0.1/$MONGOPORT) 2>/dev/null && break; sleep 1; done
      fi
      "$PY" -I "$ROOT/scripts/mongo_admin.py" init
      echo "mongodb up on :$MONGOPORT (auth enabled)"
    else
      echo "mongod not found - raw logs will fall back to PostgreSQL JSONB"
    fi
    ;;
  stop)
    "$PGBIN/pg_ctl" -D "$PGDATA" stop -m fast || true
    (echo > /dev/tcp/127.0.0.1/$MONGOPORT) 2>/dev/null && "$PY" -I "$ROOT/scripts/mongo_admin.py" shutdown || true
    ;;
  status)
    "$PGBIN/pg_ctl" -D "$PGDATA" status || true
    (echo > /dev/tcp/127.0.0.1/$MONGOPORT) 2>/dev/null && echo "mongodb up" || echo "mongodb down"
    ;;
esac
