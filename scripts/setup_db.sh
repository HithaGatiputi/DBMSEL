#!/usr/bin/env bash
# (Re)create the dbmsel database and apply all SQL files in order.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/_secrets.sh"
PGBIN="${PGBIN:-/opt/homebrew/opt/postgresql@16/bin}"
export PGHOST=127.0.0.1 PGPORT="${PGPORT:-5433}" PGUSER="$(whoami)" PGPASSWORD="$PG_SUPER_PASSWORD"

"$PGBIN/psql" -d postgres -q -v ON_ERROR_STOP=1 <<SQL
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='dbmsel' AND pid<>pg_backend_pid();
DROP DATABASE IF EXISTS dbmsel;
CREATE DATABASE dbmsel;
SQL
for f in "$ROOT"/db/0*.sql; do
  echo "applying $(basename "$f")"
  "$PGBIN/psql" -d dbmsel -q -v ON_ERROR_STOP=1 \
     -v app_pw="$PG_APP_PASSWORD" -v ro_pw="$PG_RO_PASSWORD" -f "$f"
done
echo "database ready"
