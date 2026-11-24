#!/usr/bin/env bash
# Open the project's databases with the right credentials.
#
#   scripts/db.sh psql      PostgreSQL as the owner (superuser)  - full access
#   scripts/db.sh app       PostgreSQL as dbmsel_app             - what the web app uses
#   scripts/db.sh ro        PostgreSQL as dbmsel_ro              - read-only role used by the AI
#   scripts/db.sh mongo     MongoDB shell (mongosh) on the raw-log database
#   scripts/db.sh info      connection details for GUI tools (pgAdmin, DBeaver, Compass)
#   scripts/db.sh sql "SELECT ..."   run one SQL statement as the owner and print the result
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/_secrets.sh"
PGBIN="${PGBIN:-/opt/homebrew/opt/postgresql@16/bin}"
export PGHOST=127.0.0.1 PGPORT="${PGPORT:-5433}" PGDATABASE=dbmsel
SUPER="$(whoami)"
MONGO_APP_URI="mongodb://dbmsel_app:${MONGO_APP_PASSWORD}@127.0.0.1:${MONGOPORT:-27018}/dbmsel_raw?authSource=dbmsel_raw"

case "${1:-info}" in
  psql) PGUSER="$SUPER" PGPASSWORD="$PG_SUPER_PASSWORD" exec "$PGBIN/psql" ;;
  app)  PGUSER=dbmsel_app PGPASSWORD="$PG_APP_PASSWORD" exec "$PGBIN/psql" ;;
  ro)   PGUSER=dbmsel_ro  PGPASSWORD="$PG_RO_PASSWORD"  exec "$PGBIN/psql" ;;
  sql)  shift; PGUSER="$SUPER" PGPASSWORD="$PG_SUPER_PASSWORD" exec "$PGBIN/psql" -X -P pager=off -c "$*" ;;
  mongo)
    command -v mongosh >/dev/null || { echo "mongosh not installed: brew install mongosh"; exit 1; }
    exec mongosh --quiet "$MONGO_APP_URI" ;;
  info)
    cat <<EOF
PostgreSQL  (pgAdmin / DBeaver / TablePlus)
  host 127.0.0.1   port ${PGPORT}   database dbmsel
  owner        user ${SUPER}       password ${PG_SUPER_PASSWORD}
  application  user dbmsel_app     password ${PG_APP_PASSWORD}
  read-only    user dbmsel_ro      password ${PG_RO_PASSWORD}

MongoDB  (MongoDB Compass: paste this connection string)
  ${MONGO_APP_URI}
  database dbmsel_raw   collection raw_logs

These passwords are random for this Mac and live in ${SECRETS_FILE}.
Do not paste them into slides, reports or chats.
EOF
    ;;
  *) sed -n '2,10p' "$0"; exit 1 ;;
esac
