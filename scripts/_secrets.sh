# Sourced by the other scripts. Creates (once) and loads per-machine secrets
# OUTSIDE the project folder, so zipping/sharing the project never leaks them.
SECRETS_DIR="${DBMSEL_SECRETS_DIR:-$HOME/.dbmsel}"
SECRETS_FILE="$SECRETS_DIR/secrets.env"
if [ ! -f "$SECRETS_FILE" ]; then
  mkdir -p "$SECRETS_DIR" && chmod 700 "$SECRETS_DIR"
  ( umask 077
    {
      echo "PG_SUPER_PASSWORD=$(openssl rand -hex 16)"
      echo "PG_APP_PASSWORD=$(openssl rand -hex 16)"
      echo "PG_RO_PASSWORD=$(openssl rand -hex 16)"
      echo "MONGO_ROOT_PASSWORD=$(openssl rand -hex 16)"
      echo "MONGO_APP_PASSWORD=$(openssl rand -hex 16)"
      echo "APP_SECRET=$(openssl rand -hex 32)"
    } > "$SECRETS_FILE" )
  echo "created secrets in $SECRETS_FILE"
fi
set -a; . "$SECRETS_FILE"; set +a
