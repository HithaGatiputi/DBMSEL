"""Authentication: scrypt password hashes + HMAC-signed, expiring bearer tokens.
The acting analyst is always taken from the verified token, never from the
request body, so audit attribution cannot be spoofed."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from . import config, db

TOKEN_TTL = 8 * 3600
STAFF_ROLES = ("Analyst", "Admin")
DEFAULT_PASSWORD = os.environ.get("DEMO_PASSWORD", "Rvce@2026")


def _secret() -> bytes:
    """Token-signing key from ~/.dbmsel/secrets.env (outside the project)."""
    key = os.environ.get("APP_SECRET")
    if not key:
        raise RuntimeError("APP_SECRET missing: run scripts/services.sh start once to create ~/.dbmsel/secrets.env")
    return key.encode()


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, s, h = stored.split("$")
        dk = hashlib.scrypt(pw.encode(), salt=base64.b64decode(s), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(dk, base64.b64decode(h))
    except Exception:
        return False


def validate_password_strength(pw: str) -> str | None:
    if len(pw) < 8:
        return "Password must be at least 8 characters"
    if not any(c.isdigit() for c in pw) or not any(c.isalpha() for c in pw):
        return "Password must contain letters and digits"
    return None


def make_token(user: dict) -> str:
    body = json.dumps({"uid": user["user_id"], "role": user["role"], "tv": user["token_version"],
                       "exp": int(time.time()) + TOKEN_TTL}, separators=(",", ":")).encode()
    b = base64.urlsafe_b64encode(body).decode().rstrip("=")
    sig = hmac.new(_secret(), b.encode(), hashlib.sha256).hexdigest()
    return f"{b}.{sig}"


def read_token(token: str) -> dict | None:
    try:
        b, sig = token.split(".")
        if not hmac.compare_digest(sig, hmac.new(_secret(), b.encode(), hashlib.sha256).hexdigest()):
            return None
        data = json.loads(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)))
        if data["exp"] < time.time():
            return None
        return data
    except Exception:
        return None


MAX_FAILS, LOCK_MINUTES = 5, 5


def login(username: str, password: str) -> dict | None:
    """Returns the user row or None. Lockout survives restarts: failures are
    counted from the login_attempts table (since the last success, last 5 min)."""
    fails = db.one("""SELECT COUNT(*) AS n FROM login_attempts
                       WHERE username=%s AND NOT success AND attempted_at > now() - make_interval(mins => %s)
                         AND attempted_at > COALESCE((SELECT MAX(attempted_at) FROM login_attempts
                                                       WHERE username=%s AND success), '-infinity')""",
                   (username, LOCK_MINUTES, username))["n"]
    if fails >= MAX_FAILS:
        db.query("INSERT INTO login_attempts (username, success) VALUES (%s, FALSE)", (username,))
        raise PermissionError(f"Too many failed attempts; try again in {LOCK_MINUTES} minutes")
    row = db.one("""SELECT u.user_id, u.username, u.role, u.department, c.password_hash, c.token_version, c.must_change
                      FROM users u JOIN user_credentials c USING (user_id)
                     WHERE u.username = %s AND u.is_active AND u.role IN ('Analyst','Admin')""", (username,))
    ok = bool(row) and verify_password(password, row["password_hash"])
    db.query("INSERT INTO login_attempts (username, success) VALUES (%s, %s)", (username, ok))
    if not ok:
        return None
    row.pop("password_hash")
    return row


def set_password(user_id: int, new_password: str, must_change: bool) -> None:
    """Store a new hash and bump token_version so every existing session dies."""
    db.query("""INSERT INTO user_credentials (user_id, password_hash, must_change) VALUES (%s,%s,%s)
                ON CONFLICT (user_id) DO UPDATE SET password_hash=EXCLUDED.password_hash,
                    must_change=EXCLUDED.must_change, token_version=user_credentials.token_version+1, updated_at=now()""",
             (user_id, hash_password(new_password), must_change))
