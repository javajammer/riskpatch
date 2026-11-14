from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from riskpatch.db import audit, now_iso, tx

SCOPES = ("read", "ingest", "operate", "admin")
IMPLIES = {"admin": set(SCOPES), "operate": {"operate", "read"}, "read": {"read"}, "ingest": {"ingest"}}
ROLE_SCOPES = {"viewer": ("read",), "operator": ("read", "operate"), "admin": ("read", "operate", "admin")}
ROLES = tuple(ROLE_SCOPES)
SESSION_HOURS = 8
MIN_PASSWORD_LENGTH = 12
_SCRYPT = {"n": 2**14, "r": 8, "p": 1}


@dataclass(frozen=True)
class Principal:
    token_id: int
    name: str
    workspace_id: int
    scopes: frozenset[str]
    kind: str = "token"

    def has(self, scope: str) -> bool:
        return any(scope in IMPLIES.get(item, {item}) for item in self.scopes)

    @property
    def actor(self) -> str:
        return f"{self.kind}:{self.name}"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def csrf_for(token: str) -> str:
    return hmac.new(hash_token(token).encode(), b"riskpatch-csrf", hashlib.sha256).hexdigest()[:32]


def create_token(conn: sqlite3.Connection, name: str, scopes: list[str], workspace_id: int = 1, expires_at: str | None = None, plaintext: str | None = None) -> str:
    bad = [item for item in scopes if item not in SCOPES]
    if bad or not scopes:
        raise ValueError(f"invalid scope: {bad or 'empty'}")
    token = plaintext or "rp_" + secrets.token_urlsafe(32)
    with tx(conn):
        conn.execute(
            "INSERT INTO api_tokens (workspace_id, name, token_hash, scopes, created_at, expires_at) VALUES (?,?,?,?,?,?)",
            (workspace_id, name, hash_token(token), ",".join(sorted(set(scopes))), now_iso(), expires_at),
        )
        audit(conn, "system", "token.create", name, {"scopes": scopes}, workspace_id)
    return token


def ensure_bootstrap(conn: sqlite3.Connection, token: str) -> None:
    if not token:
        return
    row = conn.execute("SELECT id FROM api_tokens WHERE token_hash=?", (hash_token(token),)).fetchone()
    if row is None:
        create_token(conn, "bootstrap-admin", ["admin"], plaintext=token)


def authenticate(conn: sqlite3.Connection, token: str) -> Principal | None:
    if not token:
        return None
    row = conn.execute("SELECT * FROM api_tokens WHERE token_hash=?", (hash_token(token),)).fetchone()
    if row is None or row["revoked_at"]:
        return None
    if row["expires_at"] and row["expires_at"] <= now_iso():
        return None
    return Principal(row["id"], row["name"], row["workspace_id"], frozenset(row["scopes"].split(",")))


def touch(conn: sqlite3.Connection, token_id: int) -> None:
    try:
        conn.execute("UPDATE api_tokens SET last_used_at=? WHERE id=?", (now_iso(), token_id))
    except sqlite3.OperationalError:
        pass  # a busy writer must not fail a read request


def revoke_token(conn: sqlite3.Connection, name: str) -> int:
    with tx(conn):
        cur = conn.execute("UPDATE api_tokens SET revoked_at=? WHERE name=? AND revoked_at IS NULL", (now_iso(), name))
        audit(conn, "system", "token.revoke", name)
    return cur.rowcount


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, dklen=32, **_SCRYPT)
    return f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), dklen=32, n=int(n), r=int(r), p=int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


_DUMMY_HASH = hash_password("not-a-real-password-used-for-timing")


def check_password_policy(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    return None


def create_user(conn: sqlite3.Connection, username: str, password: str, role: str, created_by: str, workspace_id: int = 1) -> int:
    if role not in ROLE_SCOPES:
        raise ValueError(f"invalid role: {role}")
    problem = check_password_policy(password)
    if problem:
        raise ValueError(problem)
    ts = now_iso()
    with tx(conn):
        cur = conn.execute(
            "INSERT INTO users (workspace_id, username, password_hash, role, created_at, created_by, updated_at) VALUES (?,?,?,?,?,?,?)",
            (workspace_id, username, hash_password(password), role, ts, created_by, ts),
        )
        audit(conn, created_by, "user.create", username, {"role": role}, workspace_id)
    return cur.lastrowid


def ensure_bootstrap_admin(conn: sqlite3.Connection, username: str, password: str) -> bool:
    if not username or not password:
        return False
    if conn.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
        return False
    create_user(conn, username, password, "admin", "system:bootstrap")
    return True


def find_user(conn: sqlite3.Connection, username: str):
    return conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


def authenticate_password(conn: sqlite3.Connection, username: str, password: str):
    row = find_user(conn, username.strip())
    stored = row["password_hash"] if row else _DUMMY_HASH
    ok = verify_password(password, stored)
    if row is None or not ok or row["disabled_at"]:
        return None
    return row


def create_session(conn: sqlite3.Connection, user_id: int) -> str:
    secret = "rpu_" + secrets.token_urlsafe(32)
    ts = now_iso()
    expires = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    with tx(conn):
        conn.execute(
            "INSERT INTO sessions (user_id, secret_hash, created_at, expires_at, last_seen_at) VALUES (?,?,?,?,?)",
            (user_id, hash_token(secret), ts, expires, ts),
        )
        conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (ts, user_id))
    return secret


def authenticate_session(conn: sqlite3.Connection, secret: str) -> Principal | None:
    if not secret:
        return None
    row = conn.execute(
        """SELECT s.id AS session_id, s.expires_at, u.id AS user_id, u.username, u.role, u.workspace_id, u.disabled_at
           FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.secret_hash=?""",
        (hash_token(secret),),
    ).fetchone()
    if row is None or row["disabled_at"] or row["expires_at"] <= now_iso():
        return None
    return Principal(row["user_id"], row["username"], row["workspace_id"], frozenset(ROLE_SCOPES[row["role"]]), kind="user")


def delete_session(conn: sqlite3.Connection, secret: str) -> None:
    with tx(conn):
        conn.execute("DELETE FROM sessions WHERE secret_hash=?", (hash_token(secret),))


def revoke_user_sessions(conn: sqlite3.Connection, user_id: int, keep_secret: str | None = None) -> None:
    keep = hash_token(keep_secret) if keep_secret else ""
    conn.execute("DELETE FROM sessions WHERE user_id=? AND secret_hash<>?", (user_id, keep))


def set_password(conn: sqlite3.Connection, user_id: int, password: str, actor: str, keep_secret: str | None = None) -> None:
    problem = check_password_policy(password)
    if problem:
        raise ValueError(problem)
    with tx(conn):
        conn.execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?", (hash_password(password), now_iso(), user_id))
        revoke_user_sessions(conn, user_id, keep_secret)
        audit(conn, actor, "user.password_reset", str(user_id))


def set_user_role(conn: sqlite3.Connection, user_id: int, role: str, actor: str) -> None:
    if role not in ROLE_SCOPES:
        raise ValueError(f"invalid role: {role}")
    with tx(conn):
        conn.execute("UPDATE users SET role=?, updated_at=? WHERE id=?", (role, now_iso(), user_id))
        audit(conn, actor, "user.role", str(user_id), {"role": role})


def set_user_disabled(conn: sqlite3.Connection, user_id: int, disabled: bool, actor: str) -> None:
    ts = now_iso()
    with tx(conn):
        conn.execute("UPDATE users SET disabled_at=?, updated_at=? WHERE id=?", (ts if disabled else None, ts, user_id))
        if disabled:
            revoke_user_sessions(conn, user_id)
        audit(conn, actor, "user.disable" if disabled else "user.enable", str(user_id))


def active_admin_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled_at IS NULL").fetchone()[0]


def create_user_token(conn: sqlite3.Connection, name: str, scopes: list[str], owner_user_id: int, purpose: str, actor: str, workspace_id: int = 1) -> str:
    token = create_token(conn, name, scopes, workspace_id)
    with tx(conn):
        conn.execute("UPDATE api_tokens SET owner_user_id=?, purpose=? WHERE token_hash=?", (owner_user_id, purpose, hash_token(token)))
        audit(conn, actor, "token.create", name, {"scopes": scopes, "purpose": purpose}, workspace_id)
    return token
