"""
WireDown — SQLite Auto-Provisioning Layer
=========================================

Lightweight SQLite-backed persistence for the admin panel.

- File:      backend/wiredown.db  (single-file DB, <1 MB footprint)
- Hashing:   bcrypt (CPU cost = 12)
- Seeding:   idempotent. Creates default admin on first boot.
             If ADMIN_PASSWORD is unset, a strong random password
             is generated and printed *once* to the server log.

Used by `real_admin.py` (the protected admin console at /admin/console).
"""

from __future__ import annotations

import logging
import os
import secrets
import sqlite3
import string
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import bcrypt

log = logging.getLogger("wiredown.db")

# ── Paths & constants ────────────────────────────────────────────────────────
DB_PATH = Path(os.environ.get("WIREDOWN_DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "wiredown.db")))

# Brute-force protection (5 failures within 15 min → 15 min lockout)
LOGIN_FAILURE_THRESHOLD = 5
LOGIN_LOCKOUT_SECONDS = 15 * 60


# ── Connection helpers ──────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    """Open a connection with WAL mode for concurrent reads from the dashboard."""
    conn = sqlite3.connect(DB_PATH, timeout=5.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


@contextmanager
def connection():
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Bcrypt helpers ──────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ── Schema ──────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    created_at    TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    username    TEXT,
    success     INTEGER NOT NULL,
    user_agent  TEXT,
    attempted_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts(ip, attempted_at);

CREATE TABLE IF NOT EXISTS device_registry (
    mac          TEXT PRIMARY KEY,
    ip           TEXT,
    vendor       TEXT,
    hostname     TEXT,
    status       TEXT NOT NULL DEFAULT 'trusted', -- trusted | monitored | threat | isolated
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    notes        TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    actor     TEXT,
    action    TEXT NOT NULL,
    target    TEXT,
    details   TEXT,
    ip        TEXT,
    ts        REAL NOT NULL
);
"""


def init_db() -> None:
    """Create tables if they don't exist. Idempotent."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connection() as conn:
        conn.executescript(SCHEMA)
    log.info("WireDown SQLite initialized at %s", DB_PATH)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Admin seeding ───────────────────────────────────────────────────────────

def _generate_strong_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def seed_default_admin() -> Optional[dict]:
    """
    Idempotent admin auto-provisioning.

    - If no users exist:
        * Use env ADMIN_USERNAME (default 'admin') and ADMIN_PASSWORD.
        * If ADMIN_PASSWORD is unset/empty, generate a strong random password.
        * Print credentials to the log ONCE.
    - If admin user exists:
        * Do nothing (production-safe — never overwrite).

    Returns a dict {username, password, generated: bool} on first-boot creation,
    else None.
    """
    username = (os.environ.get("ADMIN_USERNAME") or "admin").strip()
    raw_pw = os.environ.get("ADMIN_PASSWORD")

    with connection() as conn:
        existing = conn.execute(
            "SELECT id, username FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if existing:
            log.info("Admin user '%s' already exists — skipping seed", username)
            return None

        generated = False
        if not raw_pw or not raw_pw.strip():
            raw_pw = _generate_strong_password()
            generated = True

        pw_hash = hash_password(raw_pw)
        conn.execute(
            "INSERT INTO users(username, password_hash, role, created_at) "
            "VALUES (?, ?, 'admin', ?)",
            (username, pw_hash, _now_iso()),
        )

        # Banner the credentials prominently — admins MUST see this on first boot.
        banner = (
            "\n" + "=" * 68 + "\n"
            "  WireDown — DEFAULT ADMIN PROVISIONED (FIRST BOOT)\n"
            "  -------------------------------------------------\n"
            f"   Username : {username}\n"
            f"   Password : {raw_pw}\n"
            f"   Console  : /admin/console/login\n"
            "  -------------------------------------------------\n"
            "  STORE THIS PASSWORD NOW. It will not be shown again.\n"
            + "=" * 68 + "\n"
        )
        log.warning(banner)
        return {"username": username, "password": raw_pw, "generated": generated}


# ── User operations ─────────────────────────────────────────────────────────

def get_user(username: str) -> Optional[sqlite3.Row]:
    with connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def update_last_login(username: str) -> None:
    with connection() as conn:
        conn.execute(
            "UPDATE users SET last_login_at = ? WHERE username = ?",
            (_now_iso(), username),
        )


# ── Brute-force tracking ────────────────────────────────────────────────────

def record_login_attempt(ip: str, username: str, success: bool, user_agent: str = "") -> None:
    with connection() as conn:
        conn.execute(
            "INSERT INTO login_attempts(ip, username, success, user_agent, attempted_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (ip, username, 1 if success else 0, user_agent, time.time()),
        )


def is_ip_locked_out(ip: str) -> bool:
    """5 failed attempts within the last LOGIN_LOCKOUT_SECONDS → locked."""
    cutoff = time.time() - LOGIN_LOCKOUT_SECONDS
    with connection() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM login_attempts "
            "WHERE ip = ? AND success = 0 AND attempted_at >= ?",
            (ip, cutoff),
        ).fetchone()
    return (row["n"] or 0) >= LOGIN_FAILURE_THRESHOLD


def clear_login_failures(ip: str) -> None:
    """Wipe failed attempts for an IP after a successful login."""
    with connection() as conn:
        conn.execute(
            "DELETE FROM login_attempts WHERE ip = ? AND success = 0", (ip,)
        )


# ── Audit log ───────────────────────────────────────────────────────────────

def audit(actor: Optional[str], action: str, target: str = "", details: str = "", ip: str = "") -> None:
    with connection() as conn:
        conn.execute(
            "INSERT INTO audit_log(actor, action, target, details, ip, ts) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (actor, action, target, details, ip, time.time()),
        )
    # Best-effort live push to the SOC dashboard. We import socketio lazily
    # to avoid an import cycle with app.py and silently no-op if it's not
    # yet wired (e.g. during early startup before app.py finishes loading).
    try:
        from app import socketio  # noqa: WPS433 (intentional late import)
        socketio.emit(
            "audit_event",
            {
                "actor": actor,
                "action": action,
                "target": target,
                "details": details,
                "ip": ip,
                "ts": time.time(),
            },
            namespace="/ws/frontend",
        )
    except Exception:
        # Logging here would spam during boot — keep silent.
        pass


def get_recent_audit(limit: int = 100) -> list[dict]:
    with connection() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def purge_stale_login_attempts() -> int:
    """Delete login_attempts older than the brute-force window.

    Called once at process startup so the lockout counter never poisons
    a fresh boot. Returns the number of rows deleted.
    """
    cutoff = time.time() - LOGIN_LOCKOUT_SECONDS
    with connection() as conn:
        cur = conn.execute(
            "DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff,)
        )
        return cur.rowcount or 0


# ── Device registry persistence (used by app.py for warm-restart memory) ────

def upsert_device(mac: str, ip: str = "", vendor: str = "Unknown",
                  hostname: str = "", status: str = "trusted") -> None:
    now = _now_iso()
    with connection() as conn:
        existing = conn.execute(
            "SELECT mac FROM device_registry WHERE mac = ?", (mac,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE device_registry "
                "SET ip = COALESCE(NULLIF(?, ''), ip), "
                "    vendor = COALESCE(NULLIF(?, ''), vendor), "
                "    hostname = COALESCE(NULLIF(?, ''), hostname), "
                "    status = ?, "
                "    last_seen = ? "
                "WHERE mac = ?",
                (ip, vendor, hostname, status, now, mac),
            )
        else:
            conn.execute(
                "INSERT INTO device_registry(mac, ip, vendor, hostname, status, "
                "first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (mac, ip, vendor, hostname, status, now, now),
            )


def get_all_devices() -> list[dict]:
    with connection() as conn:
        rows = conn.execute(
            "SELECT * FROM device_registry ORDER BY last_seen DESC"
        ).fetchall()
    return [dict(r) for r in rows]
