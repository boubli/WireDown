"""
WireDown — Real Admin Console (Hidden Route)
============================================

The actual operator dashboard. Lives behind the hidden path
`/admin/console` so unauthorized scanners hitting `/` only see the
NetGate Pro R4500 honeypot.

Auth:
    - SQLite-backed users table (see db.py).
    - bcrypt password verification.
    - Per-IP brute-force protection (5 fails / 15 min lockout).
    - Flask session-based login persistence.

The admin user is auto-provisioned on first boot by `db.seed_default_admin()`.
"""

from __future__ import annotations

import logging
import os
import time

from flask import (
    Blueprint,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import db

log = logging.getLogger("wiredown.real_admin")

# Hidden route prefix — NOT linked from anywhere on the honeypot.
real_admin = Blueprint(
    "real_admin",
    __name__,
    template_folder="../ui/templates/real_admin",
    static_folder="../ui/static",
    url_prefix="/admin/console",
)


def is_authenticated() -> bool:
    return bool(session.get("wd_admin"))


def _require_auth():
    """Return a redirect to /login if the caller is not authenticated, else None."""
    if not is_authenticated():
        return redirect(url_for("real_admin.login"))
    return None


def _require_auth_json():
    if not is_authenticated():
        return jsonify({"error": "unauthorized"}), 401
    return None


# ── Auth routes ──────────────────────────────────────────────────────────────

@real_admin.route("/", methods=["GET"])
def index():
    return redirect(url_for("real_admin.dashboard") if is_authenticated()
                    else url_for("real_admin.login"))


@real_admin.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr or "0.0.0.0"
    ua = request.headers.get("User-Agent", "")

    if request.method == "POST":
        # Brute-force gate
        if db.is_ip_locked_out(ip):
            log.warning("IP %s is locked out — login denied", ip)
            db.audit(None, "admin_login_locked_out", "", "", ip)
            return render_template(
                "login.html",
                error="Too many failed attempts. Try again in 15 minutes.",
            ), 429

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        row = db.get_user(username)
        ok = bool(row and db.verify_password(password, row["password_hash"]))

        db.record_login_attempt(ip, username, ok, ua)

        if ok:
            session.clear()
            session["wd_admin"] = username
            db.update_last_login(username)
            db.clear_login_failures(ip)
            db.audit(username, "admin_login_success", "", "", ip)
            log.info("Admin '%s' authenticated from %s", username, ip)
            return redirect(url_for("real_admin.dashboard"))

        db.audit(None, "admin_login_failed", username, "", ip)
        log.warning("Failed admin login from %s (user=%s)", ip, username)
        return render_template("login.html", error="Invalid credentials"), 401

    return render_template("login.html")


@real_admin.route("/logout")
def logout():
    user = session.get("wd_admin")
    session.pop("wd_admin", None)
    if user:
        db.audit(user, "admin_logout", "", "", request.remote_addr or "")
    return redirect(url_for("real_admin.login"))


# ── Dashboard ────────────────────────────────────────────────────────────────

@real_admin.route("/dashboard")
def dashboard():
    guard = _require_auth()
    if guard:
        return guard
    return render_template("dashboard.html", admin_username=session["wd_admin"])


# ── REST API (consumed by the dashboard JS) ──────────────────────────────────

@real_admin.route("/api/devices")
def api_devices():
    guard = _require_auth_json()
    if guard:
        return guard
    from app import devices
    return jsonify(list(devices.values()))


@real_admin.route("/api/stats")
def api_stats():
    guard = _require_auth_json()
    if guard:
        return guard
    from app import stats, devices
    return jsonify({
        **stats,
        "active_devices":   sum(1 for d in devices.values() if d.get("status") == "active"),
        "isolated_devices": sum(1 for d in devices.values() if d.get("status") == "isolated"),
        "threat_devices":   sum(1 for d in devices.values() if d.get("status") == "attacker"),
        "uptime_seconds":   round(time.time() - stats["uptime_start"], 1),
        "preview_mode":     os.environ.get("PREVIEW_MODE") == "1",
    })


@real_admin.route("/api/threats")
def api_threats():
    guard = _require_auth_json()
    if guard:
        return guard
    from app import threat_engine
    return jsonify(threat_engine.get_all_threats())


@real_admin.route("/api/isolation-log")
def api_isolation_log():
    guard = _require_auth_json()
    if guard:
        return guard
    from app import isolation_log
    return jsonify(isolation_log[-100:])


@real_admin.route("/api/captured-credentials")
def api_captured_credentials():
    guard = _require_auth_json()
    if guard:
        return guard
    from fake_admin import get_captured_credentials
    return jsonify(get_captured_credentials())


@real_admin.route("/api/honeypot-log")
def api_honeypot_log():
    guard = _require_auth_json()
    if guard:
        return guard
    from fake_admin import get_access_log
    return jsonify(get_access_log()[-200:])


@real_admin.route("/api/audit")
def api_audit():
    guard = _require_auth_json()
    if guard:
        return guard
    return jsonify(db.get_recent_audit(200))


@real_admin.route("/api/whitelist", methods=["GET", "POST"])
def api_whitelist():
    guard = _require_auth_json()
    if guard:
        return guard
    from app import ip_access_control
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        action = payload.get("action")
        ip = payload.get("ip", "")
        if action == "add" and ip:
            ip_access_control.add_to_whitelist(ip)
            db.audit(session["wd_admin"], "whitelist_add", ip, "", request.remote_addr or "")
        elif action == "remove" and ip:
            ip_access_control.remove_from_whitelist(ip)
            db.audit(session["wd_admin"], "whitelist_remove", ip, "", request.remote_addr or "")
        return jsonify({"status": "ok"})
    return jsonify(sorted(ip_access_control.get_whitelist()))


@real_admin.route("/api/blacklist", methods=["GET", "POST"])
def api_blacklist():
    guard = _require_auth_json()
    if guard:
        return guard
    from app import ip_access_control
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        action = payload.get("action")
        ip = payload.get("ip", "")
        if action == "add" and ip:
            ip_access_control.add_to_blacklist(ip)
            try:
                from app import execute_software_isolation, _resolve_mac_for_ip
                mac = _resolve_mac_for_ip(ip)
                execute_software_isolation(mac, ip)
            except Exception as exc:
                log.warning("iptables isolation skipped (%s)", exc)
            db.audit(session["wd_admin"], "blacklist_add", ip, "", request.remote_addr or "")
        elif action == "remove" and ip:
            ip_access_control.remove_from_blacklist(ip)
            db.audit(session["wd_admin"], "blacklist_remove", ip, "", request.remote_addr or "")
        return jsonify({"status": "ok"})
    return jsonify(sorted(ip_access_control.get_blacklist()))


@real_admin.route("/api/firewall")
def api_firewall():
    guard = _require_auth_json()
    if guard:
        return guard
    import firewall
    return jsonify(firewall.status())


@real_admin.route("/api/bridge")
def api_bridge():
    """Status of the wd-engine UDS bridge."""
    guard = _require_auth_json()
    if guard:
        return guard
    try:
        from server import engine_bridge  # type: ignore
        return jsonify({
            "running":         engine_bridge._running,
            "preview_stub":    engine_bridge.preview,
            "uds_path":        str(engine_bridge.uds_path),
            "events_received": engine_bridge.events_received,
            "last_event_ts":   engine_bridge.last_event_ts,
        })
    except Exception as exc:
        return jsonify({"running": False, "error": str(exc)})


# ── 1-Click Update System ────────────────────────────────────────────────────

@real_admin.route("/api/system/update-status", methods=["GET"])
def api_system_update_status():
    guard = _require_auth_json()
    if guard:
        return guard
    import update_service
    return jsonify(update_service.get_status())


@real_admin.route("/api/system/update-check", methods=["POST"])
def api_system_update_check():
    """Force an immediate GitHub releases poll."""
    guard = _require_auth_json()
    if guard:
        return guard
    import update_service
    state = update_service.check_now()
    db.audit(session.get("wd_admin"), "system_update_check", "",
             f"latest={state.get('latest_version')}", request.remote_addr or "")
    return jsonify(state)


@real_admin.route("/api/system/update", methods=["POST"])
def api_system_update():
    """
    Trigger the local proxmox-update.sh. Authenticated operators only.
    The script pulls the latest GitHub release, atomically swaps the
    install tree, and restarts wd-engine + wiredown-api.
    """
    guard = _require_auth_json()
    if guard:
        return guard
    import update_service
    actor = session.get("wd_admin")
    state = update_service.run_update()
    db.audit(actor, "system_update_triggered", "",
             f"to={state.get('latest_version')}", request.remote_addr or "")
    log.warning("1-click update triggered by '%s' from %s",
                actor, request.remote_addr)
    return jsonify(state)


@real_admin.route("/api/whoami")
def api_whoami():
    guard = _require_auth_json()
    if guard:
        return guard
    user = db.get_user(session["wd_admin"])
    if not user:
        return jsonify({"error": "user not found"}), 404
    return jsonify({
        "username":      user["username"],
        "role":          user["role"],
        "created_at":    user["created_at"],
        "last_login_at": user["last_login_at"],
    })
