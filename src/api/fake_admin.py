"""
╔══════════════════════════════════════════════════════════════╗
║  WireDown — Fake Router Admin Panel (Honeypot)               ║
║  Flask Blueprint · Credential capture · Interaction logging  ║
╚══════════════════════════════════════════════════════════════╝

Serves a convincing NetGate Pro R4500 router admin interface.
Every login attempt, page visit, and button click is captured
and streamed to the WireDown monitoring dashboard.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from flask import (
    Blueprint,
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

log = logging.getLogger("wiredown.fake_admin")

# Module-level state (populated by register_admin_panel)
_captured_credentials: list[dict] = []
_access_log: list[dict] = []
_on_credential_captured: Optional[Callable] = None
_on_page_access: Optional[Callable] = None

# Blueprint Definition

fake_admin = Blueprint(
    "fake_admin",
    __name__,
    template_folder="../ui/templates",
)

# Fake device data

# nosonar: intentional honeypot network configuration — all IPs are fake bait data
FAKE_DEVICES = [
    {
        "id": 1, "hostname": "DESKTOP-A1B2C3D", "mac": "A4:83:E7:2F:01:AA",
        "ip": "10.0.0.101", "type": "Ethernet", "status": "online",
        "vendor": "Intel Corporate", "last_seen": "2 min ago", "rx_bytes": "1.2 GB", "tx_bytes": "340 MB",
    },
    {
        "id": 2, "hostname": "iPhone-Sarah", "mac": "F0:18:98:4C:D2:BB",
        "ip": "10.0.0.102", "type": "WiFi (5GHz)", "status": "online",
        "vendor": "Apple Inc.", "last_seen": "Just now", "rx_bytes": "890 MB", "tx_bytes": "120 MB",
    },
    {
        "id": 3, "hostname": "NAS-Synology", "mac": "00:11:32:8A:F5:CC",
        "ip": "10.0.0.10", "type": "Ethernet", "status": "online",
        "vendor": "Synology Inc.", "last_seen": "1 min ago", "rx_bytes": "45.6 GB", "tx_bytes": "12.3 GB",
    },
    {
        "id": 4, "hostname": "Galaxy-S24-Mike", "mac": "B4:F1:DA:77:E3:DD",
        "ip": "10.0.0.103", "type": "WiFi (2.4GHz)", "status": "online",
        "vendor": "Samsung Electronics", "last_seen": "5 min ago", "rx_bytes": "450 MB", "tx_bytes": "89 MB",
    },
    {
        "id": 5, "hostname": "PRINTER-HP-4520", "mac": "3C:D9:2B:11:44:EE",
        "ip": "10.0.0.200", "type": "WiFi (2.4GHz)", "status": "online",
        "vendor": "HP Inc.", "last_seen": "12 min ago", "rx_bytes": "23 MB", "tx_bytes": "156 MB",
    },
    {
        "id": 6, "hostname": "Roku-LivingRoom", "mac": "D8:31:34:5A:22:FF",
        "ip": "10.0.0.104", "type": "WiFi (5GHz)", "status": "online",
        "vendor": "Roku Inc.", "last_seen": "Just now", "rx_bytes": "8.9 GB", "tx_bytes": "45 MB",
    },
    {
        "id": 7, "hostname": "IoT-Gateway-01", "mac": "24:6F:28:AB:CD:11",
        "ip": "10.0.0.205", "type": "WiFi (2.4GHz)", "status": "online",
        "vendor": "Espressif Systems", "last_seen": "30 sec ago", "rx_bytes": "12 MB", "tx_bytes": "8 MB",
    },
    {
        "id": 8, "hostname": "MacBook-Pro-Admin", "mac": "A8:66:7F:C9:88:22",
        "ip": "10.0.0.100", "type": "WiFi (5GHz)", "status": "online",
        "vendor": "Apple Inc.", "last_seen": "3 min ago", "rx_bytes": "3.4 GB", "tx_bytes": "1.1 GB",
    },
    {
        "id": 9, "hostname": "Ring-Doorbell", "mac": "5C:A6:E6:33:DD:33",
        "ip": "10.0.0.206", "type": "WiFi (2.4GHz)", "status": "idle",
        "vendor": "Amazon Technologies", "last_seen": "1 hour ago", "rx_bytes": "670 MB", "tx_bytes": "2.1 GB",
    },
    {
        "id": 10, "hostname": "unknown-device", "mac": "DE:AD:BE:EF:CA:FE",
        "ip": "10.0.0.199", "type": "WiFi (2.4GHz)", "status": "online",
        "vendor": "Unknown", "last_seen": "8 min ago", "rx_bytes": "2.3 GB", "tx_bytes": "4.5 GB",
    },
]

# nosonar: intentional honeypot network configuration — all IPs/subnets are fake bait data
FAKE_ROUTER_CONFIG = {
    "general": {
        "hostname": "NetGate-Pro-R4500",
        "firmware_version": "v3.8.2 Build 20241015",
        "model": "NetGate Pro R4500",
        "serial_number": "NG4500-2024-A8F3E1",
        "uptime": "47 days 12:33:07",
        "timezone": "UTC-5 (Eastern)",
        "ntp_server": "pool.ntp.org",
    },
    "wan": {
        "type": "DHCP",
        "ip": "192.168.1.1",
        "subnet": "255.255.255.0",
        "gateway": "192.168.1.254",
        "dns1": "8.8.8.8",
        "dns2": "8.8.4.4",
        "mac": "00:1A:2B:3C:4D:5E",
        "speed": "100 Mbps",
        "status": "UP",
        "mtu": 1500,
    },
    "lan": {
        "ip": "10.0.0.1",
        "subnet": "255.255.255.0",
        "dhcp_enabled": True,
        "dhcp_start": "10.0.0.100",
        "dhcp_end": "10.0.0.250",
        "lease_time": "24 hours",
        "mac": "00:1A:2B:3C:4D:5F",
        "speed": "1 Gbps",
        "status": "UP",
    },
    "wifi": {
        "ssid": "NetGate-Office",
        "security": "WPA3-Personal",
        "channel": 6,
        "band": "2.4 GHz + 5 GHz",
        "max_clients": 128,
        "connected_clients": 54,
        "hidden": False,
        "mac_filtering": False,
        "power": "High",
    },
    "firewall": {
        "enabled": True,
        "mode": "NAT",
        "dos_protection": True,
        "syn_flood_protection": True,
        "ping_from_wan": False,
        "remote_management": True,
        "remote_management_port": 8443,
        "vpn_passthrough": True,
        "dmz_enabled": False,
        "upnp_enabled": True,
    },
    "security": {
        "admin_username": "admin",
        "remote_access": True,
        "ssh_enabled": True,
        "ssh_port": 22,
        "telnet_enabled": False,
        "auto_update": True,
        "last_update_check": "2024-10-15 03:00:00",
        "log_level": "warning",
    },
}


# Helpers

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log_access(path: str) -> None:
    """Log every page access with IP, path, user-agent."""
    entry = {
        "ip": request.remote_addr,
        "path": path,
        "method": request.method,
        "user_agent": request.headers.get("User-Agent", "Unknown"),
        "timestamp": _now_iso(),
        "referrer": request.headers.get("Referer", ""),
    }
    _access_log.append(entry)
    log.info("Admin access: %s %s from %s", request.method, path, request.remote_addr)

    if _on_page_access:
        try:
            _on_page_access(entry)
        except Exception as exc:
            log.error("Error in on_page_access callback: %s", exc)


# Routes

@fake_admin.route("/", methods=["GET"])
def admin_login_page():
    """Serve the admin login page."""
    _log_access("/")
    return render_template("admin_login.html")


@fake_admin.route("/login", methods=["POST"])
def admin_login():
    """Capture login credentials and redirect to warning."""
    _log_access("/login")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "Unknown")

    cred_entry = {
        "ip": ip,
        "username": username,
        "password": password,
        "user_agent": user_agent,
        "timestamp": _now_iso(),
    }
    _captured_credentials.append(cred_entry)

    log.warning(
        "CREDENTIAL CAPTURED — IP: %s, User: %s, Pass: %s",
        ip, username, password,
    )

    if _on_credential_captured:
        try:
            _on_credential_captured(ip, username, password, user_agent)
        except Exception as exc:
            log.error("Error in on_credential_captured callback: %s", exc)

    session["admin_logged_in"] = True
    session["admin_username"] = username
    
    # Trigger final shutdown sequence
    from app import execute_software_isolation, _resolve_mac_for_ip
    mac = _resolve_mac_for_ip(ip)
    execute_software_isolation(mac, ip)
    
    return render_template("warning.html", user_agent=user_agent, ip_address=ip)


@fake_admin.route("/dashboard", methods=["GET"])
def admin_dashboard():
    """Serve the admin dashboard (requires login)."""
    _log_access("/dashboard")

    if not session.get("admin_logged_in"):
        return redirect(url_for("fake_admin.admin_login_page") + "?error=1")

    username = session.get("admin_username", "admin")
    return render_template("admin_dashboard.html", username=username)


@fake_admin.route("/api/devices", methods=["GET"])
def api_devices():
    """Return fake JSON device list."""
    _log_access("/api/devices")
    return jsonify({
        "status": "success",
        "total": len(FAKE_DEVICES),
        "devices": FAKE_DEVICES,
    })


@fake_admin.route("/api/config", methods=["GET"])
def api_config_get():
    """Return fake router configuration JSON."""
    _log_access("/api/config")
    return jsonify({
        "status": "success",
        "config": FAKE_ROUTER_CONFIG,
    })


@fake_admin.route("/api/config", methods=["POST"])
def api_config_post():
    """Capture any config changes attempted."""
    _log_access("/api/config [POST]")

    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "Unknown")

    try:
        payload = request.get_json(silent=True) or {}
    except Exception:
        payload = {}

    if not payload:
        payload = dict(request.form)

    config_change = {
        "ip": ip,
        "user_agent": user_agent,
        "action": payload.get("action", "unknown"),
        "payload": payload,
        "timestamp": _now_iso(),
    }

    _access_log.append({
        **config_change,
        "path": "/api/config",
        "method": "POST",
        "type": "config_change_attempt",
    })

    log.warning(
        "CONFIG CHANGE ATTEMPT — IP: %s, Action: %s, Payload: %s",
        ip, payload.get("action", "unknown"), payload,
    )
    
    if payload.get("action") == "password_change":
        # Log the password change trap
        log.warning("PASSWORD TRAP TRIGGERED — IP: %s, attempted new password: %s", ip, payload.get("password", ""))

    return jsonify({
        "status": "success",
        "message": "Configuration updated successfully.",
    })

@fake_admin.route("/apply_config", methods=["GET"])
def apply_config():
    """The final shutdown sequence. The attacker lands here after the password trap."""
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "Unknown")
    _log_access("/apply_config")
    
    from app import execute_software_isolation, _resolve_mac_for_ip
    mac = _resolve_mac_for_ip(ip)
    execute_software_isolation(mac, ip)
    
    return render_template("warning.html", user_agent=user_agent, ip_address=ip)


@fake_admin.route("/logout", methods=["GET"])
def admin_logout():
    """Handle logout."""
    _log_access("/logout")
    session.pop("admin_logged_in", None)
    session.pop("admin_username", None)
    return redirect(url_for("fake_admin.admin_login_page"))


# Public API

def get_captured_credentials() -> list[dict]:
    """Return all captured credentials."""
    return list(_captured_credentials)


def get_access_log() -> list[dict]:
    """Return the access log."""
    return list(_access_log)


def register_admin_panel(
    app: Flask,
    on_credential_captured: Optional[Callable] = None,
    on_page_access: Optional[Callable] = None,
) -> None:
    """
    Register the fake admin panel blueprint with a Flask app.

    Parameters# fake router admin panel — captures creds and logs everything  Callback ``on_credential_captured(ip, username, password, user_agent)``
        invoked whenever credentials are submitted.
    on_page_access : callable, optional
        Callback ``on_page_access(access_entry_dict)`` invoked on
        every page access.
    """
    global _on_credential_captured, _on_page_access

    _on_credential_captured = on_credential_captured
    _on_page_access = on_page_access

    app.register_blueprint(fake_admin)
    log.info("Fake NetGate honeypot registered at /")
