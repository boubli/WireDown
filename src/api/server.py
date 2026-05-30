"""
WireDown — ASGI Entrypoint
==========================

Supervisor runs:
    uvicorn server:app --host 0.0.0.0 --port 8001 --reload

The core WireDown stack is a Flask + Flask-SocketIO application
(`app.py`). This file wraps that WSGI app with an ASGI adapter so it
can be served by uvicorn on the platform-mandated port 8001.

It also performs:
  - First-boot SQLite initialization
  - Idempotent admin auto-provisioning (db.seed_default_admin)
  - PREVIEW_MODE detection (when running inside the sandboxed
    container that cannot open raw sockets / DNS:53 / iptables)

In PREVIEW_MODE the raw-packet services (DNS sinkhole on :53,
fake SSH on :22, AF_PACKET sniffer, ARP/Guardian) are skipped
gracefully; the dashboard, honeypot, red-screen, REST API,
SQLite store, and WebSockets all remain fully functional.
"""

from __future__ import annotations

import logging
import os
import sys

# Ensure backend/ is on sys.path no matter where uvicorn is launched from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Load .env (lightweight, no external dep) ────────────────────────────────
def _load_env_file() -> None:
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            os.environ.setdefault(key, val)

_load_env_file()

# ── Detect whether we can run privileged network services ────────────────────
def _detect_preview_mode() -> bool:
    if os.environ.get("PREVIEW_MODE", "").strip().lower() in ("1", "true", "yes"):
        return True
    if os.environ.get("PREVIEW_MODE", "").strip().lower() in ("0", "false", "no"):
        return False
    # Sandboxed kubernetes pods on the Emergent preview don't run as root with
    # CAP_NET_RAW. If we're not root, we can't open AF_PACKET sockets.
    return os.geteuid() != 0


PREVIEW_MODE = _detect_preview_mode()
os.environ["PREVIEW_MODE"] = "1" if PREVIEW_MODE else "0"

# When in preview mode, force-bind to 127.0.0.1 so app.py's network_init
# doesn't blow up trying to discover a real LAN interface via scapy.
os.environ.setdefault("FORCE_BIND_IP", "127.0.0.1")
os.environ.setdefault("GUARDIAN_INTERFACE", "lo")
os.environ.setdefault("GUARDIAN_SUBNET", "127.0.0.0/8")

# Configure logging early.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("wiredown.server")

# ── Initialize SQLite + seed admin BEFORE importing app.py ───────────────────
import db as _db  # noqa: E402

_db.init_db()
_purged = _db.purge_stale_login_attempts()
if _purged:
    log.info("Purged %d stale login_attempts rows (>%ds old)",
             _purged, _db.LOGIN_LOCKOUT_SECONDS)
_seed_result = _db.seed_default_admin()
if _seed_result:
    log.info("Admin seeded: %s (auto-generated=%s)",
             _seed_result["username"], _seed_result["generated"])

# ── Import the Flask app (this runs all module-level wiring in app.py) ───────
log.info("WireDown booting | PREVIEW_MODE=%s", PREVIEW_MODE)
from app import app as flask_app, socketio  # noqa: E402

# ── Start the heavy network services if and only if we're privileged ─────────
if not PREVIEW_MODE:
    try:
        from app import (
            dns_sinkhole, port_scan_detector, fake_ssh,
            bandwidth_throttle, guardian_service, arp_scanner,
        )
        dns_sinkhole.start()
        port_scan_detector.start()
        fake_ssh.start()
        bandwidth_throttle.start()
        guardian_service.start()
        arp_scanner.start()
        log.info("All WireDown network services started (privileged mode)")
    except Exception as exc:
        log.error("Failed to start one or more network services: %s", exc)
else:
    log.warning(
        "PREVIEW_MODE active — DNS sinkhole, FakeSSH, GuardianService, and "
        "ARPScanner are STUBBED. Dashboard, honeypot, red-screen, REST and "
        "WebSockets remain fully operational. Seed demo devices/threats so "
        "the UI is populated."
    )
    try:
        from app import devices, register_device, on_threat_signal_mac, _emit_threat_alert  # noqa: E402

        # Seed a representative LAN — one trusted device, one monitored,
        # one flagged threat — so the SOC dashboard isn't empty in preview.
        _seed_devices = [
            ("A4:83:E7:2F:01:AA", "10.0.0.101", "Intel Corporate",     "trusted"),
            ("F0:18:98:4C:D2:BB", "10.0.0.102", "Apple Inc.",          "trusted"),
            ("00:11:32:8A:F5:CC", "10.0.0.10",  "Synology Inc.",       "trusted"),
            ("B4:F1:DA:77:E3:DD", "10.0.0.103", "Samsung Electronics", "trusted"),
            ("24:6F:28:AB:CD:11", "10.0.0.205", "Espressif Systems",   "trusted"),
            ("DE:AD:BE:EF:CA:FE", "10.0.0.199", "Unknown",             "monitored"),
        ]
        for mac, ip, vendor, status in _seed_devices:
            d = register_device(mac, vendor=vendor, ip=ip)
            d["status"] = status
            _db.upsert_device(mac, ip=ip, vendor=vendor, status=status)
    except Exception as exc:
        log.error("Demo data seeder failed: %s", exc)

# ── Start wd-engine UDS bridge (real in production, stub in preview) ─────────
try:
    from wd_engine_bridge import EngineBridge  # noqa: E402
    from app import register_device, on_threat_signal_mac, socketio as _sio  # noqa: E402

    def _dispatch_engine_event(evt: dict) -> None:
        kind = evt.get("kind")
        if kind == "device":
            mac = evt.get("mac", "")
            ip = evt.get("ip", "")
            vendor = evt.get("vendor", "Unknown")
            if mac:
                d = register_device(mac, vendor=vendor, ip=ip)
                if evt.get("hostname"):
                    d["hostname"] = evt["hostname"]
                _db.upsert_device(mac, ip=ip, vendor=vendor, status=d.get("status", "trusted"))
        elif kind == "threat":
            mac = evt.get("mac") or ""
            ip = evt.get("src_ip", "")
            signal_type = evt.get("signal", "")
            details = {"detail": evt.get("detail", ""), "weight": evt.get("weight", 0)}
            if signal_type:
                if not mac:
                    # Resolve from ip if possible (use deterministic synthetic MAC otherwise)
                    from app import _resolve_mac_for_ip  # noqa: E402
                    mac = _resolve_mac_for_ip(ip)
                on_threat_signal_mac(mac, signal_type, details, ip=ip)
        # 'dns' and 'stat' events flow only through Socket.IO for the live UI.

    engine_bridge = EngineBridge(preview=PREVIEW_MODE)
    engine_bridge.start(_dispatch_engine_event, _sio)
except Exception as exc:
    log.error("EngineBridge failed to start: %s", exc)

# ── Start the OUI vendor-table monthly updater (silently no-ops in preview
#    when network egress is restricted) ──────────────────────────────────────
try:
    from oui_updater import start_background as _start_oui  # noqa: E402
    _start_oui()
except Exception as exc:
    log.warning("OUI updater not started: %s", exc)

# ── Start the GitHub release checker for the 1-click Update system ──────────
try:
    from update_service import start_background as _start_update, check_now as _check_update  # noqa: E402
    _start_update()
    # Fire one initial check straight away so the dashboard banner is
    # populated within the first few seconds rather than waiting for the
    # 1 h interval.
    import threading as _t  # noqa: E402
    _t.Thread(target=_check_update, daemon=True, name="wd-update-first-check").start()
except Exception as exc:
    log.warning("Update service not started: %s", exc)

# ── Mount the WSGI Flask app under an ASGI envelope ──────────────────────────
# Note: socket.io's eventlet WebSocket transport works over polling under the
# WsgiToAsgi adapter for our purposes (Engine.IO falls back to long-polling),
# which is sufficient for the dashboard.
from asgiref.wsgi import WsgiToAsgi  # noqa: E402


class _PrefixStripMiddleware:
    """
    Allows the WireDown UI to be served from `/api/wd/*` on platform
    ingresses that only route `/api/*` to the backend (such as the
    Emergent preview environment). In production (LXC binding port 80
    directly) callers hit the bare routes — `/`, `/admin/console`,
    `/warning` — so this middleware is a no-op for them.
    """

    PREFIX = "/api/wd"

    def __init__(self, wsgi_app):
        self._wsgi = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path == self.PREFIX or path.startswith(self.PREFIX + "/"):
            stripped = path[len(self.PREFIX):] or "/"
            environ["PATH_INFO"] = stripped
            environ["SCRIPT_NAME"] = (
                (environ.get("SCRIPT_NAME") or "") + self.PREFIX
            )
        return self._wsgi(environ, start_response)


flask_app.wsgi_app = _PrefixStripMiddleware(flask_app.wsgi_app)

app = WsgiToAsgi(flask_app)
log.info("WireDown ASGI entrypoint ready — uvicorn will serve on :8001")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=5000, log_level="info")

