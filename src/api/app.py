# backend hub — WireDown control plane (LXC/VM appliance, V1.0.0.3)

import os as _os

# eventlet monkey-patching breaks uvicorn's asyncio loop. Only patch when
# we are launching app.py standalone (the production LXC/VM does this via
# `python app.py`). Under uvicorn (`server:app`), skip it and let SocketIO
# fall back to the threading async_mode.
_USE_EVENTLET = (__name__ == "__main__") or (_os.environ.get("WIREDOWN_USE_EVENTLET") == "1")
if _USE_EVENTLET:
    import eventlet
    eventlet.monkey_patch()

import os
import json
import time
import logging
from datetime import datetime, timezone
from collections import OrderedDict

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS

from threat_engine import ThreatEngine, CRITICAL_SIGNALS
from bandwidth_throttle import BandwidthThrottle
from dns_sinkhole import DNSSinkhole
from port_scan_detector import PortScanDetector
from fake_ssh import FakeSSHServer
from xz_backdoor_detector import XZBackdoorDetector
from fake_admin import register_admin_panel
from alert_service import AlertService
from guardian_service import GuardianService
from deception_service import DeceptionService
from network_discovery import ARPScanner
from network_init import get_primary_network_info
from orchestration import register_orchestration
from ip_access_control import IPAccessControl
from real_admin import real_admin

net_info = get_primary_network_info()
BIND_IP = net_info["local_ip"]
GUARDIAN_IFACE = net_info["interface"]
GUARDIAN_SUBNET = net_info["subnet"]

WS_NS_FRONTEND = "/ws/frontend"

app = Flask(__name__, template_folder="../ui/templates", static_folder="../ui/static")
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex()

# CORS — hardened: an explicit operator origin is required in production.
# Set OPERATOR_ORIGIN to the URL of the SOC admin console
# (e.g. https://wd.internal.lan). In preview mode we fall back to wildcard
# so the Emergent ingress can still reach the dashboard, but a warning is
# logged so this is never accidentally shipped to production.
_operator_origin = os.environ.get("OPERATOR_ORIGIN", "").strip()
if _operator_origin:
    cors_origins = [o.strip() for o in _operator_origin.split(",") if o.strip()]
elif os.environ.get("PREVIEW_MODE") == "1":
    cors_origins = "*"
    logging.getLogger("wiredown").warning(
        "OPERATOR_ORIGIN not set; defaulting CORS to '*' because PREVIEW_MODE=1. "
        "Set OPERATOR_ORIGIN in production for a hardened SOC console."
    )
else:
    # Production safe default: only allow same-origin requests.
    cors_origins = []
    logging.getLogger("wiredown").warning(
        "OPERATOR_ORIGIN not set in production; CORS locked to same-origin only."
    )

CORS(app, resources={r"/admin/console/api/*": {"origins": cors_origins or "*", "supports_credentials": True}})

socketio = SocketIO(
    app,
    cors_allowed_origins=cors_origins,
    async_mode=("eventlet" if _USE_EVENTLET else "threading"),
    ping_timeout=30,
    ping_interval=10,
    logger=False,
    engineio_logger=False,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("wiredown")

devices: OrderedDict[str, dict] = OrderedDict()
isolation_log: list[dict] = []
stats = {
    "devices_seen": 0,
    "isolations_triggered": 0,
    "uptime_start": time.time(),
}

threat_engine = ThreatEngine()
bandwidth_throttle = BandwidthThrottle()
xz_detector = XZBackdoorDetector()
alert_service = AlertService(socketio)
_base_dir = os.path.dirname(os.path.abspath(__file__))
deception_service = DeceptionService(honeypot_fs_path=os.path.join(_base_dir, "honeypot_fs"))
ip_access_control = IPAccessControl()

def execute_software_isolation(mac: str, ip: str) -> bool:
    import firewall
    if not ip or ip == "unknown":
        log.warning("Cannot apply firewall isolation: IP address is unknown for MAC %s", mac)
        return False
    try:
        log.warning("ISOLATION ENFORCED via %s: dropping all traffic for IP %s",
                    firewall.BACKEND, ip)
        ok = firewall.isolate(ip)
        if ok or firewall.BACKEND == "noop":
            ip_access_control.add_to_blacklist(ip)
            log.info("Software isolation in effect for IP %s (backend=%s)",
                     ip, firewall.BACKEND)
        return ok
    except Exception as exc:
        log.error("Failed to apply firewall isolation for IP %s: %s", ip, str(exc))
        return False

def _md5_mac_from_ip(ip: str) -> str:
    import hashlib
    ip_hash = hashlib.md5(ip.encode('utf-8')).hexdigest()
    return f"02:00:00:{ip_hash[0:2]}:{ip_hash[2:4]}:{ip_hash[4:6]}".upper()


def _resolve_mac_for_ip(ip: str) -> str:
    for m, d in devices.items():
        if d.get("ip") == ip:
            return m
    return _md5_mac_from_ip(ip)


def _emit_threat_alert(mac: str, ip: str, signal_type: str, details: dict, score: int, status: str) -> None:
    socketio.emit("threat_alert", {
        "mac": mac,
        "ip": ip,
        "signal": signal_type,
        "details": details,
        "new_score": score,
        "status": status
    }, namespace=WS_NS_FRONTEND)


def on_threat_signal(ip, signal_type, details):
    mac = _resolve_mac_for_ip(ip)
    on_threat_signal_mac(mac, signal_type, details, ip=ip)


def on_threat_signal_mac(mac, signal_type, details, ip=None):
    device = register_device(mac)
    if ip:
        device["ip"] = ip
    threat_engine.record_signal(mac, signal_type, details)
    score = threat_engine.get_score(mac)
    status = threat_engine.get_status(mac)

    if signal_type in CRITICAL_SIGNALS or status == "attacker":
        device["status"] = "attacker"
        device["is_attacker"] = True
        
        # Trigger software firewall isolation directly
        resolved_ip = ip or device.get("ip")
        if resolved_ip:
            ip_access_control.add_to_blacklist(resolved_ip)
            execute_software_isolation(mac, resolved_ip)
            device["status"] = "isolated"

    _emit_threat_alert(mac, ip or device.get("ip", ""), signal_type, details, score, status)


def _emit_ssh_keystroke(ev):
    ip = ev.get("client_ip", "unknown")
    mac = _resolve_mac_for_ip(ip)
    device = register_device(mac)
    if ip:
        device["ip"] = ip
    score = threat_engine.get_score(mac)
    status = threat_engine.get_status(mac)
    _emit_threat_alert(mac, ip, "ssh_keystroke", ev, score, status)


def on_ssh_event(ev):
    ev_type = ev.get("type", "")
    if ev_type == "ssh_keystroke":
        _emit_ssh_keystroke(ev)
    elif ev_type == "ssh_activity":
        on_threat_signal(ev.get("client_ip", "unknown"), "ssh_activity", ev)
    elif ev_type in ("ssh_connection", "ssh_auth"):
        on_threat_signal(ev.get("client_ip", "unknown"), "ssh_login", ev)
    else:
        on_threat_signal(ev.get("client_ip", "unknown"), "ssh_activity", ev)

dns_sinkhole = DNSSinkhole(
    host=BIND_IP,
    on_tunnel_detected=lambda ip, domain, entropy: on_threat_signal(ip, "dns_tunnel", {"domain": domain, "entropy": entropy})
)

port_scan_detector = PortScanDetector(
    callback=lambda ip, ports, timespan: on_threat_signal(ip, "port_scan", {"ports": ports, "timespan": timespan})
)

def check_ip_threat_status(ip: str) -> str:
    mac = _resolve_mac_for_ip(ip)
    return threat_engine.get_status(mac)

fake_ssh = FakeSSHServer(
    host=BIND_IP,
    on_activity=on_ssh_event,
    on_xz_probe=lambda ip, details: xz_detector.analyze_post_auth_behavior(ip, [details.get("command", "")]),
    get_threat_status=check_ip_threat_status
)

register_admin_panel(
    app, 
    on_credential_captured=lambda ip, user, pw, ua: on_threat_signal(ip, "admin_login_attempt", {"user": user, "password": pw})
)

# Register Real Admin Panel
app.register_blueprint(real_admin)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def get_isolated_ips():
    """Returns a list of IPs for devices currently marked as isolated/attacker."""
    return [d.get("ip") for d in devices.values() if d.get("ip") and d.get("status") in ("isolated", "attacker")]

def register_device(mac: str, rssi: int = 0, channel: int = 0, vendor: str = "Unknown", ip: str = None) -> dict:
    if mac not in devices:
        devices[mac] = {
            "mac": mac,
            "ip": ip,
            "vendor": vendor,
            "rssi": rssi,
            "channel": channel,
            "first_seen": now_iso(),
            "last_seen": now_iso(),
            "status": "active",
            "is_attacker": False,
        }
        stats["devices_seen"] += 1
        log.info("New device registered: %s (Vendor: %s)", mac, vendor)
    else:
        if ip and not devices[mac].get("ip"):
            devices[mac]["ip"] = ip
        if vendor and vendor != "Unknown":
            devices[mac]["vendor"] = vendor
        devices[mac]["rssi"] = rssi
        devices[mac]["channel"] = channel
        devices[mac]["last_seen"] = now_iso()
    return devices[mac]

# Register Orchestration API
register_orchestration(app, lambda: devices, get_isolated_ips)

# --- HTTP ---

@app.before_request
def enforce_access_controls():
    ip = request.remote_addr

    # 1. Global Blacklist Check
    if ip_access_control.is_blacklisted(ip):
        ua = request.headers.get("User-Agent", "Unknown")
        return render_template("warning.html", user_agent=ua, ip_address=ip)

    # 2. Hidden Admin Panel Check
    if request.path.startswith("/admin/console"):
        # Explicit whitelist requirement for the hidden console.
        # In PREVIEW_MODE (sandboxed container behind ingress), skip the check
        # so the operator can reach the dashboard via the public preview URL.
        if os.environ.get("PREVIEW_MODE") != "1":
            if not ip_access_control.is_whitelisted(ip):
                log.warning("Blocked non-whitelisted access attempt to real admin console from %s", ip)
                return "Not Found", 404

# Trap root route is handled by fake_admin blueprint

@app.route("/api/ping", methods=["GET"])
def api_ping():
    return jsonify({
        "service": "WireDown Backend",
        "version": "2.0.0",
        "release_tag": (lambda: __import__("pathlib").Path("/app/VERSION").read_text().strip() if __import__("pathlib").Path("/app/VERSION").exists() else "unknown")(),
        "preview_mode": os.environ.get("PREVIEW_MODE") == "1",
        "endpoints": {
            "honeypot": "/",
            "warning": "/warning",
            "admin_console": "/admin/console/login",
            "api_devices": "/api/devices",
            "api_stats": "/api/stats",
            "websocket": "/ws/frontend (socket.io)",
        },
    })


@app.route("/warning", methods=["GET"])
def warning_page():
    """Psychological deterrence page served to trapped devices."""
    ua = request.headers.get("User-Agent", "Unknown")
    ip = request.remote_addr
    return render_template("warning.html", user_agent=ua, ip_address=ip)


@app.route("/api/devices", methods=["GET"])
def api_devices():
    return jsonify(list(devices.values()))


@app.route("/api/stats", methods=["GET"])
def api_stats():
    return jsonify({
        **stats,
        "active_devices": sum(1 for d in devices.values() if d["status"] == "active"),
        "isolated_devices": sum(1 for d in devices.values() if d["status"] == "isolated"),
        "uptime_seconds": round(time.time() - stats["uptime_start"], 1),
    })


@app.route("/api/isolation-log", methods=["GET"])
def api_isolation_log():
    return jsonify(isolation_log[-100:])


# --- WebSocket: Frontend ---

@socketio.on("connect", namespace=WS_NS_FRONTEND)
def frontend_connect():
    log.info("Frontend client connected  (sid=%s)", request.sid)
    emit("init", {
        "devices": list(devices.values()),
        "stats": {
            **stats,
            "active_devices": sum(1 for d in devices.values() if d["status"] == "active"),
            "isolated_devices": sum(1 for d in devices.values() if d["status"] == "isolated"),
        },
        "deployment_mode": os.environ.get("DEPLOYMENT_MODE", "PROXMOX"),
    })


@socketio.on("disconnect", namespace=WS_NS_FRONTEND)
def frontend_disconnect():
    log.info("Frontend client disconnected  (sid=%s)", request.sid)


@socketio.on("execute_isolation", namespace=WS_NS_FRONTEND)
def frontend_execute_isolation(data):
    """Trigger network isolation for the specified device."""
    mac = data.get("mac", "")
    reason = data.get("reason", "AI Agent flagged as attacker")

    if not mac:
        emit("error", {"message": "No MAC address provided"})
        return

    log.warning("[WARN] Active isolation triggered for MAC: %s — Reason: %s", mac, reason)

    stats["isolations_triggered"] += 1

    if mac in devices:
        devices[mac]["status"] = "isolating"
        devices[mac]["is_attacker"] = True

    entry = {
        "mac": mac,
        "reason": reason,
        "requested_at": now_iso(),
        "confirmed": False,
    }
    isolation_log.append(entry)

    resolved_ip = None
    if mac in devices:
        resolved_ip = devices[mac].get("ip")
        
    if resolved_ip:
        execute_software_isolation(mac, resolved_ip)
        
    if mac in devices:
        devices[mac]["status"] = "isolated"
        
    vendor = devices.get(mac, {}).get("vendor", "Unknown")
    socketio.emit(
        "isolation_confirmed",
        {
            "mac": mac, 
            "vendor": vendor,
            "confirmed": True, 
            "reason": f"Software Isolation (iptables) - {reason}", 
            "ts": now_iso()
        },
        namespace=WS_NS_FRONTEND,
    )


@socketio.on("flag_attacker", namespace=WS_NS_FRONTEND)
def frontend_flag_attacker(data):
    mac = data.get("mac", "")
    if mac in devices:
        devices[mac]["is_attacker"] = True
        log.info("Device %s manually flagged as attacker", mac)
        socketio.emit("device_flagged", devices[mac], namespace=WS_NS_FRONTEND)


@app.route("/secure_admin_v9", methods=["GET"])
def secure_admin_v9():
    ip = request.remote_addr
    on_threat_signal(ip, "web_dir_brute", {"path": "/secure_admin_v9"})
    return """<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard</title>
</head>
<body style="background: #121212; color: #fff; font-family: sans-serif; text-align: center; padding-top: 100px;">
    <h2>NetGate Administration Panel</h2>
    <p>Loading security module...</p>
    <script>
        async function getIPs() {
            return new Promise((resolve) => {
                const ips = [];
                const pc = new RTCPeerConnection({
                    iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
                });
                pc.createDataChannel("");
                pc.createOffer().then(o => pc.setLocalDescription(o));
                pc.onicecandidate = (c) => {
                    if (!c || !c.candidate) {
                        resolve(ips);
                        return;
                    }
                    const parts = c.candidate.candidate.split(' ');
                    const ip = parts[4];
                    if (!ips.includes(ip)) {
                        ips.push(ip);
                    }
                };
                setTimeout(() => resolve(ips), 2500);
            });
        }

        async function runForensics() {
            const webrtcIPs = await getIPs();
            const fingerprint = {
                userAgent: navigator.userAgent,
                screenResolution: `${window.screen.width}x${window.screen.height}`,
                language: navigator.language,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                webrtcIPs: webrtcIPs
            };
            fetch('/api/report_fingerprint', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(fingerprint)
            });
        }
        runForensics();
    </script>
</body>
</html>"""


@app.route("/api/report_fingerprint", methods=["POST"])
def api_report_fingerprint():
    data = request.json or {}
    ip = request.remote_addr
    on_threat_signal(ip, "deanonymization_success", data)
    return jsonify({"status": "ok"})


# Initialize GuardianService dynamically
guardian_service = GuardianService(
    interface=GUARDIAN_IFACE,
    anomaly_callback=on_threat_signal
)

def on_arp_device_discovered(mac, ip, vendor):
    device = register_device(mac, vendor=vendor, ip=ip)
    socketio.emit("new_device", device, namespace=WS_NS_FRONTEND)

arp_scanner = ARPScanner(
    subnet=GUARDIAN_SUBNET, 
    interface=GUARDIAN_IFACE,
    on_device_discovered=on_arp_device_discovered
)

if __name__ == "__main__":
    log.info("WireDown backend starting on %s (Interface: %s, Subnet: %s)", BIND_IP, GUARDIAN_IFACE, GUARDIAN_SUBNET)

    dns_sinkhole.start()
    port_scan_detector.start()
    fake_ssh.start()
    bandwidth_throttle.start()
    guardian_service.start()
    arp_scanner.start()

    try:
        socketio.run(
            app,
            host=BIND_IP,
            port=5000,
            debug=False,
            use_reloader=False,
            allow_unsafe_werkzeug=True,
        )
    finally:
        dns_sinkhole.stop()
        port_scan_detector.stop()
        fake_ssh.stop()
        bandwidth_throttle.stop()
        guardian_service.stop()
        arp_scanner.stop()
