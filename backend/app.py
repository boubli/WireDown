# backend hub — glues ESP32, frontend, and security modules together

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

WS_NS_FRONTEND = "/ws/frontend"
WS_NS_ESP32 = "/ws/esp32"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex()

# CORS — default to wildcard since this is a LAN appliance.
# Set CORS_ORIGINS in .env to lock it down if you want.
cors_origins = os.environ.get("CORS_ORIGINS", "*")
CORS(app, resources={r"/*": {"origins": cors_origins}})

socketio = SocketIO(
    app,
    cors_allowed_origins=cors_origins,
    async_mode="eventlet",
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

esp32_sid = None
devices: OrderedDict[str, dict] = OrderedDict()
isolation_log: list[dict] = []
stats = {
    "devices_seen": 0,
    "isolations_triggered": 0,
    "esp32_connected": False,
    "uptime_start": time.time(),
}

threat_engine = ThreatEngine()
bandwidth_throttle = BandwidthThrottle()
xz_detector = XZBackdoorDetector()

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
    on_tunnel_detected=lambda ip, domain, entropy: on_threat_signal(ip, "dns_tunnel", {"domain": domain, "entropy": entropy})
)

port_scan_detector = PortScanDetector(
    callback=lambda ip, ports, timespan: on_threat_signal(ip, "port_scan", {"ports": ports, "timespan": timespan})
)

fake_ssh = FakeSSHServer(
    on_activity=on_ssh_event,
    on_xz_probe=lambda ip, details: xz_detector.analyze_post_auth_behavior(ip, [details.get("command", "")])
)

register_admin_panel(
    app, 
    on_credential_captured=lambda ip, user, pw, ua: on_threat_signal(ip, "admin_login_attempt", {"user": user, "password": pw})
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def register_device(mac: str, rssi: int = 0, channel: int = 0) -> dict:
    if mac not in devices:
        devices[mac] = {
            "mac": mac,
            "rssi": rssi,
            "channel": channel,
            "first_seen": now_iso(),
            "last_seen": now_iso(),
            "status": "active",
            "is_attacker": False,
        }
        stats["devices_seen"] += 1
        log.info("New device registered: %s (RSSI %d)", mac, rssi)
    else:
        devices[mac]["rssi"] = rssi
        devices[mac]["channel"] = channel
        devices[mac]["last_seen"] = now_iso()
    return devices[mac]


# --- HTTP ---

@app.before_request
def force_admin_decoy():
    if request.path != "/admin":
        return None
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "")
    on_threat_signal(ip, "web_dir_brute", {"path": "/admin"})
    return render_template("warning.html", user_agent=ua, ip_address=ip)


@app.route("/", methods=["GET"])
def index():
    # If the request accepts HTML (i.e. browser request), render the matrix trap page
    accept = request.headers.get("Accept", "")
    ua = request.headers.get("User-Agent", "")
    if "text/html" in accept or "Mozilla" in ua:
        ip = request.remote_addr
        on_threat_signal(ip, "web_trap", {"path": "/"})
        return render_template("warning.html", user_agent=ua, ip_address=ip)

    return jsonify({
        "service": "WireDown Backend",
        "version": "1.0.0",
        "endpoints": {
            "warning": "/warning",
            "api_devices": "/api/devices",
            "api_stats": "/api/stats",
            "websocket": "ws://HOST:5000 (socket.io)",
        },
    })


@app.route("/admin", methods=["GET", "POST"])
def admin_decoy():
    ip = request.remote_addr
    ua = request.headers.get("User-Agent", "")
    on_threat_signal(ip, "web_dir_brute", {"path": "/admin"})
    return render_template("warning.html", user_agent=ua, ip_address=ip)


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


# --- ESP32 config + flash endpoints ---

@app.route("/api/esp32/configure", methods=["POST"])
def api_esp32_configure():
    """Accept WiFi creds + backend IP, write a modified .ino."""
    from esp32_flasher import configure_ino
    data = request.get_json(silent=True) or {}
    ssid = data.get("ssid", "").strip()
    password = data.get("password", "").strip()
    backend_ip = data.get("backend_ip", "").strip()

    if not all([ssid, password, backend_ip]):
        return jsonify({"status": "error", "message": "ssid, password, and backend_ip are required"}), 400

    try:
        path = configure_ino(ssid, password, backend_ip)
        return jsonify({"status": "ok", "message": "ino configured", "path": path})
    except Exception as exc:
        log.error("ESP32 configure failed: %s", exc)
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.route("/api/esp32/flash", methods=["POST"])
def api_esp32_flash():
    """Compile and flash the configured .ino to a connected ESP32."""
    from esp32_flasher import compile_and_flash, detect_esp32_port
    data = request.get_json(silent=True) or {}
    port = data.get("port") or detect_esp32_port() or "/dev/ttyUSB0"

    try:
        result = compile_and_flash(port=port)
        return jsonify(result)
    except Exception as exc:
        log.error("ESP32 flash failed: %s", exc)
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.route("/api/esp32/status", methods=["GET"])
def api_esp32_status():
    """Return current flash process status."""
    from esp32_flasher import get_flash_status
    return jsonify(get_flash_status())


@app.route("/api/esp32/detect", methods=["GET"])
def api_esp32_detect():
    """Auto-detect connected ESP32 port."""
    from esp32_flasher import detect_esp32_port
    port = detect_esp32_port()
    if port:
        return jsonify({"status": "ok", "port": port})
    return jsonify({"status": "not_found", "port": None}), 404


# --- WebSocket: ESP32 ---

@socketio.on("connect", namespace=WS_NS_ESP32)
def esp32_connect():
    global esp32_sid
    esp32_sid = request.sid
    stats["esp32_connected"] = True
    log.info("ESP32 sensor connected  (sid=%s)", request.sid)
    emit("ack", {"status": "connected", "ts": now_iso()})
    socketio.emit("esp32_status", {"connected": True}, namespace=WS_NS_FRONTEND)


@socketio.on("disconnect", namespace=WS_NS_ESP32)
def esp32_disconnect():
    global esp32_sid
    esp32_sid = None
    stats["esp32_connected"] = False
    log.warning("ESP32 sensor disconnected")
    socketio.emit("esp32_status", {"connected": False}, namespace=WS_NS_FRONTEND)


@socketio.on("message", namespace=WS_NS_ESP32)
def esp32_message(raw):
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        log.error("Bad JSON from ESP32: %s", raw)
        return

    msg_type = data.get("type", "")

    if msg_type == "device_discovered":
        mac = data.get("mac", "??:??:??:??:??:??")
        rssi = data.get("rssi", 0)
        channel = data.get("channel", 0)
        device = register_device(mac, rssi, channel)
        socketio.emit("new_device", device, namespace=WS_NS_FRONTEND)

    elif msg_type == "esp32_hello":
        log.info("ESP32 hello: %s", data)

    elif msg_type == "heartbeat":
        log.debug("ESP32 heartbeat — uptime %d ms, heap %d",
                  data.get("uptime", 0), data.get("free_heap", 0))

    elif msg_type == "isolation_complete":
        mac = data.get("mac", "")
        log.info("Isolation confirmed by ESP32 for %s", mac)
        if mac in devices:
            devices[mac]["status"] = "isolated"
        entry = {"mac": mac, "confirmed": True, "ts": now_iso(), "frames": data.get("frames", 0)}
        isolation_log.append(entry)
        socketio.emit("isolation_confirmed", entry, namespace=WS_NS_FRONTEND)

    elif msg_type == "attack_detected":
        attack = data.get("attack", "")
        mac = data.get("mac", "")
        details = data.get("details", {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except json.JSONDecodeError:
                details = {"raw": details}
        if not attack or not mac:
            log.warning("Attack signal missing fields: %s", data)
            return
        ip_from_details = details.get("ip") if isinstance(details, dict) else None
        on_threat_signal_mac(mac, attack, details, ip=ip_from_details)

    elif msg_type == "pong":
        pass

    else:
        log.warning("Unknown ESP32 message type: %s", msg_type)


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
        "esp32_connected": stats["esp32_connected"],
        "deployment_mode": os.environ.get("DEPLOYMENT_MODE", "ESP32"),
    })


@socketio.on("disconnect", namespace=WS_NS_FRONTEND)
def frontend_disconnect():
    log.info("Frontend client disconnected  (sid=%s)", request.sid)


@socketio.on("execute_isolation", namespace=WS_NS_FRONTEND)
def frontend_execute_isolation(data):
    """Relay isolation command from Frontend AI Agent to ESP32."""
    mac = data.get("mac", "")
    reason = data.get("reason", "AI Agent flagged as attacker")

    if not mac:
        emit("error", {"message": "No MAC address provided"})
        return

    log.warning("ISOLATION REQUESTED — MAC: %s  Reason: %s", mac, reason)

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

    if esp32_sid:
        socketio.emit(
            "message",
            json.dumps({"type": "isolate", "mac": mac}),
            namespace="/ws/esp32",
            to=esp32_sid,
        )
        emit("isolation_sent", {"mac": mac, "status": "sent_to_esp32"})
        log.info("Isolation command forwarded to ESP32 for %s", mac)
    else:
        emit("isolation_sent", {"mac": mac, "status": "esp32_offline"})
        log.error("Cannot isolate %s — ESP32 not connected!", mac)
        if mac in devices:
            devices[mac]["status"] = "isolated"
        socketio.emit(
            "isolation_confirmed",
            {"mac": mac, "confirmed": False, "reason": "ESP32 offline", "ts": now_iso()},
            namespace=WS_NS_FRONTEND,
        )


@socketio.on("flag_attacker", namespace=WS_NS_FRONTEND)
def frontend_flag_attacker(data):
    mac = data.get("mac", "")
    if mac in devices:
        devices[mac]["is_attacker"] = True
        log.info("Device %s manually flagged as attacker", mac)
        socketio.emit("device_flagged", devices[mac], namespace=WS_NS_FRONTEND)


@socketio.on("simulate_device", namespace=WS_NS_FRONTEND)
def frontend_simulate_device(data):
    """Spawn a fake device for testing."""
    import random
    mac = data.get("mac") or "DE:AD:{:02X}:{:02X}:{:02X}:{:02X}".format(
        random.randint(0, 255), random.randint(0, 255),
        random.randint(0, 255), random.randint(0, 255),
    )
    rssi = data.get("rssi", random.randint(-80, -30))
    channel = data.get("channel", random.choice([1, 6, 11]))
    device = register_device(mac, rssi, channel)
    socketio.emit("new_device", device, namespace=WS_NS_FRONTEND)
    log.info("Simulated device spawned: %s", mac)


if __name__ == "__main__":
    log.info("WireDown backend starting")

    dns_sinkhole.start()
    port_scan_detector.start()
    fake_ssh.start()
    bandwidth_throttle.start()

    try:
        socketio.run(
            app,
            host="0.0.0.0",
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
