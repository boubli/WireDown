# backend hub for WireDown
# glues the ESP32 to the frontend and runs the security modules.

import os
import json
import time
import logging
from datetime import datetime, timezone
from collections import OrderedDict

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS

from threat_engine import ThreatEngine
from bandwidth_throttle import BandwidthThrottle
from dns_sinkhole import DNSSinkhole
from port_scan_detector import PortScanDetector
from fake_ssh import FakeSSHServer
from xz_backdoor_detector import XZBackdoorDetector
from fake_admin import register_admin_panel

# WebSocket namespace constants
WS_NS_FRONTEND = "/ws/frontend"
WS_NS_ESP32 = "/ws/esp32"

# App Setup
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32).hex()
CORS(app, resources={r"/*": {"origins": "*"}})

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
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

# In-Memory State
esp32_sid = None                          # Socket.IO session id of the ESP32
devices: OrderedDict[str, dict] = OrderedDict()   # mac → device info
isolation_log: list[dict] = []            # audit trail
stats = {
    "devices_seen": 0,
    "isolations_triggered": 0,
    "esp32_connected": False,
    "uptime_start": time.time(),
}

# Security Modules

threat_engine = ThreatEngine()
bandwidth_throttle = BandwidthThrottle()
xz_detector = XZBackdoorDetector()

def on_threat_signal(ip, signal_type, details):
    mac = "UNKNOWN"
    for m, d in devices.items():
        if d.get("ip") == ip:
            mac = m
            break
            
    device = register_device(mac)
    device["ip"] = ip
    threat_engine.record_signal(mac, signal_type, details)
    score = threat_engine.get_score(mac)
    status = threat_engine.get_status(mac)
    
    socketio.emit("threat_alert", {
        "mac": mac,
        "ip": ip,
        "signal": signal_type,
        "details": details,
        "new_score": score,
        "status": status
    }, namespace=WS_NS_FRONTEND)

dns_sinkhole = DNSSinkhole(
    on_tunnel_detected=lambda ip, domain, entropy: on_threat_signal(ip, "dns_tunnel", {"domain": domain, "entropy": entropy})
)

port_scan_detector = PortScanDetector(
    callback=lambda ip, ports, timespan: on_threat_signal(ip, "port_scan", {"ports": ports, "timespan": timespan})
)

fake_ssh = FakeSSHServer(
    on_activity=lambda ev: on_threat_signal(ev.get("client_ip"), "ssh_activity", ev),
    on_xz_probe=lambda ip, details: xz_detector.analyze_post_auth_behavior(ip, [details.get("command", "")])
)

register_admin_panel(
    app, 
    on_credential_captured=lambda ip, user, pw, ua: on_threat_signal(ip, "admin_login_attempt", {"user": user, "password": pw})
)

# Helpers

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def register_device(mac: str, rssi: int = 0, channel: int = 0) -> dict:
    """Add or update a device in the registry."""
    if mac not in devices:
        devices[mac] = {
            "mac": mac,
            "rssi": rssi,
            "channel": channel,
            "first_seen": now_iso(),
            "last_seen": now_iso(),
            "status": "active",          # active | isolated | destroyed
            "is_attacker": False,
        }
        stats["devices_seen"] += 1
        log.info("New device registered: %s (RSSI %d)", mac, rssi)
    else:
        devices[mac]["rssi"] = rssi
        devices[mac]["channel"] = channel
        devices[mac]["last_seen"] = now_iso()
    return devices[mac]


# HTTP Routes

@app.route("/", methods=["GET"])
def index():
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


# WebSocket: ESP32 Channel

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
    """Handle all JSON messages from ESP32."""
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

    elif msg_type == "pong":
        pass

    else:
        log.warning("Unknown ESP32 message type: %s", msg_type)


# WebSocket: Frontend Channel

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
    })


@socketio.on("disconnect", namespace=WS_NS_FRONTEND)
def frontend_disconnect():
    log.info("Frontend client disconnected  (sid=%s)", request.sid)


@socketio.on("execute_isolation", namespace=WS_NS_FRONTEND)
def frontend_execute_isolation(data):
    """
    Receive an isolation command from the Frontend AI Agent
    and relay it to the ESP32.
    """
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
    """Let the frontend spawn a fake device for testing."""
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


# Entry Point

if __name__ == "__main__":
    log.info("╔══════════════════════════════════════╗")
    log.info("║   WireDown Backend — Starting...     ║")
    log.info("╚══════════════════════════════════════╝")
    log.info("Dashboard:  http://localhost:5000")
    log.info("Warning:    http://localhost:5000/warning")

    dns_sinkhole.start()
    port_scan_detector.start()
    fake_ssh.start()
    bandwidth_throttle.start()

    try:
        socketio.run(
            app,
            host="0.0.0.0",
            port=5000,
            debug=True,
            use_reloader=False,
            allow_unsafe_werkzeug=True,
        )
    finally:
        dns_sinkhole.stop()
        port_scan_detector.stop()
        fake_ssh.stop()
        bandwidth_throttle.stop()
