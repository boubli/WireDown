import logging
from datetime import datetime, timezone

logger = logging.getLogger("wiredown.alert_service")

class AlertService:
    def __init__(self, socketio, namespace="/ws/frontend"):
        self.socketio = socketio
        self.namespace = namespace

    def emit_alert(self, mac: str, ip: str, signal_type: str, details: dict, score: int, status: str):
        """Sends a high-severity threat alert directly to the dashboard web socket."""
        try:
            logger.info("Emitting alert: signal=%s MAC=%s IP=%s score=%d status=%s", 
                        signal_type, mac, ip, score, status)
            self.socketio.emit("threat_alert", {
                "mac": mac,
                "ip": ip,
                "signal": signal_type,
                "details": details,
                "new_score": score,
                "status": status
            }, namespace=self.namespace)
        except Exception as e:
            logger.error("Failed to emit alert via socket.io: %s", str(e))
