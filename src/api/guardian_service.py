import logging
import threading
import time
from typing import Callable, Optional

# Scapy dynamic import handling
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("wiredown.guardian_service")

class GuardianService:
    def __init__(self, interface: str = "br0", anomaly_callback: Optional[Callable] = None):
        self.interface = interface
        self.anomaly_callback = anomaly_callback  # callback(ip, signal_type, details)
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._recent_connections = {}  # (src_ip, dst_ip) -> timestamp to track scan rate

    def start(self):
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy is not installed. GuardianService running in passive mock mode.")
            return

        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True, name="guardian-sniff")
        self._thread.start()
        logger.info("GuardianService network sniffing started on interface: %s", self.interface)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        logger.info("GuardianService network sniffing stopped")

    def _sniff_loop(self):
        # Sniff packets indefinitely while running
        while self._running:
            try:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    filter="ip",
                    store=0,
                    timeout=1.0
                )
            except Exception as e:
                logger.error("Error in Scapy sniffing process: %s", str(e))
                time.sleep(2)

    def _process_packet(self, pkt):
        if not self._running:
            return
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Only audit packets originating from the monitored local range
        if not src_ip.startswith("192.168.8."):
            return

        # 1. High-Risk Port Connection Detection (SSH, Telnet, RDP, SMB)
        dport = None
        protocol = "TCP"
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            protocol = "UDP"

        if dport in (22, 23, 3389, 445):
            details = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "port": dport,
                "protocol": protocol,
                "description": f"Unauthorized out-of-bounds {protocol} connection targeting restricted port {dport}"
            }
            if self.anomaly_callback:
                self.anomaly_callback(src_ip, "probe_anomaly", details)

        # 2. Lateral Scanning/Movement Detection (Internal scan patterns)
        if dst_ip.startswith("192.168.8.") and src_ip != dst_ip:
            now = time.time()
            # Clean up old tracking records periodically
            self._recent_connections = {k: v for k, v in self._recent_connections.items() if now - v < 10.0}
            
            conn_key = (src_ip, dst_ip)
            self._recent_connections[conn_key] = now

            # Count distinct target connections from the same source IP inside 10 seconds
            distinct_targets = set()
            for (s_ip, d_ip), ts in self._recent_connections.items():
                if s_ip == src_ip:
                    distinct_targets.add(d_ip)

            # Trigger Scan Anomaly if scanning more than 8 distinct internal hosts
            if len(distinct_targets) >= 8:
                details = {
                    "src_ip": src_ip,
                    "target_count": len(distinct_targets),
                    "description": f"Internal lateral network scan pattern identified across {len(distinct_targets)} hosts"
                }
                if self.anomaly_callback:
                    self.anomaly_callback(src_ip, "port_scan_flood", details)
