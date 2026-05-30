import logging
import threading
import time
from typing import Callable, Optional

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logger = logging.getLogger("wiredown.network_discovery")

class ARPScanner:
    def __init__(self, subnet: str = "192.168.8.0/24", interface: str = "br0", scan_interval: int = 30, on_device_discovered: Optional[Callable] = None):
        self.subnet = subnet
        self.interface = interface
        self.scan_interval = scan_interval
        self.on_device_discovered = on_device_discovered # callback(mac, ip, vendor)
        self._running = False
        self._thread = None

    def start(self):
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy is not installed. ARPScanner cannot run.")
            return

        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._scan_loop, daemon=True, name="arp-scanner")
        self._thread.start()
        logger.info("ARPScanner started on interface %s for subnet %s", self.interface, self.subnet)

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        logger.info("ARPScanner stopped")

    def resolve_vendor(self, mac: str) -> str:
        if not SCAPY_AVAILABLE:
            return "Unknown"
        try:
            # conf.manufdb is the Scapy MAC vendor database
            vendor = conf.manufdb._resolve_MAC(mac)
            if vendor and vendor != mac:
                return vendor
        except Exception:
            pass
        return "Unknown"

    def _scan_loop(self):
        while self._running:
            try:
                # Create ARP request packet
                arp_request = ARP(pdst=self.subnet)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp_request

                # Send packet and get responses
                result = srp(packet, iface=self.interface, timeout=2, verbose=0)[0]

                for sent, received in result:
                    ip = received.psrc
                    mac = received.hwsrc.upper()
                    vendor = self.resolve_vendor(mac)
                    
                    if self.on_device_discovered:
                        self.on_device_discovered(mac, ip, vendor)

            except Exception as e:
                logger.error("Error during ARP scan: %s", str(e))
            
            # Wait for next scan
            for _ in range(self.scan_interval):
                if not self._running:
                    break
                time.sleep(1)
