# per-device threat scoring with time decay

import logging
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional

logger = logging.getLogger("wiredown.threat_engine")


SIGNAL_WEIGHTS: Dict[str, int] = {
    "xz_backdoor":          80,
    "krack_attack":         60,
    "deauth_flood":         50,
    "arp_spoof":            40,
    "dns_tunnel":           40,
    "port_scan":            35,
    "brute_force":          30,
    "ssh_login":            30,
    "admin_login_attempt":  30,
    "mac_flood":            25,
    "honeypot_file_access": 20,
    "ssh_command":          20,
    "high_connection_rate": 15,
    "probe_anomaly":        10,
}

# Decay configuration
DECAY_POINTS = 5        # points removed per decay interval
DECAY_INTERVAL = 300    # seconds (5 minutes)


class ThreatEngine:

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # mac → { score, signals, history, first_seen, last_updated }
        self._devices: Dict[str, Dict[str, Any]] = {}
        self._running = False
        self._decay_thread: Optional[threading.Thread] = None




    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._decay_thread = threading.Thread(
            target=self._decay_loop, daemon=True, name="threat-decay"
        )
        self._decay_thread.start()
        logger.info("Threat decay thread started (interval=%ds, decay=%dpts)",
                     DECAY_INTERVAL, DECAY_POINTS)

    def stop(self) -> None:
        self._running = False
        if self._decay_thread is not None:
            self._decay_thread.join(timeout=5)
            self._decay_thread = None
        logger.info("ThreatEngine stopped")



    def record_signal(self, mac: str, signal_type: str,
                      details: Optional[Dict[str, Any]] = None) -> int:
        if details is None:
            details = {}

        weight = SIGNAL_WEIGHTS.get(signal_type, 0)
        if weight == 0:
            logger.warning("Unknown signal type '%s' for MAC %s — ignored",
                           signal_type, mac)
            return self.get_score(mac)

        now = time.time()

        with self._lock:
            device = self._devices.get(mac)
            if device is None:
                device = {
                    "score": 0,
                    "signals": {},       # signal_type → count
                    "history": [],       # list of event dicts
                    "first_seen": now,
                    "last_updated": now,
                }
                self._devices[mac] = device

            device["score"] += weight
            device["last_updated"] = now
            device["signals"][signal_type] = device["signals"].get(signal_type, 0) + 1
            device["history"].append({
                "signal": signal_type,
                "weight": weight,
                "details": details,
                "timestamp": now,
            })

            new_score = device["score"]

        status = self._classify(new_score)
        logger.info(
            "Signal '%s' (+%d) recorded for %s — score=%d status=%s",
            signal_type, weight, mac, new_score, status,
        )
        return new_score

    def get_score(self, mac: str) -> int:
        with self._lock:
            device = self._devices.get(mac)
            if device is None:
                return 0
            return device["score"]

    def get_status(self, mac: str) -> str:
        return self._classify(self.get_score(mac))

    def get_all_threats(self) -> List[Dict[str, Any]]:
        with self._lock:
            result = []
            for mac, dev in self._devices.items():
                result.append({
                    "mac": mac,
                    "score": dev["score"],
                    "status": self._classify(dev["score"]),
                    "signal_count": sum(dev["signals"].values()),
                    "signals": dict(dev["signals"]),
                    "first_seen": dev["first_seen"],
                    "last_updated": dev["last_updated"],
                })
        result.sort(key=lambda d: d["score"], reverse=True)
        return result

    def get_device_report(self, mac: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            device = self._devices.get(mac)
            if device is None:
                return None
            return {
                "mac": mac,
                "score": device["score"],
                "status": self._classify(device["score"]),
                "signals": dict(device["signals"]),
                "history": list(device["history"]),
                "first_seen": device["first_seen"],
                "last_updated": device["last_updated"],
            }



    @staticmethod
    def _classify(score: int) -> str:
        if score >= 60:
            return "attacker"
        if score >= 30:
            return "suspicious"
        return "safe"

    def _decay_loop(self) -> None:
        logger.debug("Decay loop running")
        while self._running:
            time.sleep(1)  # wake up every second to check _running flag
            now = time.time()
            with self._lock:
                for mac, device in self._devices.items():
                    elapsed = now - device["last_updated"]
                    if elapsed < DECAY_INTERVAL:
                        continue

                    intervals = int(elapsed // DECAY_INTERVAL)
                    decay_total = intervals * DECAY_POINTS
                    old_score = device["score"]
                    if old_score <= 0:
                        continue
                    new_score = max(0, old_score - decay_total)
                    if new_score != old_score:
                        device["score"] = new_score

                        device["last_updated"] = now
                        logger.debug(
                            "Decay: %s %d → %d (-%d over %d intervals)",
                            mac, old_score, new_score, old_score - new_score,
                            intervals,
                        )
