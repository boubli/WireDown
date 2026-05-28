"""
WireDown Honeypot — Multi-Factor Threat Score Engine
=====================================================
Maintains per-device threat scores based on weighted security signals.
Scores decay over time to avoid permanent blacklisting of devices that
have stopped exhibiting malicious behaviour.
"""

import logging
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional

logger = logging.getLogger("wiredown.threat_engine")

# ---------------------------------------------------------------------------
# Signal weight table — higher weight = more malicious intent indicated
# ---------------------------------------------------------------------------
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
    """Thread-safe, per-device threat scoring engine with time-based decay."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # mac → { score, signals, history, first_seen, last_updated }
        self._devices: Dict[str, Dict[str, Any]] = {}
        self._running = False
        self._decay_thread: Optional[threading.Thread] = None
        logger.info("ThreatEngine initialised")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background decay thread."""
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
        """Signal the decay thread to stop."""
        self._running = False
        if self._decay_thread is not None:
            self._decay_thread.join(timeout=5)
            self._decay_thread = None
        logger.info("ThreatEngine stopped")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_signal(self, mac: str, signal_type: str,
                      details: Optional[Dict[str, Any]] = None) -> int:
        """
        Record a security signal for *mac*.

        Parameters
        ----------
        mac : str
            Device MAC address (or any unique identifier).
        signal_type : str
            One of the keys in ``SIGNAL_WEIGHTS``.
        details : dict, optional
            Arbitrary context to store alongside the signal.

        Returns
        -------
        int
            The device's updated threat score.
        """
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
        """Return the current threat score for *mac* (0 if unknown)."""
        with self._lock:
            device = self._devices.get(mac)
            if device is None:
                return 0
            return device["score"]

    def get_status(self, mac: str) -> str:
        """
        Return a human-readable classification for *mac*.

        * ``'safe'``       — score < 30
        * ``'suspicious'`` — 30 ≤ score < 60
        * ``'attacker'``   — score ≥ 60
        """
        return self._classify(self.get_score(mac))

    def get_all_threats(self) -> List[Dict[str, Any]]:
        """
        Return every tracked device sorted by descending score.

        Each entry: ``{mac, score, status, signal_count, first_seen, last_updated}``
        """
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
        """
        Return the full signal history and metadata for *mac*.

        Returns ``None`` if the device has never been seen.
        """
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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _classify(score: int) -> str:
        if score >= 60:
            return "attacker"
        if score >= 30:
            return "suspicious"
        return "safe"

    def _decay_loop(self) -> None:
        """Background loop that reduces stale scores every ``DECAY_INTERVAL``."""
        logger.debug("Decay loop running")
        while self._running:
            time.sleep(1)  # wake up every second to check _running flag
            now = time.time()
            with self._lock:
                for mac, device in self._devices.items():
                    elapsed = now - device["last_updated"]
                    if elapsed < DECAY_INTERVAL:
                        continue
                    # Calculate how many full intervals have elapsed
                    intervals = int(elapsed // DECAY_INTERVAL)
                    decay_total = intervals * DECAY_POINTS
                    old_score = device["score"]
                    if old_score <= 0:
                        continue
                    new_score = max(0, old_score - decay_total)
                    if new_score != old_score:
                        device["score"] = new_score
                        # Advance the baseline so we don't re-decay
                        device["last_updated"] = now
                        logger.debug(
                            "Decay: %s %d → %d (-%d over %d intervals)",
                            mac, old_score, new_score, old_score - new_score,
                            intervals,
                        )
