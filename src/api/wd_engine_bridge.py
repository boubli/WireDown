"""
WireDown — wd-engine UDS bridge.

Reads NDJSON events from `/run/wiredown.sock` (written by the Rust
`wd-engine` daemon) and dispatches them into the existing in-process
state (devices registry, threat engine, isolation_log, audit_log) AND
broadcasts them live over Socket.IO on `/ws/frontend` so the SOC
dashboard refreshes in real time.

In PREVIEW_MODE (no Rust binary, no UDS socket) the bridge runs as a
zero-cost stub that periodically emits synthetic events so the dashboard
WebSocket layer can still be exercised end-to-end.
"""

from __future__ import annotations

import json
import logging
import os
import random
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("wiredown.bridge")

UDS_PATH = Path(os.environ.get("WD_ENGINE_UDS", "/run/wiredown.sock"))


class EngineBridge:
    """Single-thread NDJSON consumer with auto-reconnect."""

    def __init__(self, uds_path: Path = UDS_PATH, preview: bool = False) -> None:
        self.uds_path = uds_path
        self.preview = preview
        self._thread: Optional[threading.Thread] = None
        self._running = False
        # Bound late to avoid an import cycle with app.py.
        self._dispatch = None
        self._socketio = None
        self.last_event_ts: float = 0.0
        self.events_received: int = 0

    # ── Lifecycle ────────────────────────────────────────────────────────
    def start(self, dispatch_fn, socketio) -> None:
        self._dispatch = dispatch_fn
        self._socketio = socketio
        if self._running:
            return
        self._running = True
        target = self._run_stub if self.preview else self._run_uds
        self._thread = threading.Thread(target=target, daemon=True, name="wd-engine-bridge")
        self._thread.start()
        mode = "STUB (preview)" if self.preview else f"UDS {self.uds_path}"
        log.info("wd-engine bridge started in %s mode", mode)

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    # ── Real UDS reader ──────────────────────────────────────────────────
    def _run_uds(self) -> None:
        backoff = 1.0
        while self._running:
            sock = self._connect()
            if sock is None:
                time.sleep(min(backoff, 10.0))
                backoff = min(backoff * 1.7, 10.0)
                continue
            backoff = 1.0
            log.info("Connected to wd-engine UDS at %s", self.uds_path)
            try:
                with sock.makefile("rb", buffering=0) as f:
                    for raw in f:
                        if not self._running:
                            break
                        line = raw.strip()
                        if not line:
                            continue
                        self._handle_line(line)
            except OSError as exc:
                log.warning("wd-engine UDS read error: %s — reconnecting", exc)
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

    def _connect(self) -> Optional[socket.socket]:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(str(self.uds_path))
            return s
        except (FileNotFoundError, ConnectionRefusedError, OSError) as exc:
            log.debug("wd-engine UDS not available: %s", exc)
            return None

    # ── Preview stub ─────────────────────────────────────────────────────
    def _run_stub(self) -> None:
        """Generate synthetic NDJSON events so the WebSocket pipeline is testable."""
        # Wait a bit so the dashboard has time to subscribe before we start emitting.
        time.sleep(2.0)
        sample_pool = [
            {"kind": "dns", "query": "evil.com",            "qtype": "A", "client_ip": "10.0.0.103", "sinkholed": True,  "upstream": False},
            {"kind": "dns", "query": "google.com",          "qtype": "A", "client_ip": "10.0.0.101", "sinkholed": False, "upstream": True},
            {"kind": "dns", "query": "beacon.malware.xyz",  "qtype": "A", "client_ip": "10.0.0.199", "sinkholed": True,  "upstream": False},
            {"kind": "threat", "src_ip": "10.0.0.199", "mac": "DE:AD:BE:EF:CA:FE",
             "signal": "port_scan_flood", "weight": 60,
             "detail": "SYN burst: 14 distinct dst ports in 10s"},
            {"kind": "threat", "src_ip": "10.0.0.205", "mac": "24:6F:28:AB:CD:11",
             "signal": "dns_sinkhole_hit", "weight": 40,
             "detail": "exfil.io"},
            {"kind": "device", "mac": "9C:8E:CD:11:22:33", "ip": "10.0.0.150",
             "vendor": "Cisco Systems", "hostname": "lab-switch-01", "source": "arp"},
        ]
        while self._running:
            evt = dict(random.choice(sample_pool))
            evt["ts"] = time.time()
            self._handle_line(json.dumps(evt).encode("utf-8"))
            time.sleep(random.uniform(3.5, 7.5))

    # ── Dispatch ─────────────────────────────────────────────────────────
    def _handle_line(self, line: bytes) -> None:
        try:
            evt = json.loads(line)
        except json.JSONDecodeError as exc:
            log.warning("malformed NDJSON from wd-engine: %s", exc)
            return
        self.events_received += 1
        self.last_event_ts = time.time()
        if self._dispatch:
            try:
                self._dispatch(evt)
            except Exception:
                log.exception("dispatch failed for event %s", evt.get("kind"))
        if self._socketio:
            try:
                self._socketio.emit(
                    "engine_event",
                    {**evt, "_received_at": datetime.now(timezone.utc).isoformat()},
                    namespace="/ws/frontend",
                )
            except Exception:
                log.exception("socket.io emit failed")
