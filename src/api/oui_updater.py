"""
WireDown — IEEE OUI vendor table updater.

Refreshes `/etc/wiredown/oui.csv` from the IEEE master list at most once
per 30 days. Designed to run as a long-lived daemon thread inside the
control plane.

Format on disk: `<3-byte-prefix>,<vendor>` per line, e.g.

    A4:83:E7,Intel Corporate
    F0:18:98,Apple Inc.

The Rust `wd-engine` is signalled with `SIGHUP` on a successful refresh
so it re-mmaps the table without a restart.

Source: https://standards-oui.ieee.org/oui/oui.csv
"""

from __future__ import annotations

import csv
import io
import logging
import os
import signal
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

log = logging.getLogger("wiredown.oui_updater")

OUI_PATH = Path(os.environ.get("WD_OUI_PATH", "/etc/wiredown/oui.csv"))
OUI_URL  = os.environ.get("WD_OUI_URL", "https://standards-oui.ieee.org/oui/oui.csv")
REFRESH_DAYS = int(os.environ.get("WD_OUI_REFRESH_DAYS", "30"))


def _signal_engine() -> None:
    """SIGHUP the wd-engine daemon so it re-reads the OUI table."""
    pid_file = Path("/run/wd-engine.pid")
    if not pid_file.exists():
        return
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, signal.SIGHUP)
        log.info("Signalled wd-engine pid=%d with SIGHUP", pid)
    except (OSError, ValueError) as exc:
        log.warning("Could not SIGHUP wd-engine: %s", exc)


def _needs_refresh() -> bool:
    if not OUI_PATH.exists():
        return True
    age_days = (time.time() - OUI_PATH.stat().st_mtime) / 86400.0
    return age_days >= REFRESH_DAYS


def _download_and_write() -> Optional[int]:
    log.info("Refreshing IEEE OUI table from %s", OUI_URL)
    try:
        req = urllib.request.Request(
            OUI_URL,
            headers={"User-Agent": "WireDown/2.0 (+oui_updater)"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError) as exc:
        log.warning("OUI download failed: %s", exc)
        return None

    # Streaming CSV parse → minimal "prefix,vendor" pairs.
    reader = csv.reader(io.StringIO(raw))
    written = 0
    OUI_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUI_PATH.with_suffix(".csv.tmp")
    with tmp.open("w", encoding="utf-8") as out:
        for row in reader:
            # IEEE format: "Registry","Assignment","Organization Name","Organization Address"
            if len(row) < 3 or row[0].strip().lower() == "registry":
                continue
            assignment = row[1].strip().replace("-", "").upper()
            vendor = row[2].strip()
            if len(assignment) != 6 or not vendor:
                continue
            prefix = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}"
            out.write(f"{prefix},{vendor}\n")
            written += 1
    tmp.replace(OUI_PATH)
    log.info("OUI table refreshed: %d entries → %s", written, OUI_PATH)
    return written


def _loop() -> None:
    while True:
        try:
            if _needs_refresh():
                if _download_and_write() is not None:
                    _signal_engine()
        except Exception:
            log.exception("OUI updater loop hiccup")
        # Re-check every 24 h. Actual refresh only happens once per REFRESH_DAYS.
        time.sleep(86400)


def start_background() -> threading.Thread:
    t = threading.Thread(target=_loop, daemon=True, name="oui-updater")
    t.start()
    log.info(
        "OUI updater started (path=%s url=%s refresh=%dd)",
        OUI_PATH, OUI_URL, REFRESH_DAYS,
    )
    return t
