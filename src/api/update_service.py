"""
WireDown — 1-Click update service.

Two responsibilities:
  1. **Background poller** — every UPDATE_CHECK_INTERVAL seconds, query
     GitHub's releases API for the latest tag, compare against the
     locally installed VERSION, and remember the outcome in
     `update_state` (consumed by `/admin/console/api/system/update-status`).

  2. **Executor** — when an authenticated operator hits
     `POST /admin/console/api/system/update`, spawn the local
     `proxmox-update.sh` script in a detached subprocess and stream its
     stdout/stderr into the update_state log.

The Rust `wd-engine` is restarted by the bash script itself (via
`systemctl restart wd-engine`), so this module does NOT need elevated
privileges beyond the ability to invoke the script.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

log = logging.getLogger("wiredown.update")

# ── Configuration ────────────────────────────────────────────────────────────
REPO            = os.environ.get("WD_GITHUB_REPO", "boubli/WireDown")
GITHUB_LATEST   = f"https://api.github.com/repos/{REPO}/releases/latest"
VERSION_FILE    = Path(os.environ.get("WD_VERSION_PATH", "/app/VERSION"))
UPDATE_SCRIPT   = Path(os.environ.get("WD_UPDATE_SCRIPT", "/app/deploy/proxmox-update.sh"))
CHECK_INTERVAL  = int(os.environ.get("WD_UPDATE_CHECK_INTERVAL_SEC", "3600"))   # 1 h
UPDATE_TIMEOUT  = int(os.environ.get("WD_UPDATE_TIMEOUT_SEC", "600"))           # 10 min cap

_VERSION_RX = re.compile(r"V?(\d+(?:\.\d+)+)", re.IGNORECASE)


# ── Shared state (consumed by REST + WebSocket) ─────────────────────────────
update_state: dict = {
    "current_version":  None,
    "latest_version":   None,
    "update_available": False,
    "release_url":      None,
    "release_notes":    None,
    "last_checked":     0.0,
    "checking":         False,
    # While update is running:
    "in_progress":      False,
    "started_at":       None,
    "finished_at":      None,
    "exit_code":        None,
    "log_tail":         [],     # last ~200 lines of stdout/stderr
}

_state_lock = threading.Lock()


# ── Helpers ─────────────────────────────────────────────────────────────────

def _read_current_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return "0.0.0"


def _normalise(v: str) -> tuple[int, ...]:
    """Turn 'V1.0.0.3' or 'v1.0.0-rc1' into a comparable tuple."""
    m = _VERSION_RX.search(v or "")
    if not m:
        return (0,)
    return tuple(int(p) for p in m.group(1).split("."))


def _socketio_emit(event: str, payload: dict) -> None:
    try:
        from app import socketio   # late import to avoid cycle
        socketio.emit(event, payload, namespace="/ws/frontend")
    except Exception:
        pass


# ── GitHub poller ───────────────────────────────────────────────────────────

def check_now() -> dict:
    """Single GitHub releases poll. Updates `update_state` in place."""
    with _state_lock:
        update_state["checking"] = True
        update_state["current_version"] = _read_current_version()
    try:
        req = urllib.request.Request(
            GITHUB_LATEST,
            headers={
                "User-Agent": "WireDown/V1.0.0.3 (+update_service)",
                "Accept":     "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        latest_tag   = (payload.get("tag_name") or "").strip() or None
        release_url  = payload.get("html_url")
        release_body = (payload.get("body") or "").strip()

        current = _read_current_version()
        available = bool(latest_tag) and _normalise(latest_tag) > _normalise(current)

        with _state_lock:
            update_state.update({
                "current_version":  current,
                "latest_version":   latest_tag,
                "update_available": available,
                "release_url":      release_url,
                "release_notes":    release_body[:2000],
                "last_checked":     time.time(),
                "checking":         False,
            })
        if available:
            log.info("UPDATE AVAILABLE: %s → %s", current, latest_tag)
            _socketio_emit("update_available", {
                "current_version": current,
                "latest_version":  latest_tag,
                "release_url":     release_url,
            })
        else:
            log.debug("WireDown is up-to-date (%s ≥ %s)", current, latest_tag)
        return dict(update_state)

    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        log.warning("Update check failed: %s", exc)
        with _state_lock:
            update_state["checking"] = False
            update_state["last_checked"] = time.time()
        return dict(update_state)


def _background_loop() -> None:
    # Small jitter so multiple appliances behind the same NAT don't hammer GitHub
    # in unison.
    time.sleep(5 + (os.getpid() % 30))
    while True:
        try:
            check_now()
        except Exception:
            log.exception("Background update check crashed (caught)")
        time.sleep(CHECK_INTERVAL)


def start_background() -> threading.Thread:
    t = threading.Thread(target=_background_loop, daemon=True, name="wd-update-checker")
    t.start()
    log.info("Update checker started (repo=%s every %ds)", REPO, CHECK_INTERVAL)
    return t


# ── Executor ────────────────────────────────────────────────────────────────

def _append_log(line: str) -> None:
    line = line.rstrip()
    if not line:
        return
    with _state_lock:
        update_state["log_tail"].append(line)
        # Cap to last 200 lines.
        if len(update_state["log_tail"]) > 200:
            del update_state["log_tail"][:-200]
    _socketio_emit("update_log", {"line": line, "ts": time.time()})


def run_update() -> dict:
    """
    Execute the OS-level update script and stream its output into
    `update_state`. Returns the final state dict.
    """
    with _state_lock:
        if update_state["in_progress"]:
            return {"error": "update already in progress", **update_state}
        update_state.update({
            "in_progress": True,
            "started_at":  time.time(),
            "finished_at": None,
            "exit_code":   None,
            "log_tail":    [],
        })

    if not UPDATE_SCRIPT.exists():
        msg = f"update script not found at {UPDATE_SCRIPT}"
        log.error(msg)
        _append_log("[ERROR] " + msg)
        with _state_lock:
            update_state["in_progress"] = False
            update_state["exit_code"]   = 127
            update_state["finished_at"] = time.time()
        return dict(update_state)

    _socketio_emit("update_started", {"started_at": update_state["started_at"]})

    def _runner() -> None:
        try:
            proc = subprocess.Popen(
                ["bash", str(UPDATE_SCRIPT)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert proc.stdout is not None
            deadline = time.time() + UPDATE_TIMEOUT
            for raw_line in proc.stdout:
                _append_log(raw_line)
                if time.time() > deadline:
                    proc.kill()
                    _append_log("[ABORT] update timeout exceeded")
                    break
            rc = proc.wait(timeout=10)
        except Exception as exc:
            _append_log(f"[EXCEPTION] {exc}")
            rc = 1
        finally:
            with _state_lock:
                update_state["in_progress"] = False
                update_state["exit_code"]   = rc
                update_state["finished_at"] = time.time()
            _socketio_emit("update_finished", {
                "exit_code":   rc,
                "finished_at": update_state["finished_at"],
            })

    threading.Thread(target=_runner, daemon=True, name="wd-update-runner").start()
    return dict(update_state)


def get_status() -> dict:
    with _state_lock:
        return dict(update_state)
