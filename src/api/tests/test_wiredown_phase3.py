"""
WireDown Phase 3 (V1.0.0.3) — backend test suite.

New coverage on top of Phase 1 & 2:
  * Pixel-perfect pfSense honeypot template at GET /api/wd/
  * Filesystem cleanup (no legacy /app/platforms, /app/core, etc.)
  * /app/VERSION == V1.0.0.3
  * /app/deploy/ contents + dynamic GitHub installer scripts
  * 1-Click Update service:
        - /admin/console/api/system/update-status (GET, auth)
        - /admin/console/api/system/update-check  (POST, auth)
        - /admin/console/api/system/update        (POST, auth)
        - unauthenticated variants -> 401
  * Dashboard banner data-testids
  * Audit log captures system_update_check + system_update_triggered
  * /app/README.md + /app/GIT_CLEANUP.md content checks
  * Phase 1+2 regression smoke
  * Honeypot POST still serves SECURITY VIOLATION red-screen (runs LAST)
"""
import json
import os
import re
import sqlite3
import stat
import subprocess
import time
import uuid

import pytest
import requests

BASE_URL = "http://localhost:8001"
WD = f"{BASE_URL}/api/wd"

ADMIN_USER = "admin"
ADMIN_PASS = "WireDown@2026"

DB_PATH = "/app/src/api/wiredown.db"
NET_ACL_PATH = "/app/src/api/network_security.json"
DEPLOY_DIR = "/app/deploy"
VERSION_FILE = "/app/VERSION"
EXPECTED_VERSION = "V1.0.0.3"


# ---------- fixtures ----------

@pytest.fixture(scope="session", autouse=True)
def _bootstrap_clean_backend():
    """Reset login_attempts + IP ACL + bounce backend so blacklist (caused
    by any prior honeypot-POST test) is gone."""
    try:
        c = sqlite3.connect(DB_PATH)
        c.execute("DELETE FROM login_attempts")
        c.commit()
        c.close()
    except Exception as e:
        print(f"[warn] could not reset login_attempts: {e}")
    try:
        with open(NET_ACL_PATH, "w") as fh:
            json.dump({"whitelist": [], "blacklist": []}, fh)
    except Exception as e:
        print(f"[warn] could not reset network_security.json: {e}")
    try:
        subprocess.run(["sudo", "supervisorctl", "restart", "backend"],
                       check=False, timeout=15)
        time.sleep(5)
    except Exception as e:
        print(f"[warn] could not restart backend: {e}")
    yield


@pytest.fixture(autouse=True)
def _reset_login_attempts_each_test():
    try:
        c = sqlite3.connect(DB_PATH)
        c.execute("DELETE FROM login_attempts")
        c.commit()
        c.close()
    except Exception:
        pass
    yield


@pytest.fixture
def client():
    s = requests.Session()
    s.headers.update({"User-Agent": "wd-phase3/1.0"})
    return s


@pytest.fixture
def auth_client(client):
    r = client.post(
        f"{WD}/admin/console/login",
        data={"username": ADMIN_USER, "password": ADMIN_PASS},
        allow_redirects=False,
    )
    if r.status_code == 429:
        pytest.skip("IP locked out from prior test runs (HTTP 429).")
    assert r.status_code in (302, 303), f"expected redirect after login, got {r.status_code}"
    try:
        client.post(f"{WD}/admin/console/api/blacklist",
                    json={"action": "remove", "ip": "127.0.0.1"})
    except Exception:
        pass
    return client


# ---------- 1. pfSense honeypot template ----------

class TestPfSenseHoneypotV3:
    REQUIRED = [
        "pfSense",
        "SIGN IN",
        "netgate.rocks",
        "2004 - 2017",
        "Rubicon Communications",
        "view license",
    ]

    def test_required_strings_present(self, client):
        r = client.get(f"{WD}/")
        assert r.status_code == 200, f"GET /api/wd/ -> {r.status_code}"
        body = r.text
        missing = [s for s in self.REQUIRED if s not in body]
        assert not missing, f"pfSense template missing required strings: {missing}"

    def test_title_exact(self, client):
        r = client.get(f"{WD}/")
        assert r.status_code == 200
        m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
        assert m, "no <title> tag found in honeypot page"
        assert m.group(1).strip() == "pfSense - Login"


# ---------- 2. (ESP32 shim removed in V1.0.0.3) ----------


# ---------- 3. Filesystem cleanup ----------

class TestFilesystemCleanup:
    FORBIDDEN_PATHS = [
        "/app/platforms",
        "/app/core",
        "/app/src/api/esp32_flasher.py",
        "/app/scripts/install_arduino_cli.sh",
        "/app/.env.example",
    ]

    @pytest.mark.parametrize("path", FORBIDDEN_PATHS)
    def test_path_absent(self, path):
        assert not os.path.exists(path), f"legacy path should be removed: {path}"


# ---------- 4. VERSION file ----------

class TestVersionFile:
    def test_version_is_v1003(self):
        with open(VERSION_FILE, "r") as fh:
            content = fh.read().strip()
        assert content == EXPECTED_VERSION, \
            f"expected VERSION={EXPECTED_VERSION!r}, got {content!r}"


# ---------- 5. /app/deploy contents ----------

class TestDeployArtifacts:
    REQUIRED_FILES = [
        "proxmox-lxc.sh",
        "proxmox-vm.sh",
        "proxmox-update.sh",
        "wd-engine.service",
        "wiredown-api.service",
        "RELEASE_NOTES.md",
    ]
    EXECUTABLE = ["proxmox-lxc.sh", "proxmox-vm.sh", "proxmox-update.sh"]

    @pytest.mark.parametrize("name", REQUIRED_FILES)
    def test_file_exists(self, name):
        p = os.path.join(DEPLOY_DIR, name)
        assert os.path.isfile(p), f"missing deploy artifact: {p}"

    @pytest.mark.parametrize("name", EXECUTABLE)
    def test_file_executable(self, name):
        p = os.path.join(DEPLOY_DIR, name)
        st = os.stat(p)
        assert st.st_mode & stat.S_IXUSR, f"{p} is not executable (mode={oct(st.st_mode)})"


# ---------- 6. Installer scripts use GitHub API dynamically ----------

class TestInstallerScripts:
    LXC = os.path.join(DEPLOY_DIR, "proxmox-lxc.sh")
    VM  = os.path.join(DEPLOY_DIR, "proxmox-vm.sh")
    UPD = os.path.join(DEPLOY_DIR, "proxmox-update.sh")

    HARD_VERSION_RX = re.compile(r"\bV1\.0\.0(?:\.\d+)?\b")

    def _read(self, p):
        with open(p, "r") as fh:
            return fh.read()

    def test_lxc_dynamic_fetch(self):
        body = self._read(self.LXC)
        assert "api.github.com/repos/" in body
        assert "releases/latest" in body

    def test_vm_dynamic_fetch(self):
        body = self._read(self.VM)
        assert "api.github.com/repos/" in body
        assert "releases/latest" in body

    def _no_hardcoded_version_outside_comments(self, body, fname):
        offending = []
        for i, line in enumerate(body.splitlines(), 1):
            stripped = line.strip()
            # ignore pure-comment lines
            if stripped.startswith("#"):
                continue
            # allow log/echo-only output of any version (those are
            # informational; the API result is still authoritative).
            if re.match(r"^(echo|log|printf|say)\b", stripped):
                continue
            if self.HARD_VERSION_RX.search(line):
                offending.append((i, line.rstrip()))
        assert not offending, \
            f"{fname} has hard-coded version strings outside comment/log: {offending[:3]}"

    def test_lxc_no_hardcoded_version(self):
        self._no_hardcoded_version_outside_comments(self._read(self.LXC), "proxmox-lxc.sh")

    def test_vm_no_hardcoded_version(self):
        self._no_hardcoded_version_outside_comments(self._read(self.VM), "proxmox-vm.sh")

    def test_update_script_dynamic_and_atomic(self):
        body = self._read(self.UPD)
        assert "api.github.com" in body, "proxmox-update.sh missing api.github.com"
        assert "tarball_url" in body, "proxmox-update.sh missing tarball_url"
        assert "systemctl restart wd-engine" in body, \
            "proxmox-update.sh must restart wd-engine"
        assert "systemctl restart wiredown-api" in body, \
            "proxmox-update.sh must restart wiredown-api"
        # atomic 'mv' staging pattern
        assert re.search(r"^\s*mv\s+", body, re.MULTILINE), \
            "proxmox-update.sh missing atomic mv staging pattern"


# ---------- 7. /api/system/update-status ----------

class TestUpdateStatus:
    URL = f"{WD}/admin/console/api/system/update-status"

    REQUIRED_KEYS = {
        "current_version", "latest_version", "update_available",
        "last_checked", "in_progress", "log_tail",
    }

    def test_unauth_401(self, client):
        r = client.get(self.URL)
        assert r.status_code == 401, f"unauth update-status -> {r.status_code}"

    def test_auth_returns_state(self, auth_client):
        r = auth_client.get(self.URL)
        assert r.status_code == 200, f"auth update-status -> {r.status_code}"
        data = r.json()
        missing = self.REQUIRED_KEYS - set(data.keys())
        assert not missing, f"update-status missing keys: {missing}; payload={data}"
        assert data["current_version"] == EXPECTED_VERSION, \
            f"current_version expected {EXPECTED_VERSION}, got {data['current_version']!r}"
        assert isinstance(data["log_tail"], list)


# ---------- 8. /api/system/update-check (forces GitHub poll) ----------

class TestUpdateCheck:
    URL_CHECK  = f"{WD}/admin/console/api/system/update-check"
    URL_STATUS = f"{WD}/admin/console/api/system/update-status"

    def test_unauth_401(self, client):
        r = client.post(self.URL_CHECK)
        assert r.status_code == 401

    def test_auth_check_advances_last_checked(self, auth_client):
        before = time.time()
        r = auth_client.post(self.URL_CHECK)
        assert r.status_code == 200, f"update-check -> {r.status_code} body={r.text[:200]}"
        time.sleep(0.5)
        r2 = auth_client.get(self.URL_STATUS)
        assert r2.status_code == 200
        data = r2.json()
        last = float(data.get("last_checked") or 0)
        # last_checked must be within ~5s of "now" (we just polled)
        assert abs(time.time() - last) < 5.0, \
            f"last_checked {last} not within 5s of now {time.time()}"
        assert last >= before - 1, "last_checked did not advance"


# ---------- 9. /api/system/update executor ----------

class TestUpdateExecutor:
    URL_UPDATE = f"{WD}/admin/console/api/system/update"
    URL_STATUS = f"{WD}/admin/console/api/system/update-status"

    def test_unauth_401(self, client):
        r = client.post(self.URL_UPDATE)
        assert r.status_code == 401

    def test_auth_triggers_update_and_logs(self, auth_client):
        r = auth_client.post(self.URL_UPDATE)
        assert r.status_code == 200, f"update -> {r.status_code} body={r.text[:200]}"
        data = r.json()
        # initial response should mark in_progress=true OR have exit_code set if
        # the script returned immediately (127 for missing /opt/wiredown).
        # The runner thread starts immediately so we only require *some* state.
        assert "in_progress" in data
        # Wait up to ~10s for the runner to finish (script exits 127 fast).
        deadline = time.time() + 12
        final = data
        while time.time() < deadline:
            time.sleep(1)
            r2 = auth_client.get(self.URL_STATUS)
            if r2.status_code == 200:
                final = r2.json()
                if final.get("in_progress") is False:
                    break
        assert final.get("in_progress") is False, \
            f"update still in_progress after 12s: {final}"
        assert final.get("exit_code") is not None, \
            f"exit_code must be set after completion: {final}"
        assert isinstance(final.get("log_tail"), list)
        assert len(final["log_tail"]) >= 1, \
            f"log_tail should have >=1 line, got {final.get('log_tail')}"


# ---------- 10. Dashboard data-testids ----------

class TestDashboardBanner:
    DASH = f"{WD}/admin/console/dashboard"
    REQ_TESTIDS = [
        'data-testid="update-banner"',
        'data-testid="update-install-btn"',
        'data-testid="update-latest-version"',
        'data-testid="update-dismiss-btn"',
    ]

    def test_dashboard_contains_banner_markup(self, auth_client):
        r = auth_client.get(self.DASH)
        assert r.status_code == 200, f"dashboard -> {r.status_code}"
        body = r.text
        missing = [t for t in self.REQ_TESTIDS if t not in body]
        assert not missing, f"dashboard missing data-testids: {missing}"
        assert "/admin/console/api/system/update" in body, \
            "dashboard must reference /admin/console/api/system/update"


# ---------- 11. Audit log captures update events ----------

class TestAuditLogUpdates:
    URL_CHECK  = f"{WD}/admin/console/api/system/update-check"
    URL_UPDATE = f"{WD}/admin/console/api/system/update"
    URL_AUDIT  = f"{WD}/admin/console/api/audit"

    def test_check_and_trigger_appear_in_audit(self, auth_client):
        # Fire both
        r1 = auth_client.post(self.URL_CHECK)
        assert r1.status_code == 200
        r2 = auth_client.post(self.URL_UPDATE)
        assert r2.status_code == 200
        time.sleep(1)
        # Fetch audit
        r3 = auth_client.get(self.URL_AUDIT)
        assert r3.status_code == 200, f"audit -> {r3.status_code}"
        payload = r3.json()
        rows = payload if isinstance(payload, list) else \
               payload.get("audit", payload.get("rows", []))
        assert isinstance(rows, list) and rows, f"audit empty: {payload}"
        actions = []
        for row in rows[:100]:
            if isinstance(row, dict):
                act = row.get("action") or row.get("event") or ""
                actions.append(act)
            else:
                actions.append(str(row))
        blob = " ".join(actions)
        assert "system_update_check" in blob, \
            f"audit missing 'system_update_check': sample={actions[:10]}"
        assert "system_update_triggered" in blob, \
            f"audit missing 'system_update_triggered': sample={actions[:10]}"


# ---------- 12. Docs ----------

class TestDocs:
    def test_readme_v3(self):
        p = "/app/README.md"
        assert os.path.exists(p), f"missing {p}"
        body = open(p).read()
        for needle in ["V1.0.0.3", "proxmox-lxc.sh", "1-Click Update", "pfSense"]:
            assert needle in body, f"/app/README.md missing {needle!r}"

    def test_git_cleanup(self):
        p = "/app/GIT_CLEANUP.md"
        assert os.path.exists(p), f"missing {p}"
        body = open(p).read()
        for needle in ["git tag", "gh release delete", "V1.0.0.3"]:
            assert needle in body, f"/app/GIT_CLEANUP.md missing {needle!r}"


# ---------- 13. Phase 1+2 regression smoke ----------

class TestRegressionSmoke:
    def test_ping(self, client):
        r = client.get(f"{BASE_URL}/api/ping")
        assert r.status_code == 200
        data = r.json()
        assert data.get("version") == "2.0.0"
        assert data.get("preview_mode") is True

    def test_admin_login_redirects(self, client):
        r = client.post(
            f"{WD}/admin/console/login",
            data={"username": ADMIN_USER, "password": ADMIN_PASS},
            allow_redirects=False,
        )
        assert r.status_code in (302, 303), f"login -> {r.status_code}"

    def test_firewall_noop(self, auth_client):
        r = auth_client.get(f"{WD}/admin/console/api/firewall")
        assert r.status_code == 200
        assert r.json().get("backend") == "noop"

    def test_bridge_running(self, auth_client):
        r = auth_client.get(f"{WD}/admin/console/api/bridge")
        assert r.status_code == 200
        assert r.json().get("running") is True

    def test_phase2_rust_engine_present(self):
        for rel in ["Cargo.toml", "src/main.rs", "src/event.rs", "src/bridge.rs",
                    "src/capture.rs", "src/arp.rs", "src/dns.rs",
                    "src/portscan.rs", "src/oui.rs", "build.sh", "README.md"]:
            p = os.path.join("/app/src/engine", rel)
            assert os.path.exists(p) and os.path.getsize(p) > 0, \
                f"wd-engine source missing/empty: {rel}"


# ---------- 14. LAST: honeypot POST still serves red-screen ----------

class TestZZHoneypotPostV3:
    """Runs LAST — blacklists 127.0.0.1 via threat engine."""

    def test_honeypot_post_red_screen(self):
        s = requests.Session()
        r = s.post(f"{WD}/login",
                   data={"username": "honeypot_user", "password": "honeypot_pw"},
                   allow_redirects=True, timeout=10)
        assert r.status_code == 200
        assert "SECURITY VIOLATION" in r.text, \
            "honeypot POST should serve red-screen warning.html"
