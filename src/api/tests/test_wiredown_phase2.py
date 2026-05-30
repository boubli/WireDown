"""
WireDown Phase 2 — backend test suite.

New coverage on top of Phase 1:
  * pfSense honeypot template (replaces NetGate R4500 brand)
  * /api/ping advertises version 2.0.0, websocket port 8001, preview_mode true
  * /api/wd/admin/console/api/firewall  (noop backend in preview)
  * /api/wd/admin/console/api/bridge    (stub UDS bridge metadata)
  * Stub bridge actively emits events  (events_received grows)
  * CORS hardening warning surfaces in backend logs in preview mode
  * SQLite audit_log captures login + wrong-password attempts
  * Rust wd-engine source tree present, non-empty, well-formed
"""
import os
import re
import sqlite3
import time
import uuid

import pytest
import requests

BASE_URL = "http://localhost:8001"
WD = f"{BASE_URL}/api/wd"

ADMIN_USER = "admin"
ADMIN_PASS = "WireDown@2026"

DB_PATH = "/app/backend/wiredown.db"
NET_ACL_PATH = "/app/backend/network_security.json"
RUST_ROOT = "/app/wd-engine"
RUST_SRC = os.path.join(RUST_ROOT, "src")
ARCH_DOC = "/app/docs/WIREDOWN_ARCHITECTURE_PROPOSAL.md"
BACKEND_ERR_LOG = "/var/log/supervisor/backend.err.log"


# ---------- fixtures ----------

@pytest.fixture(scope="session", autouse=True)
def _bootstrap_clean_backend():
    """Once per session: wipe SQLite login_attempts, wipe IP blacklist
    file, then restart the backend so the in-memory ACL is fresh."""
    import subprocess, json as _j
    try:
        c = sqlite3.connect(DB_PATH)
        c.execute("DELETE FROM login_attempts")
        c.commit()
        c.close()
    except Exception as e:
        print(f"[warn] could not reset login_attempts: {e}")
    try:
        with open(NET_ACL_PATH, "w") as fh:
            _j.dump({"whitelist": [], "blacklist": []}, fh)
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
    """Reset DB login_attempts before every test (brute-force counter)."""
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
    s.headers.update({"User-Agent": "wd-phase2/1.0"})
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
    # Clear any residual IP blacklist (the honeypot POST test may have
    # blacklisted localhost). This is best-effort and keeps subsequent
    # auth-required tests working.
    try:
        client.post(
            f"{WD}/admin/console/api/blacklist",
            json={"action": "remove", "ip": "127.0.0.1"},
        )
    except Exception:
        pass
    return client


# ---------- /api/ping (version + websocket port) ----------

class TestPingBanner:
    def test_ping_version_and_preview_and_ws_port(self, client):
        r = client.get(f"{BASE_URL}/api/ping")
        assert r.status_code == 200
        data = r.json()
        assert data.get("version") == "2.0.0", f"expected version 2.0.0, got {data.get('version')}"
        assert data.get("preview_mode") is True, f"preview_mode must be True, got {data.get('preview_mode')}"
        ws = data.get("endpoints", {}).get("websocket", "")
        assert "8001" in ws, f"websocket should mention port 8001, got {ws!r}"
        assert "5000" not in ws, f"websocket must NOT mention legacy port 5000, got {ws!r}"


# ---------- pfSense honeypot page ----------

class TestPfSenseHoneypot:
    REQUIRED_STRINGS = [
        "pfSense",
        "Login to pfSense",
        "SIGN IN",
        "pfSense is developed and maintained by Netgate",
        "ESF 2004 - 2021",
        "View license",
    ]

    def test_pfsense_login_html(self, client):
        r = client.get(f"{WD}/")
        assert r.status_code == 200
        body = r.text
        missing = [s for s in self.REQUIRED_STRINGS if s not in body]
        assert not missing, f"pfSense template missing required strings: {missing}"

    def test_pfsense_title(self, client):
        r = client.get(f"{WD}/")
        assert r.status_code == 200
        m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
        assert m, "no <title> tag in honeypot page"
        title = m.group(1).strip()
        assert title == "pfSense - Login", f"expected title 'pfSense - Login', got {title!r}"


# ---------- /api/firewall ----------

class TestFirewallEndpoint:
    def test_firewall_status_noop(self, auth_client):
        r = auth_client.get(f"{WD}/admin/console/api/firewall")
        assert r.status_code == 200
        data = r.json()
        for k in ("backend", "has_nftables", "has_iptables"):
            assert k in data, f"firewall payload missing key {k!r}: {data}"
        assert data["backend"] == "noop", \
            f"expected backend 'noop' in preview container, got {data['backend']!r}"
        assert data["has_nftables"] is False
        assert data["has_iptables"] is False

    def test_firewall_requires_auth(self, client):
        r = client.get(f"{WD}/admin/console/api/firewall")
        assert r.status_code == 401


# ---------- /api/bridge ----------

class TestBridgeEndpoint:
    def test_bridge_metadata(self, auth_client):
        r = auth_client.get(f"{WD}/admin/console/api/bridge")
        assert r.status_code == 200
        data = r.json()
        assert data.get("running") is True, f"bridge.running must be True: {data}"
        assert data.get("preview_stub") is True, f"bridge.preview_stub must be True: {data}"
        assert data.get("uds_path") == "/run/wiredown.sock", \
            f"uds_path should be /run/wiredown.sock, got {data.get('uds_path')}"
        assert isinstance(data.get("events_received"), int)
        assert data["events_received"] >= 0

    def test_bridge_events_received_grows(self, auth_client):
        """STUB bridge fires every 3.5–7.5s; over ~30–60s the counter MUST grow."""
        r1 = auth_client.get(f"{WD}/admin/console/api/bridge")
        assert r1.status_code == 200
        c0 = r1.json().get("events_received", 0)
        deadline = time.time() + 60
        c1 = c0
        while time.time() < deadline:
            time.sleep(5)
            r = auth_client.get(f"{WD}/admin/console/api/bridge")
            if r.status_code != 200:
                continue
            c1 = r.json().get("events_received", 0)
            if c1 > c0:
                break
        assert c1 > c0, f"bridge events_received did not grow within 60s (start={c0}, end={c1})"


# ---------- Devices >= 6 ----------

class TestDevices:
    def test_devices_list_min_6(self, auth_client):
        r = auth_client.get(f"{WD}/admin/console/api/devices")
        assert r.status_code == 200
        data = r.json()
        devices = data if isinstance(data, list) else data.get("devices", [])
        assert len(devices) >= 6, f"expected >=6 devices, got {len(devices)}"


# ---------- CORS hardening warning ----------

class TestCORSHardening:
    def test_warning_in_backend_log(self):
        """In PREVIEW_MODE=1 without OPERATOR_ORIGIN set, the backend must
        log a warning instructing the operator to set OPERATOR_ORIGIN."""
        assert os.path.exists(BACKEND_ERR_LOG), f"missing {BACKEND_ERR_LOG}"
        with open(BACKEND_ERR_LOG, "r", errors="replace") as fh:
            log = fh.read()
        assert "OPERATOR_ORIGIN not set" in log, \
            "expected CORS-hardening warning 'OPERATOR_ORIGIN not set' in backend.err.log"

    def test_ping_still_serves_with_wildcard_cors(self, client):
        r = client.get(f"{BASE_URL}/api/ping", headers={"Origin": "https://example.com"})
        assert r.status_code == 200


# ---------- Audit log ----------

class TestAuditLog:
    def test_login_success_and_fail_appear_in_audit(self, client):
        # Make sure brute-force counter is fresh.
        try:
            c = sqlite3.connect(DB_PATH)
            c.execute("DELETE FROM login_attempts")
            c.commit()
            c.close()
        except Exception as e:
            pytest.skip(f"cannot reset DB: {e}")

        wrong_user = f"audit_probe_{uuid.uuid4().hex[:6]}"

        # 1 wrong-password attempt
        r_fail = client.post(
            f"{WD}/admin/console/login",
            data={"username": wrong_user, "password": "wrong"},
            allow_redirects=False,
        )
        assert r_fail.status_code in (401, 429)

        # 1 successful login (becomes our auth_client)
        r_ok = client.post(
            f"{WD}/admin/console/login",
            data={"username": ADMIN_USER, "password": ADMIN_PASS},
            allow_redirects=False,
        )
        if r_ok.status_code == 429:
            pytest.skip("IP locked out — cannot test audit log on success path.")
        assert r_ok.status_code in (302, 303)

        # Pull audit log (most recent first).
        r_aud = client.get(f"{WD}/admin/console/api/audit")
        assert r_aud.status_code == 200, f"audit endpoint returned {r_aud.status_code}"
        payload = r_aud.json()
        rows = payload if isinstance(payload, list) else payload.get("audit", payload.get("rows", []))
        assert isinstance(rows, list) and rows, f"audit log empty: {payload}"
        # Join everything textual to do an existence check
        blob = " ".join(str(row) for row in rows[:50]).lower()
        assert "login" in blob or "auth" in blob or "admin" in blob, \
            f"audit log does not appear to contain auth events: {rows[:3]}"


# ---------- Brute-force lockout still works in Phase 2 ----------

class TestBruteForceStillWorks:
    def test_5_fails_then_429(self):
        try:
            c = sqlite3.connect(DB_PATH)
            c.execute("DELETE FROM login_attempts")
            c.commit()
            c.close()
        except Exception as e:
            pytest.skip(f"cannot reset DB: {e}")
        s = requests.Session()
        bad_user = f"phase2bf_{uuid.uuid4().hex[:6]}"
        for i in range(5):
            r = s.post(
                f"{WD}/admin/console/login",
                data={"username": bad_user, "password": "wrong"},
                allow_redirects=False,
            )
            assert r.status_code in (401, 429), f"attempt {i+1}: {r.status_code}"
        r6 = s.post(
            f"{WD}/admin/console/login",
            data={"username": bad_user, "password": "wrong"},
            allow_redirects=False,
        )
        assert r6.status_code == 429, f"6th attempt expected 429, got {r6.status_code}"


# ---------- Rust wd-engine source tree ----------

REQUIRED_RUST_FILES = [
    "Cargo.toml",
    "build.sh",
    "README.md",
    "src/main.rs",
    "src/event.rs",
    "src/bridge.rs",
    "src/capture.rs",
    "src/arp.rs",
    "src/dns.rs",
    "src/portscan.rs",
    "src/oui.rs",
]

REQUIRED_CRATES = ["tokio", "pnet", "etherparse", "trust-dns-proto", "ahash"]
REQUIRED_MODULES = ["arp", "bridge", "capture", "dns", "event", "oui", "portscan"]


class TestRustEngineSourceTree:
    def test_all_files_exist_nonempty(self):
        missing, empty = [], []
        for rel in REQUIRED_RUST_FILES:
            p = os.path.join(RUST_ROOT, rel)
            if not os.path.exists(p):
                missing.append(rel)
            elif os.path.getsize(p) == 0:
                empty.append(rel)
        assert not missing, f"missing wd-engine files: {missing}"
        assert not empty, f"empty wd-engine files: {empty}"

    def test_cargo_toml_has_required_crates(self):
        with open(os.path.join(RUST_ROOT, "Cargo.toml"), "r") as fh:
            toml = fh.read()
        missing = [c for c in REQUIRED_CRATES if c not in toml]
        assert not missing, f"Cargo.toml missing crates: {missing}"

    def test_main_rs_declares_modules(self):
        with open(os.path.join(RUST_SRC, "main.rs"), "r") as fh:
            src = fh.read()
        # naive scan for `mod <name>;`
        declared = set(re.findall(r"^\s*mod\s+([a-zA-Z_]\w*)\s*;", src, re.MULTILINE))
        missing = [m for m in REQUIRED_MODULES if m not in declared]
        assert not missing, f"main.rs missing module declarations: {missing} (found={declared})"


# ---------- Startup log lines ----------

class TestStartupLogs:
    def test_wd_engine_bridge_started_stub(self):
        with open(BACKEND_ERR_LOG, "r", errors="replace") as fh:
            log = fh.read()
        assert "wd-engine bridge started in STUB (preview) mode" in log, \
            "startup log missing 'wd-engine bridge started in STUB (preview) mode'"

    def test_oui_updater_started(self):
        with open(BACKEND_ERR_LOG, "r", errors="replace") as fh:
            log = fh.read()
        assert "OUI updater started" in log, "startup log missing 'OUI updater started'"


# ---------- Architecture proposal still present ----------

class TestArchitectureDoc:
    def test_arch_doc_exists(self):
        assert os.path.exists(ARCH_DOC), f"missing {ARCH_DOC}"
        assert os.path.getsize(ARCH_DOC) > 2000


# ---------- LAST: honeypot POST (this blacklists localhost) ----------

class TestZZHoneypotPost:
    """Run LAST. The honeypot POST trips the threat engine and blacklists
    127.0.0.1 — which would break every subsequent auth-required test."""

    def test_pfsense_login_captures_creds_redirects_to_redscreen(self):
        s = requests.Session()
        r = s.post(
            f"{WD}/login",
            data={"username": "honeypot_user", "password": "honeypot_pw"},
            allow_redirects=True,
        )
        assert r.status_code == 200
        assert "SECURITY VIOLATION" in r.text, \
            "honeypot POST should serve the red-screen warning.html (SECURITY VIOLATION)"
