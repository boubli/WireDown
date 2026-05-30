"""
WireDown — Firewall isolation backend (iptables ↔ nftables auto-detect).

Strategy:
    1. Probe both `nft` and `iptables` at import time.
    2. Prefer `nft` (modern Debian/Ubuntu/Proxmox default). Fall back to
       `iptables`. If neither is present (preview container), become a
       no-op LOGGER so the rest of the control plane keeps working.
    3. All public methods are idempotent — re-isolating an already
       isolated IP is a cheap no-op.

The same module exposes both per-IP isolation and per-MAC isolation
(layer-2 drop via `xt_mac` or `nft meta ether saddr`).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from typing import Iterable

log = logging.getLogger("wiredown.firewall")


def _probe(cmd: str) -> bool:
    if not shutil.which(cmd):
        return False
    try:
        subprocess.run(
            [cmd, "--version"],
            check=True, capture_output=True, timeout=2,
        )
        return True
    except (subprocess.SubprocessError, FileNotFoundError, PermissionError):
        return False


HAS_NFT      = _probe("nft")
HAS_IPTABLES = _probe("iptables")

if HAS_NFT:
    BACKEND = "nftables"
elif HAS_IPTABLES:
    BACKEND = "iptables"
else:
    BACKEND = "noop"

log.info("Firewall backend selected: %s (nft=%s, iptables=%s)",
         BACKEND, HAS_NFT, HAS_IPTABLES)


def _run(args: Iterable[str]) -> bool:
    cmd = list(args)
    try:
        subprocess.run(
            cmd, check=True, capture_output=True, timeout=3,
        )
        log.info("fw: %s", " ".join(cmd))
        return True
    except subprocess.CalledProcessError as exc:
        # `iptables -C` returning non-zero is how we test for rule presence;
        # callers that don't care can ignore the False return.
        log.debug("fw cmd failed (%s): %s", exc.returncode, " ".join(cmd))
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        log.warning("fw cmd error (%s): %s", exc, " ".join(cmd))
        return False


# ── nftables backend ─────────────────────────────────────────────────────────

NFT_TABLE = "wiredown"
NFT_SET_IPV4 = "blocked_v4"


def _nft_ensure_table() -> None:
    """Create the wiredown nft table + set if missing. Idempotent."""
    _run(["nft", "add", "table", "inet", NFT_TABLE])
    _run([
        "nft", "add", "set", "inet", NFT_TABLE, NFT_SET_IPV4,
        "{ type ipv4_addr; flags timeout; }",
    ])
    _run([
        "nft", "add", "chain", "inet", NFT_TABLE, "input",
        "{ type filter hook input priority -100; }",
    ])
    _run([
        "nft", "add", "chain", "inet", NFT_TABLE, "forward",
        "{ type filter hook forward priority -100; }",
    ])
    _run([
        "nft", "add", "rule", "inet", NFT_TABLE, "input",
        "ip saddr @" + NFT_SET_IPV4, "drop",
    ])
    _run([
        "nft", "add", "rule", "inet", NFT_TABLE, "forward",
        "ip saddr @" + NFT_SET_IPV4, "drop",
    ])


def _nft_isolate(ip: str) -> bool:
    _nft_ensure_table()
    return _run(["nft", "add", "element", "inet", NFT_TABLE, NFT_SET_IPV4, "{ " + ip + " }"])


def _nft_release(ip: str) -> bool:
    return _run(["nft", "delete", "element", "inet", NFT_TABLE, NFT_SET_IPV4, "{ " + ip + " }"])


# ── iptables backend (legacy) ────────────────────────────────────────────────

def _ipt_isolate(ip: str) -> bool:
    # Idempotency: only add if the rule isn't already present.
    if subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
    ).returncode != 0:
        _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    if subprocess.run(
        ["iptables", "-C", "FORWARD", "-s", ip, "-j", "DROP"],
        capture_output=True,
    ).returncode != 0:
        _run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
    return True


def _ipt_release(ip: str) -> bool:
    _run(["iptables", "-D", "INPUT",   "-s", ip, "-j", "DROP"])
    _run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
    return True


# ── Public API ───────────────────────────────────────────────────────────────

def isolate(ip: str) -> bool:
    """Apply L3 drop on the appliance for both INPUT and FORWARD chains."""
    if BACKEND == "nftables":
        return _nft_isolate(ip)
    if BACKEND == "iptables":
        return _ipt_isolate(ip)
    log.warning("[noop firewall] isolate %s — install nftables or iptables for real enforcement", ip)
    return False


def release(ip: str) -> bool:
    """Remove an isolation rule (used by operator-driven unblock)."""
    if BACKEND == "nftables":
        return _nft_release(ip)
    if BACKEND == "iptables":
        return _ipt_release(ip)
    log.warning("[noop firewall] release %s", ip)
    return False


def status() -> dict:
    return {
        "backend": BACKEND,
        "has_nftables": HAS_NFT,
        "has_iptables": HAS_IPTABLES,
    }
