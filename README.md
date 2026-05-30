<div align="center">
  <img src="wiredown-honeypot-logo.png" alt="WireDown Network Security Appliance Logo" width="200" height="200">
  <h1>WireDown</h1>
  <p><strong>Ultra-lightweight, high-performance network security appliance for Proxmox LXC and VMs.</strong></p>
</div>

[![Version](https://img.shields.io/badge/release-V1.0.0.3-1d3556?style=flat-square)](https://github.com/boubli/WireDown/releases/latest)
[![Footprint](https://img.shields.io/badge/RAM-%3C%20512%20MB-5cb85c?style=flat-square)](ARCHITECTURE.md)
[![Engine](https://img.shields.io/badge/data%20plane-Rust%20%E2%9A%99%20musl-orange?style=flat-square)](src/engine/)
[![Control plane](https://img.shields.io/badge/control%20plane-Flask%20%2B%20SQLite-2c5b8e?style=flat-square)](src/api/)

---

## What it is

WireDown is a **drop-in network watchdog** that lives on a tiny Proxmox LXC or VM and does three things at the same time:

1. **Passively maps your LAN** — every ARP reply and DHCP lease is parsed without ever sending a probe, so you get a real-time `Global_Device_Registry` (IP / MAC / OUI vendor / hostname) without spamming your network.
2. **Sinkholes hostile DNS** — built-in DNS server intercepts queries against a blocklist (DGA / C2 / known-bad domains) and answers them with the appliance's own IP, so any beaconing client lands on the **red-screen deterrent** instead of its operator.
3. **Lures and contains attackers** — port 80 serves a **pixel-perfect pfSense (Netgate) honeypot login**. Any credential POST flags the source IP, kernel-firewalls it via `nftables` / `iptables`, and shows them a forensic dump of what we already know about them.

The entire stack is engineered for ≤ 512 MB RAM and 1 vCPU.

---

## 1-Click install (Proxmox)

The installer always pulls the **latest release** from the GitHub API — no hard-coded versions.

### LXC (recommended, smaller footprint)
```bash
# On the Proxmox host:
bash <(curl -sSL https://raw.githubusercontent.com/boubli/WireDown/main/deploy/proxmox-lxc.sh)
```

### VM (better isolation, slightly heavier)
```bash
# On the Proxmox host:
bash <(curl -sSL https://raw.githubusercontent.com/boubli/WireDown/main/deploy/proxmox-vm.sh)
```

After ~3 minutes the script prints:

```
Honeypot (NetGate/pfSense bait) :  http://<lxc-ip>/
Admin console (hidden)          :  http://<lxc-ip>/admin/console/login
Default credentials             :  see /var/log/wiredown-api.log
1-click updates                 :  Admin Console → "Update Available"
```

---

## 1-Click update (in-place)

Open the admin console → an **Update Available** banner appears the moment a newer GitHub release is published → click **1-Click Update**.

Under the hood:

1. Backend background task hits `https://api.github.com/repos/boubli/WireDown/releases/latest` every hour.
2. When a newer tag is found, `update_available=true` is broadcast over Socket.IO + appears on the dashboard.
3. Clicking the button hits `POST /admin/console/api/system/update`, which runs `deploy/proxmox-update.sh` — atomic stage → swap → restart `wd-engine` + `wiredown-api`.
4. The dashboard reloads automatically when `exit_code = 0`.

---

## Architecture (V1.0.0.3)

```
┌── LAN ─────────────────────────────────────────────────────┐
│  br0  (promisc bridge)                                      │
└─────────────┬───────────────────────────────────────────────┘
              │ AF_PACKET (TPACKET_V3, zero-copy, 1 MB ring)
              ▼
   ┌──────────────────────────────┐
   │  wd-engine (Rust, musl)      │  ≈ 10 MB RAM
   │  - ARP / DHCP parser         │
   │  - DNS sinkhole on udp/53    │
   │  - SYN-burst portscan        │
   │  - OUI vendor lookup         │
   └────────────┬─────────────────┘
                │ NDJSON over /run/wiredown.sock
                ▼
   ┌──────────────────────────────┐
   │  Control plane (FastAPI/     │  ≈ 45 MB RAM
   │  Flask + Socket.IO + SQLite) │
   │  - /                         │  ← pfSense honeypot
   │  - /warning                  │  ← red-screen deterrent
   │  - /admin/console/*          │  ← hidden SOC dashboard
   │  - /api/system/update*       │  ← 1-click update API
   └────────────┬─────────────────┘
                │ nftables / iptables
                ▼
             Threat IPs blackholed
```

Full design rationale: [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Repository layout

```
WireDown/
├── VERSION                    # canonical semver — drives the update banner
├── README.md
├── ARCHITECTURE.md
├── docker-compose.yml
├── deploy/
│   ├── proxmox-lxc.sh         # 1-click LXC installer (dynamic GitHub API)
│   ├── proxmox-vm.sh          # 1-click VM installer  (dynamic GitHub API)
│   ├── proxmox-update.sh      # In-place atomic updater
│   ├── wd-engine.service      # systemd unit for the Rust data plane
│   └── wiredown-api.service   # systemd unit for the control plane
└── src/
    ├── engine/                # Rust crate — the data plane
    │   ├── Cargo.toml
    │   ├── build.sh
    │   └── src/
    │       ├── main.rs        # tokio runtime, UDS server, dispatcher
    │       ├── capture.rs     # AF_PACKET + etherparse decoder
    │       ├── arp.rs         # passive ARP + DHCP parsing
    │       ├── dns.rs         # sinkhole + upstream relay
    │       ├── portscan.rs    # SYN-burst heuristic
    │       ├── oui.rs         # IEEE OUI vendor lookup
    │       ├── bridge.rs      # NDJSON-over-UDS to control plane
    │       └── event.rs       # serde event types
    ├── api/                   # Python control plane
    │   ├── server.py          # ASGI entrypoint (uvicorn :8080)
    │   ├── app.py             # Flask app + Socket.IO + threat engine
    │   ├── db.py              # SQLite + bcrypt + audit_log
    │   ├── real_admin.py      # hidden /admin/console + REST + 1-click update
    │   ├── fake_admin.py      # honeypot at /
    │   ├── firewall.py        # nftables / iptables auto-detect
    │   ├── wd_engine_bridge.py# UDS reader + preview-mode stub
    │   ├── oui_updater.py     # monthly IEEE OUI refresh
    │   └── update_service.py  # GitHub poller + 1-click executor
    └── ui/                    # UI templates and assets
        ├── templates/
        │   ├── admin_login.html # pfSense clone HTML
        │   ├── warning.html   # red-screen warning page
        │   └── real_admin/    # SOC dashboard templates
        └── static/            # Stylesheets and JS assets
```

---

## Configuration

Everything is driven by env vars; sensible defaults exist for all of them.

| Env var | Default | Purpose |
|--------|---------|---------|
| `ADMIN_USERNAME` | `admin` | Auto-provisioned admin (first boot only). |
| `ADMIN_PASSWORD` | *auto-generated* | If unset, a strong random password is printed once to the log. |
| `OPERATOR_ORIGIN` | *(none — same-origin)* | Lock CORS for the SOC console to your operator URL. |
| `WD_GITHUB_REPO` | `boubli/WireDown` | Source for the 1-click updater. |
| `WD_UPDATE_CHECK_INTERVAL_SEC` | `3600` | How often to poll GitHub for new releases. |
| `WD_OUI_URL` | IEEE master | OUI table refresh source. |
| `WD_OUI_REFRESH_DAYS` | `30` | OUI table refresh cadence. |
| `WD_ENGINE_UDS` | `/run/wiredown.sock` | UDS path between Rust engine + Python control. |
| `PREVIEW_MODE` | auto | `1` skips raw-socket services (useful for sandbox/dev). |

---

## Security model

- **Bcrypt** (cost = 12) for admin credentials.
- **Brute-force lockout** — 5 failed attempts per IP within 15 minutes → HTTP 429 for the remaining window. Tracked in SQLite.
- **Hidden admin route** — `/admin/console/*` returns `404 Not Found` to any IP that is not on the operator whitelist (configurable).
- **Append-only audit log** — every login, every firewall rule change, every system update is written to SQLite and streamed to the dashboard via Socket.IO.
- **systemd hardening** — `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectKernelTunables`, capped `MemoryMax`.

---

## License

MIT.

---

## Status

This is V1.0.0.3 — the first official LXC/VM release. WireDown is strictly a native Proxmox LXC/VM appliance.
