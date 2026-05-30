# WireDown Architectural Documentation

## 1. High-Level Architecture & Concept

WireDown is a lightweight, low-footprint virtual network security appliance designed natively for Proxmox VE (LXC/VM). Its core objective is to monitor localized network traffic, host a convincing bait-and-switch deception layer (honeypot), block malicious network queries (DNS sinkhole), and isolate attackers automatically via firewall rules.

The system is split into two primary planes to maximize performance and separate privileges:
1. **The Data Plane (`src/engine/` - Rust)**: Runs as a high-performance, privileged daemon. It opens raw sockets to sniff frames, relays DNS queries, and streams parsed events via a Unix Domain Socket (UDS) bridge.
2. **The Control Plane (`src/api/` - Python/Flask)**: Runs as an ASGI application served by Uvicorn. It exposes a hidden administrative SOC dashboard, serves the decoy honeypot templates, processes security heuristics, and executes host firewall containment commands.

```
┌── LAN ─────────────────────────────────────────────────────┐
│  br0  (promisc bridge)                                     │
└─────────────┬──────────────────────────────────────────────┘
              │ AF_PACKET (zero-copy socket)
              ▼
   ┌──────────────────────────────┐
   │  wd-engine (Rust, musl)      │  ≈ 10 MB RAM
   │  - AF_PACKET Sniffer         │
   │  - ARP / DHCP parser         │
   │  - DNS sinkhole on udp/53    │
   │  - SYN-burst portscan        │
   └────────────┬─────────────────┘
                │ NDJSON over /run/wiredown.sock
                ▼
   ┌──────────────────────────────┐
   │  Control plane (Python/ASGI) │  ≈ 45 MB RAM
   │  - /                         │  ← NetGate honeypot bait
   │  - /warning                  │  ← deterrent red-screen
   │  - /admin/console/*          │  ← hidden SOC dashboard
   │  - /api/system/update*       │  ← 1-click update API
   └────────────┬─────────────────┘
                │ nftables / iptables
                ▼
             Threat IPs blackholed
```

---

## 2. The Data Plane: Rust Core (`src/engine/`)

The Rust engine is optimized to compile as a static `x86_64-unknown-linux-musl` binary, targetting a minimal RAM footprint (< 12MB). It spawns concurrent worker tasks using the Tokio asynchronous runtime:

- **`capture.rs` (AF_PACKET Sniffer)**: Bypasses the OS network stack by opening a raw socket using `AF_PACKET` (`SOCK_RAW`). It binds to the target bridge interface (e.g. `br0` or `eth0`) and uses `etherparse` to parse frame packets at OSI Layer 2.
- **`arp.rs` (Device Discovery)**: Passive parser that filters EtherType `0x0806` (ARP) and DHCP packets. It maps MAC-to-IP relationships and extracts hostname options from DHCP handshakes to dynamically build the device registry without active polling.
- **`dns.rs` (Sinkhole Engine)**: Starts a UDP listener on port 53. It inspects incoming DNS queries against an in-memory blocklist. Blocked queries return the appliance's IP address (redirecting attackers to the red-screen trap), while clean queries are relayed to the upstream resolver (e.g. Cloudflare `1.1.1.1`).
- **`portscan.rs` (SYN Heuristic)**: Tracks TCP handshake attempts across different destinations. If a host attempts connections to more than 10 distinct ports within a 5-second window, it flags the source for port-scanning.
- **`bridge.rs` (UDS Server)**: Opens a Unix Domain Socket at `/run/wiredown.sock`. As workers identify devices, block DNS queries, or flag port scans, events are formatted as NDJSON and written to the socket.

---

## 3. The Control Plane: Python API & UI (`src/api/` & `src/ui/`)

The control plane coordinates system logic, serves management pages, and interfaces with the host Linux kernel to apply access rules:

- **`server.py` (ASGI Entrypoint)**: Wraps the Flask + Flask-SocketIO engine in an `asgiref` WSGI-to-ASGI adapter, exposing the app to `uvicorn` on port 5000. It initializes the SQLite database and boots the background `EngineBridge` thread.
- **`wd_engine_bridge.py`**: Connects to the `/run/wiredown.sock` socket, reads NDJSON events, and broadcasts them over the admin panel WebSockets in real time.
- **`fake_admin.py` (Deception Trap)**: Serves a convincing pfSense (Netgate) login screen at root `/`. Credential submission triggers immediate administrative alerts, records the attacker's IP/MAC, and applies firewall containment.
- **`real_admin.py` (Admin SOC Console)**: A hardened, password-protected blueprint served at the hidden prefix `/admin/console`. Includes IP-lockout brute-force defense (bcrypt) and whitelisted operator access.
- **`firewall.py` (Containment Engine)**: Auto-detects whether the host system uses `nftables` or `iptables` and injects host-level isolation rules dropping all packets from flagged attacker IPs.

---

## 4. Deployment Environments

WireDown is engineered strictly for native Proxmox VE orchestration:

1. **LXC Container (Debian 12)**: The recommended installation. The container requires `net_raw` and `net_admin` capabilities to allow the Rust data plane to open raw sockets and modify iptables rule chains.
2. **Virtual Machine**: Cloud-init custom scripting automates installation. Ideal for environments requiring hypervisor-level CPU/memory isolation.
