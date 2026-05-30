# WireDown V1.0.0.3 — Release Notes

**The official pivot to a Proxmox LXC / VM appliance.** The ESP32-era is retired; everything now runs inside the appliance with a Rust data-plane and a Python control-plane.

## Highlights

- **Rust `wd-engine` data plane** (musl-static, ≈10 MB RSS)
  - AF_PACKET zero-copy capture on the bridge interface
  - Passive ARP / DHCP parser → `Global_Device_Registry`
  - Built-in DNS sinkhole on `udp/53` with bundled blocklist + upstream relay
  - SYN-burst portscan heuristic
  - IEEE OUI vendor lookup
  - NDJSON-over-UDS bridge to the Python control plane
- **1-click Proxmox install** (`deploy/proxmox-lxc.sh`, `deploy/proxmox-vm.sh`)
  - Dynamic — always pulls the latest GitHub release, no hard-coded version
- **1-click in-place updater**
  - Background GitHub poller (every 1 h) + secured `POST /admin/console/api/system/update`
  - Atomic stage → swap → restart of `wd-engine` and `wiredown-api`
  - Live Socket.IO progress stream to the dashboard
- **Pixel-perfect pfSense (Netgate) honeypot** at `/`
- **nftables ↔ iptables auto-detect** firewall backend with `noop` fallback
- **Monthly IEEE OUI table refresh**
- **Hardened SOC console**
  - bcrypt (cost = 12), brute-force lockout (5 fails / 15 min per IP)
  - `OPERATOR_ORIGIN`-locked CORS
  - Append-only SQLite audit log streamed to the dashboard via Socket.IO

## Breaking changes

- All legacy ESP32 hardware support and related code artifacts have been fully removed.

## Footprint

- ≈ 140 MB RAM at idle on a fresh LXC (10 MB Rust engine + 45 MB Python control plane + 80 MB Debian base)
- Static `wd-engine` binary ≈ 3 MB (musl)
- Single-file SQLite DB (`/opt/wiredown/src/api/wiredown.db`) — backup with `cp`
