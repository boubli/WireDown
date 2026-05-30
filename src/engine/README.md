# WireDown — `wd-engine`

Ultra-lightweight Rust data-plane daemon for the WireDown appliance.

## What it does

1. **Promiscuous capture** on the bridge interface (default `br0`) using
   AF_PACKET with a `TPACKET_V3` ring buffer (zero-copy, kernel-driven
   block timeout).
2. **Passive ARP + DHCP parsing** to build the `Global_Device_Registry`
   without ever sending an active probe.
3. **DNS sinkhole** on `udp/53`. Queries matching the bundled blocklist
   resolve to the WireDown LAN IP (where the NetGate honeypot lives).
4. **NDJSON-over-UDS bridge** at `/run/wiredown.sock` — every event is a
   single line of JSON terminated by `\n`. The Python control plane
   reads it with one non-blocking task.

## Build (static musl ≈ 3 MB, RSS ≈ 10 MB)

```sh
# one-time toolchain bootstrap (LXC provisioning)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
. "$HOME/.cargo/env"
rustup target add x86_64-unknown-linux-musl
apt-get install -y musl-tools

# build
cd /app/wd-engine
cargo build --release --target x86_64-unknown-linux-musl

# install
install -m 0755 target/x86_64-unknown-linux-musl/release/wd-engine /usr/local/bin/wd-engine
```

A drop-in helper is also provided: `./build.sh`.

## systemd unit (LXC)

```
[Unit]
Description=WireDown data-plane engine
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/wd-engine --iface br0 --uds /run/wiredown.sock --upstream-dns 1.1.1.1
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
Restart=always
RestartSec=2s
MemoryMax=64M
CPUWeight=50

[Install]
WantedBy=multi-user.target
```

## Architecture (data flow)

```
br0 (promisc, AF_PACKET ring)
   │
   ▼
capture::Capture::poll()  ── parses Ether/IP headers (etherparse)
   │
   ├── ARP frame   ──► arp::handle()        → DeviceEvent
   ├── DHCP packet ──► arp::dhcp_handle()   → DeviceEvent
   ├── DNS query   ──► dns::respond()       → ThreatEvent (if blocklist hit)
   └── TCP SYN     ──► portscan::observe()  → ThreatEvent (if burst)
   │
   ▼
event::Bus  (mpsc::channel, capacity 4096)
   │
   ▼
bridge::serve_uds("/run/wiredown.sock")
   │
   ▼
NDJSON line → Python control plane (backend/wd_engine_bridge.py)
```

## CLI

```
wd-engine [OPTIONS]

OPTIONS:
  --iface         <NAME>   Bridge or LAN interface to tap (default: br0)
  --uds           <PATH>   Unix Domain Socket path (default: /run/wiredown.sock)
  --upstream-dns  <IP>     Upstream resolver for non-blocked queries (default: 1.1.1.1)
  --blocklist     <FILE>   Domain blocklist, one per line (default: /etc/wiredown/blocklist.txt)
  --sinkhole-ip   <IP>     IP returned for sinkholed A queries (default: auto-detect)
  --log-level     <LEVEL>  trace|debug|info|warn|error (default: info)
```
