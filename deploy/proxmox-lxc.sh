#!/usr/bin/env bash
# ============================================================================
#  WireDown — Proxmox LXC installer  (dynamic, no hard-coded versions)
#  ----------------------------------------------------------------------------
#  Bootstraps a fresh Debian-12 LXC container and installs the latest
#  tagged WireDown release from https://github.com/boubli/WireDown.
#
#  USAGE (on the Proxmox host):
#      bash <(curl -sSL https://raw.githubusercontent.com/boubli/WireDown/main/deploy/proxmox-lxc.sh)
#
#  Required tools: pveam, pct, curl, jq.
# ============================================================================
set -euo pipefail

# ── Configuration (override via env) ────────────────────────────────────────
CTID="${CTID:-200}"
HOSTNAME="${HOSTNAME:-Wiredown}"
STORAGE="${STORAGE:-local-lvm}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
BRIDGE="${BRIDGE:-vmbr0}"
DISK_GB="${DISK_GB:-4}"
RAM_MB="${RAM_MB:-512}"
SWAP_MB="${SWAP_MB:-256}"
CORES="${CORES:-1}"
TEMPLATE="${TEMPLATE:-}"
GH_REPO="${GH_REPO:-boubli/WireDown}"
REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/${GH_REPO}}"

# ── 0. Sanity checks ────────────────────────────────────────────────────────
for cmd in pct pveam curl; do
    command -v "$cmd" >/dev/null || { echo "[FATAL] missing $cmd"; exit 1; }
done

# ── 1. Resolve LATEST release dynamically ───────────────────────────────────
echo "[wiredown] querying GitHub API for the latest release…"
LATEST_JSON="$(curl -fsSL \
    -H 'Accept: application/vnd.github+json' \
    -H 'User-Agent: wiredown-lxc-installer' \
    "https://api.github.com/repos/${GH_REPO}/releases/latest" 2>/dev/null || true)"

LATEST_TAG=""
TARBALL_URL=""

if [[ -n "$LATEST_JSON" ]]; then
    LATEST_TAG="$(echo "$LATEST_JSON" | grep -o '"tag_name": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)"
    TARBALL_URL="$(echo "$LATEST_JSON" | grep -o '"tarball_url": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)"
fi

if [[ -z "$LATEST_TAG" || "$LATEST_TAG" == "null" ]]; then
    # Fallback to tags API if no release is published yet
    TAGS_JSON="$(curl -fsSL \
        -H 'Accept: application/vnd.github+json' \
        -H 'User-Agent: wiredown-lxc-installer' \
        "https://api.github.com/repos/${GH_REPO}/tags")"
    LATEST_TAG="$(echo "$TAGS_JSON" | grep -o '"name": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)"
    TARBALL_URL="$(echo "$TAGS_JSON" | grep -o '"tarball_url": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)"
fi

[[ -z "$LATEST_TAG" || "$LATEST_TAG" == "null" ]] && { echo "[FATAL] could not resolve latest tag"; exit 1; }
echo "[wiredown] installing ${LATEST_TAG}"

# ── 2. Make sure the template is present ────────────────────────────────────
if [[ -z "$TEMPLATE" ]]; then
    echo "[wiredown] updating Proxmox appliance template index..."
    pveam update >/dev/null 2>&1 || true

    echo "[wiredown] resolving latest available Debian 12 template..."
    TEMPLATE=$(pveam available -section system | awk '/debian-12-standard_/ {print $2}' | sort -V | tail -n1)

    if [[ -z "$TEMPLATE" ]]; then
        echo "[CRITICAL WARNING] Failed to automatically resolve a valid Debian 12 template. Defaulting to fallback."
        TEMPLATE="debian-12-standard_12.2-1_amd64.tar.zst"
    fi
fi

echo "[wiredown] using template: $TEMPLATE"

if ! pveam list "$TEMPLATE_STORAGE" 2>/dev/null | grep -q "$TEMPLATE"; then
    echo "[wiredown] downloading container template $TEMPLATE to $TEMPLATE_STORAGE..."
    pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
fi

# ── 3. Create the LXC ───────────────────────────────────────────────────────
echo "[wiredown] creating LXC ${CTID} (${RAM_MB} MB RAM / ${CORES} vCPU)…"
pct create "$CTID" "${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE}" \
    --hostname    "$HOSTNAME" \
    --cores       "$CORES" \
    --memory      "$RAM_MB" \
    --swap        "$SWAP_MB" \
    --rootfs      "${STORAGE}:${DISK_GB}" \
    --net0        "name=eth0,bridge=${BRIDGE},ip=dhcp" \
    --features    "nesting=1" \
    --unprivileged 0 \
    --onboot      1

# Allow /dev/net/tun device control
cat <<EOF >> "/etc/pve/lxc/${CTID}.conf"
lxc.cgroup2.devices.allow: c 10:200 rwm
EOF

pct start "$CTID"
sleep 3

# ── 4. Provision inside the container ───────────────────────────────────────
echo "[wiredown] provisioning packages inside LXC…"
pct exec "$CTID" -- bash -c "
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq curl jq ca-certificates python3 python3-pip python3-venv \
                          nftables iptables sqlite3 git build-essential

    install -d /opt/wiredown /etc/wiredown
    cd /opt/wiredown
    curl -fsSL '$TARBALL_URL' | tar -xz --strip-components=1
    echo '$LATEST_TAG' > /opt/wiredown/VERSION

    python3 -m venv .venv
    .venv/bin/pip install --quiet -r src/api/requirements.txt

    install -m 0755 deploy/wd-engine.service /etc/systemd/system/
    install -m 0755 deploy/wiredown-api.service /etc/systemd/system/

    # Build the Rust data-plane binary if cargo is available; otherwise the
    # service runs in stub mode and the dashboard remains fully functional.
    if [[ -x /opt/wiredown/src/engine/build.sh ]]; then
        INSTALL=1 bash /opt/wiredown/src/engine/build.sh || \
            echo '[wiredown] wd-engine build skipped (cargo missing) — control plane still works'
    fi

    systemctl daemon-reload
    systemctl enable --now wiredown-api.service
    systemctl enable --now wd-engine.service || true
"

LXC_IP="$(pct exec "$CTID" -- hostname -I | awk '{print $1}')"

cat <<EOF

╔══════════════════════════════════════════════════════════════════════╗
║   WireDown ${LATEST_TAG} installed in LXC ${CTID}
║   ─────────────────────────────────────────────────────────────────
║   Honeypot (NetGate/pfSense bait) :  http://${LXC_IP}/
║   Admin console (hidden)          :  http://${LXC_IP}/admin/console/login
║   Default credentials             :  see /var/log/wiredown-api.log
║   1-click updates                 :  Admin Console → "Update Available"
╚══════════════════════════════════════════════════════════════════════╝
EOF
