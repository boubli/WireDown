#!/usr/bin/env bash
# ============================================================================
#  WireDown — Proxmox VM installer  (dynamic, no hard-coded versions)
#  ----------------------------------------------------------------------------
#  Provisions a thin Debian Cloud-Init VM, then installs the latest
#  tagged WireDown release from GitHub.
#
#  USAGE (on the Proxmox host):
#      bash <(curl -sSL https://raw.githubusercontent.com/boubli/WireDown/main/deploy/proxmox-vm.sh)
#
#  Required tools: qm, curl, jq, qemu-img.
# ============================================================================
set -euo pipefail

VMID="${VMID:-200}"
NAME="${NAME:-wiredown}"
STORAGE="${STORAGE:-local-lvm}"
BRIDGE="${BRIDGE:-vmbr0}"
RAM_MB="${RAM_MB:-512}"
CORES="${CORES:-1}"
DISK_GB="${DISK_GB:-4}"
CLOUD_IMG_URL="${CLOUD_IMG_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2}"
CLOUD_IMG="${CLOUD_IMG:-/var/lib/vz/template/iso/debian-12-genericcloud-amd64.qcow2}"
SSH_PUBKEY="${SSH_PUBKEY:-$HOME/.ssh/id_rsa.pub}"
GH_REPO="${GH_REPO:-boubli/WireDown}"

for cmd in qm curl qemu-img; do
    command -v "$cmd" >/dev/null || { echo "[FATAL] missing $cmd"; exit 1; }
done

# ── 1. Resolve LATEST release dynamically ───────────────────────────────────
echo "[wiredown] querying GitHub API for the latest release…"
LATEST_JSON="$(curl -fsSL \
    -H 'Accept: application/vnd.github+json' \
    -H 'User-Agent: wiredown-vm-installer' \
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
        -H 'User-Agent: wiredown-vm-installer' \
        "https://api.github.com/repos/${GH_REPO}/tags")"
    LATEST_TAG="$(echo "$TAGS_JSON" | grep -o '"name": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)"
    TARBALL_URL="$(echo "$TAGS_JSON" | grep -o '"tarball_url": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)"
fi

[[ -z "$LATEST_TAG" || "$LATEST_TAG" == "null" ]] && { echo "[FATAL] could not resolve latest tag"; exit 1; }
echo "[wiredown] installing ${LATEST_TAG}"

# ── 2. Cloud image ──────────────────────────────────────────────────────────
if [[ ! -f "$CLOUD_IMG" ]]; then
    echo "[wiredown] fetching Debian cloud image…"
    mkdir -p "$(dirname "$CLOUD_IMG")"
    curl -fL "$CLOUD_IMG_URL" -o "$CLOUD_IMG"
fi

# ── 3. Create + customise the VM ────────────────────────────────────────────
echo "[wiredown] creating VM $VMID ($RAM_MB MB / $CORES vCPU)…"
qm create "$VMID" \
    --name        "$NAME" \
    --memory      "$RAM_MB" \
    --cores       "$CORES" \
    --net0        "virtio,bridge=${BRIDGE}" \
    --serial0     socket --vga serial0 \
    --agent       1 \
    --ostype      l26 \
    --cpu         host

qm importdisk "$VMID" "$CLOUD_IMG" "$STORAGE" --format qcow2
qm set "$VMID" --scsihw virtio-scsi-pci --scsi0 "${STORAGE}:vm-${VMID}-disk-0"
qm set "$VMID" --ide2  "${STORAGE}:cloudinit"
qm set "$VMID" --boot  order=scsi0
qm set "$VMID" --ipconfig0 ip=dhcp
qm resize "$VMID" scsi0 "${DISK_GB}G"
[[ -f "$SSH_PUBKEY" ]] && qm set "$VMID" --sshkey "$SSH_PUBKEY"

# Inline first-boot cloud-init script that pulls the latest release.
USERDATA="/var/lib/vz/snippets/wiredown-${VMID}.yaml"
mkdir -p "$(dirname "$USERDATA")"
cat > "$USERDATA" <<YAML
#cloud-config
package_update: true
packages:
  - curl
  - jq
  - python3
  - python3-pip
  - python3-venv
  - nftables
  - sqlite3
  - git
  - ca-certificates
runcmd:
  - mkdir -p /opt/wiredown /etc/wiredown
  - curl -fsSL "${TARBALL_URL}" | tar -xz --strip-components=1 -C /opt/wiredown
  - echo "${LATEST_TAG}" > /opt/wiredown/VERSION
  - cd /opt/wiredown && python3 -m venv .venv && .venv/bin/pip install -r src/api/requirements.txt
  - install -m 0644 /opt/wiredown/deploy/wd-engine.service /etc/systemd/system/
  - install -m 0644 /opt/wiredown/deploy/wiredown-api.service /etc/systemd/system/
  - if [ -x /opt/wiredown/src/engine/build.sh ]; then INSTALL=1 bash /opt/wiredown/src/engine/build.sh; fi
  - systemctl daemon-reload
  - systemctl enable --now wiredown-api.service
  - systemctl enable --now wd-engine.service || true
YAML
qm set "$VMID" --cicustom "user=local:snippets/wiredown-${VMID}.yaml"

qm start "$VMID"

echo ""
echo "[wiredown] VM ${VMID} (${LATEST_TAG}) booting — first run takes ~3 min."
echo "[wiredown] After boot, find the IP with: qm guest cmd ${VMID} network-get-interfaces"
