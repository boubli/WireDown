#!/usr/bin/env bash
# ============================================================================
#  WireDown — In-place 1-click update.
#
#  Invoked by the admin dashboard via POST /admin/console/api/system/update.
#  Pulls the LATEST GitHub release, swaps in new files, rebuilds the Rust
#  wd-engine binary if cargo is available, then restarts both services.
#
#  Safe to re-run; uses atomic directory swap so a partial download cannot
#  brick the appliance.
# ============================================================================
set -euo pipefail

GH_REPO="${WD_GITHUB_REPO:-boubli/WireDown}"
INSTALL_DIR="${WD_INSTALL_DIR:-/opt/wiredown}"
STAGE_DIR="${INSTALL_DIR}/.update-stage"
BACKUP_DIR="${INSTALL_DIR}/.update-backup-$(date -u +%Y%m%dT%H%M%SZ)"

log() { printf '[update %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }

# ── 0. Sanity ───────────────────────────────────────────────────────────────
for cmd in curl tar systemctl; do
    command -v "$cmd" >/dev/null || { log "FATAL: missing $cmd"; exit 127; }
done
[[ -d "$INSTALL_DIR" ]] || { log "FATAL: $INSTALL_DIR not found"; exit 1; }

# ── 1. Resolve latest release ───────────────────────────────────────────────
log "querying GitHub releases API…"
LATEST_JSON="$(curl -fsSL \
    -H 'Accept: application/vnd.github+json' \
    -H "User-Agent: wiredown-update/${HOSTNAME:-unknown}" \
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
        -H "User-Agent: wiredown-update/${HOSTNAME:-unknown}" \
        "https://api.github.com/repos/${GH_REPO}/tags")"
    LATEST_TAG="$(echo "$TAGS_JSON" | grep -o '"name": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)"
    TARBALL_URL="$(echo "$TAGS_JSON" | grep -o '"tarball_url": *"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)"
fi

[[ -z "$LATEST_TAG" || "$LATEST_TAG" == "null" ]] && { log "FATAL: no latest tag"; exit 1; }

CURRENT="$(cat "${INSTALL_DIR}/VERSION" 2>/dev/null || echo "0.0.0")"
log "current=${CURRENT}  latest=${LATEST_TAG}"

if [[ "$CURRENT" == "$LATEST_TAG" ]]; then
    log "already on latest — nothing to do"
    exit 0
fi

# ── 2. Stage download ───────────────────────────────────────────────────────
log "downloading ${LATEST_TAG}…"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"
curl -fL "$TARBALL_URL" | tar -xz --strip-components=1 -C "$STAGE_DIR"
echo "$LATEST_TAG" > "${STAGE_DIR}/VERSION"
log "download OK"

# ── 3. Atomic swap (keep a rollback copy) ───────────────────────────────────
log "swapping live tree → ${BACKUP_DIR}"
mkdir -p "$BACKUP_DIR"
shopt -s dotglob nullglob
for p in "${INSTALL_DIR}"/*; do
    base="$(basename "$p")"
    case "$base" in
        .venv|.update-stage|.update-backup-*)
            continue ;;
    esac
    mv "$p" "${BACKUP_DIR}/${base}"
done
mv "${STAGE_DIR}"/* "${INSTALL_DIR}/"
rmdir "$STAGE_DIR"

# ── 4. Python deps + Rust engine ────────────────────────────────────────────
log "refreshing Python dependencies…"
"${INSTALL_DIR}/.venv/bin/pip" install -q -r "${INSTALL_DIR}/src/api/requirements.txt" || \
    log "WARN: pip refresh failed — continuing with cached deps"

if command -v cargo >/dev/null && [[ -x "${INSTALL_DIR}/src/engine/build.sh" ]]; then
    log "rebuilding wd-engine (musl)…"
    INSTALL=1 bash "${INSTALL_DIR}/src/engine/build.sh" || log "WARN: wd-engine rebuild failed"
fi

# ── 5. Restart services ─────────────────────────────────────────────────────
log "restarting wd-engine and wiredown-api…"
systemctl daemon-reload || true
systemctl restart wd-engine.service     2>/dev/null || log "wd-engine.service not active"
systemctl restart wiredown-api.service  2>/dev/null || log "wiredown-api.service not active"

log "update to ${LATEST_TAG} complete"
exit 0
