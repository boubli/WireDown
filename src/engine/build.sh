#!/usr/bin/env bash
# WireDown wd-engine — one-shot static musl build.
# Run on the LXC/VM host once during provisioning.
set -euo pipefail

if ! command -v cargo >/dev/null; then
    echo "[wd-engine] installing Rust toolchain (minimal profile)…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal
    # shellcheck source=/dev/null
    . "$HOME/.cargo/env"
fi

rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true

if ! dpkg -l musl-tools >/dev/null 2>&1; then
    echo "[wd-engine] installing musl-tools…"
    apt-get update -qq
    apt-get install -y -qq musl-tools libpcap-dev
fi

cd "$(dirname "$0")"

echo "[wd-engine] cargo build --release (musl)…"
RUSTFLAGS="-C link-arg=-s" \
    cargo build --release --target x86_64-unknown-linux-musl

bin="target/x86_64-unknown-linux-musl/release/wd-engine"
size_kb=$(du -k "$bin" | cut -f1)
echo "[wd-engine] built: $bin (${size_kb} KB)"

if [[ "${INSTALL:-0}" == "1" ]]; then
    install -m 0755 "$bin" /usr/local/bin/wd-engine
    echo "[wd-engine] installed → /usr/local/bin/wd-engine"
fi
