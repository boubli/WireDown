#!/bin/bash
echo "======================================"
echo "    Aggressive WireDown Updater"
echo "======================================"
cd /opt/wiredown

echo "[*] Fetching fresh code from GitHub..."
git fetch --all
git reset --hard origin/master

echo "[*] Recompiling C++ Core Sensor..."
mkdir -p platforms/linux/build && cd platforms/linux/build
cmake .. && make -j$(nproc)
systemctl restart wiredown.service

echo "[*] Rebuilding Docker images (Bypassing Cache)..."
cd /opt/wiredown
docker compose build --no-cache
docker compose up -d --force-recreate
echo "[*] Update Complete!"
