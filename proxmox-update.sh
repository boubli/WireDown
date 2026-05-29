#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}======================================================${NC}"
echo -e "${CYAN}       WireDown — Proxmox Update Utility              ${NC}"
echo -e "${CYAN}======================================================${NC}"
echo ""

if ! command -v pct &> /dev/null; then
    echo -e "${YELLOW}Error: This script must be run directly on the Proxmox Node shell.${NC}" >&2
    exit 1
fi

echo -e "${CYAN}[*] Searching for WireDown LXC containers...${NC}"
FOUND=0

# Loop through all running and stopped LXCs
for ID in $(pct list | awk 'NR>1 {print $1}'); do
    
    # Ensure container is running before attempting to exec
    STATUS=$(pct status $ID | awk '{print $2}')
    if [[ "$STATUS" != "running" ]]; then
        continue
    fi

    # Check if /opt/wiredown exists inside the container
    if pct exec $ID -- bash -c "test -d /opt/wiredown" 2>/dev/null; then
        echo -e "\n${GREEN}[+] Found WireDown in Container ID: $ID${NC}"
        
        echo -e "${CYAN}[*] Pulling latest updates from GitHub...${NC}"
        pct exec $ID -- bash -c "cd /opt/wiredown && git pull"
        
        echo -e "${CYAN}[*] Rebuilding and restarting Docker containers...${NC}"
        pct exec $ID -- bash -c "cd /opt/wiredown && test -f .env || cp .env.example .env && docker compose up -d --build"
        
        FOUND=1
        echo -e "${GREEN}[✔] Container $ID updated successfully!${NC}"
    fi
done

if [[ $FOUND -eq 0 ]]; then
    echo -e "\n${YELLOW}[!] No running WireDown LXC containers found on this Proxmox node.${NC}"
    echo -e "Make sure your container is powered on before running the updater."
else
    echo -e "\n${GREEN}======================================================${NC}"
    echo -e "${GREEN}  All WireDown instances are now up to date!${NC}"
    echo -e "${GREEN}======================================================${NC}"
fi
