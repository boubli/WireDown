#!/usr/bin/env bash
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
cat << "EOF"
$$\      $$\ $$\                     $$$$$$$\                                    
$$ | $\  $$ |\__|                    $$  __$$\                                   
$$ |$$$\ $$ |$$\  $$$$$$\   $$$$$$\  $$ |  $$ | $$$$$$\  $$\  $$\  $$\ $$$$$$$\  
$$ $$ $$\$$ |$$ |$$  __$$\ $$  __$$\ $$ |  $$ |$$  __$$\ $$ | $$ | $$ |$$  __$$\ 
$$$$  _$$$$ |$$ |$$ |  \__|$$$$$$$$ |$$ |  $$ |$$ /  $$ |$$ | $$ | $$ |$$ |  $$ |
$$$  / \$$$ |$$ |$$ |      $$   ____|$$ |  $$ |$$ |  $$ |$$ | $$ | $$ |$$ |  $$ |
$$  /   \$$ |$$ |$$ |      \$$$$$$$\ $$$$$$$  |\$$$$$$  |\$$$$$\$$$$  |$$ |  $$ |
\__/     \__|\__|\__|       \_______|\_______/  \______/  \_____\____/ \__|  \__|
EOF
echo -e "                   Proxmox LXC Installer (Lightweight)${NC}"
echo ""

if ! command -v pct &> /dev/null; then
    echo -e "${YELLOW}Error: This script must be run directly on the Proxmox Node shell.${NC}" >&2
    exit 1
fi

echo -e "Press [Enter] to accept the default values."
function prompt_input() {
    local prompt_text="$1"
    local default_value="$2"
    local variable_name="$3"
    read -p "$prompt_text [$default_value]: " input_value
    if [[ -z "$input_value" ]]; then
        eval $variable_name="'$default_value'"
    else
        eval $variable_name="'$input_value'"
    fi
}

prompt_input "CPU Cores" "2" CORES
prompt_input "RAM (MB)" "2048" RAM
prompt_input "Disk Size (GB)" "8" DISK
prompt_input "Network Bridge" "vmbr0" BRIDGE

echo -e "\n${CYAN}[*] Finding next available ID...${NC}"
ID=$(pvesh get /cluster/nextid)

echo -e "${CYAN}[*] Downloading Debian 12 minimal template...${NC}"
pveam update >/dev/null
TEMPLATE=$(pveam available -section system | grep debian-12-standard | awk '{print $2}' | head -n 1)
TEMPLATE_PATH="/var/lib/vz/template/cache/${TEMPLATE##*/}"
if [ ! -f "$TEMPLATE_PATH" ]; then
    pveam download local $TEMPLATE >/dev/null || true
else
    echo -e "${GREEN}[+] Template already cached, skipping download.${NC}"
fi

echo -e "${CYAN}[*] Creating LXC Container $ID...${NC}"
pct create $ID local:vztmpl/${TEMPLATE##*/} \
    --arch amd64 \
    --hostname wiredown \
    --cores $CORES \
    --memory $RAM \
    --swap $RAM \
    --rootfs local-lvm:$DISK \
    --net0 name=eth0,bridge=$BRIDGE,ip=dhcp \
    --features nesting=1,keyctl=1 \
    --unprivileged 0 \
    --password wiredown


echo -e "${CYAN}[*] Starting Container $ID...${NC}"
pct start $ID
sleep 5

echo -e "${CYAN}[*] Waiting for network connection...${NC}"
pct exec $ID -- bash -c "while ! ping -c 1 -W 1 8.8.8.8 >/dev/null; do sleep 1; done"

echo -e "${CYAN}[*] Installing Docker, build tools, and WireDown inside LXC...${NC}"
pct exec $ID -- bash -c "apt-get update && apt-get install -y curl git build-essential cmake && curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh"
pct exec $ID -- bash -c "git clone https://github.com/boubli/WireDown.git /opt/wiredown && cd /opt/wiredown && cp .env.example .env"
pct exec $ID -- bash -c "echo 'DEPLOYMENT_MODE=PROXMOX' >> /opt/wiredown/.env"
pct exec $ID -- bash -c "cd /opt/wiredown && docker compose up -d"

echo -e "${CYAN}[*] Compiling Linux sensor (C++ Core)...${NC}"
pct exec $ID -- bash -c "mkdir -p /opt/wiredown/platforms/linux/build && cd /opt/wiredown/platforms/linux/build && cmake .. && make"

echo -e "${CYAN}[*] Setting up systemd service for WireDown Sensor...${NC}"
pct exec $ID -- bash -c "cat <<EOF > /etc/systemd/system/wiredown.service
[Unit]
Description=WireDown Network Sensor
After=network.target

[Service]
Type=simple
ExecStart=/opt/wiredown/platforms/linux/build/wiredown-linux eth0
WorkingDirectory=/opt/wiredown
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF"
pct exec $ID -- bash -c "systemctl daemon-reload && systemctl enable wiredown.service && systemctl start wiredown.service"

echo -e "${CYAN}[*] Retrieving IP Address...${NC}"
IP=$(pct exec $ID -- ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

echo -e "${CYAN}[*] Setting up Message of the Day (MOTD)...${NC}"
pct exec $ID -- bash -c "echo -e '\n======================================================' > /etc/motd"
pct exec $ID -- bash -c "echo -e '  WireDown Zero-Gravity Honeypot' >> /etc/motd"
pct exec $ID -- bash -c "echo -e '======================================================' >> /etc/motd"
pct exec $ID -- bash -c "echo -e 'Dashboard URL: http://$IP:8080' >> /etc/motd"
pct exec $ID -- bash -c "echo -e 'Backend API:   http://$IP:5000' >> /etc/motd"
pct exec $ID -- bash -c "echo -e 'SSH Honeypot:  ssh root@$IP -p 2222' >> /etc/motd"
pct exec $ID -- bash -c "echo -e '\nTo view logs:  cd /opt/wiredown && docker compose logs -f' >> /etc/motd"
pct exec $ID -- bash -c "echo -e '======================================================\n' >> /etc/motd"

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}  WireDown LXC Installation Complete!${NC}"
echo -e "${GREEN}  Container ID: $ID${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "Dashboard URL: ${CYAN}http://$IP:8080${NC}"
echo -e "Backend API:   ${CYAN}http://$IP:5000${NC}"
echo -e "SSH Honeypot:  ${CYAN}ssh root@$IP -p 2222${NC}"
echo -e "To view logs:  pct exec $ID -- bash -c 'cd /opt/wiredown && docker compose logs -f'"
echo ""
