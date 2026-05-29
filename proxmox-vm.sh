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
echo -e "                     Proxmox VM Installer (Isolated)${NC}"
echo ""

if ! command -v qm &> /dev/null; then
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

echo -e "${CYAN}[*] Downloading Ubuntu 22.04 Cloud Image (Jammy)...${NC}"
mkdir -p /var/lib/vz/template/qemu
if [[ ! -f /var/lib/vz/template/qemu/ubuntu-22.04-server-cloudimg-amd64.img ]]; then
    wget -qO /var/lib/vz/template/qemu/ubuntu-22.04-server-cloudimg-amd64.img https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
fi

echo -e "${CYAN}[*] Enabling Snippets on 'local' storage for Cloud-Init...${NC}"
pvesm set local --content backup,iso,vztmpl,snippets || true
mkdir -p /var/lib/vz/snippets


echo -e "${CYAN}[*] Generating Cloud-Init Automation Snippet...${NC}"
cat <<EOF > /var/lib/vz/snippets/wiredown-cloud-init-$ID.yml
#cloud-config
package_update: true
packages:
  - curl
  - git
  - qemu-guest-agent
  - build-essential
  - cmake
runcmd:
  - curl -fsSL https://get.docker.com | sh
  - git clone https://github.com/boubli/WireDown.git /opt/wiredown
  - cd /opt/wiredown
  - cp .env.example .env
  - echo 'DEPLOYMENT_MODE=PROXMOX' >> .env
  - docker compose up -d
  - mkdir -p /opt/wiredown/platforms/linux/build
  - cd /opt/wiredown/platforms/linux/build && cmake .. && make
  - sh -c 'echo "[Unit]\nDescription=WireDown Network Sensor\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=/opt/wiredown/platforms/linux/build/wiredown-linux eth0\nWorkingDirectory=/opt/wiredown\nRestart=always\nRestartSec=5\nUser=root\n\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/wiredown.service'
  - systemctl daemon-reload
  - systemctl enable --now wiredown.service
  - systemctl enable --now qemu-guest-agent
  - sh -c "IP=\\\$(hostname -I | awk '{print \\\$1}'); echo -e '\\n======================================================\\n  WireDown Zero-Gravity Honeypot\\n======================================================\\nDashboard URL: http://\\\$IP:8080\\nBackend API:   http://\\\$IP:5000\\nSSH Honeypot:  ssh root@\\\$IP -p 2222\\n\\nTo view logs:  cd /opt/wiredown && docker compose logs -f\\n======================================================\\n' > /etc/motd"
EOF

echo -e "${CYAN}[*] Creating VM $ID...${NC}"
qm create $ID --name wiredown-vm --memory $RAM --cores $CORES --net0 virtio,bridge=$BRIDGE

echo -e "${CYAN}[*] Importing Disk Image...${NC}"
qm importdisk $ID /var/lib/vz/template/qemu/ubuntu-22.04-server-cloudimg-amd64.img local-lvm >/dev/null

echo -e "${CYAN}[*] Configuring Hardware & Cloud-Init...${NC}"
qm set $ID --scsihw virtio-scsi-pci --scsi0 local-lvm:vm-$ID-disk-0 >/dev/null
qm set $ID --ide2 local-lvm:cloudinit >/dev/null
qm set $ID --boot c --bootdisk scsi0 >/dev/null
qm set $ID --serial0 socket --vga serial0 >/dev/null
qm set $ID --agent enabled=1 >/dev/null
qm set $ID --ipconfig0 ip=dhcp >/dev/null
qm set $ID --cicustom "user=local:snippets/wiredown-cloud-init-$ID.yml" >/dev/null
qm resize $ID scsi0 ${DISK}G >/dev/null


echo -e "${CYAN}[*] Starting VM $ID...${NC}"
qm start $ID

echo -e "\n${YELLOW}[!] The VM has booted, but Cloud-Init needs 2-3 minutes to autonomously install Docker and clone WireDown.${NC}"
echo -e "${CYAN}[*] Waiting for QEMU Guest Agent to report IP Address...${NC}"

IP=""
while [ -z "$IP" ]; do
    sleep 5
    IP=$(qm guest cmd $ID network-get-interfaces 2>/dev/null | grep -A 2 -B 2 '"name": "eth0"' | grep '"ip-address"' | grep -v '127.0.0.1' | grep -v ':' | head -n 1 | awk -F'"' '{print $4}') || true
    if [ -z "$IP" ]; then
        IP=$(qm guest cmd $ID network-get-interfaces 2>/dev/null | grep -A 2 -B 2 'ipv4' | grep '"ip-address"' | grep -v '127.0.0.1' | grep -v ':' | head -n 1 | awk -F'"' '{print $4}') || true
    fi
done

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}  WireDown VM Installation Complete!${NC}"
echo -e "${GREEN}  Virtual Machine ID: $ID${NC}"
echo -e "${GREEN}======================================================${NC}"
echo -e "Dashboard URL: ${CYAN}http://$IP:8080${NC}  (Allow 2-3 mins for Docker to finish booting)"
echo -e "Backend API:   ${CYAN}http://$IP:5000${NC}"
echo -e "SSH Honeypot:  ${CYAN}ssh root@$IP -p 2222${NC}"
echo ""
