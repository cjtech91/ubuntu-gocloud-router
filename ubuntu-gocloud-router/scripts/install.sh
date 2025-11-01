#!/bin/bash
# Ubuntu GoCloud Router Installation Script
# Installs all dependencies and configures the system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}Ubuntu GoCloud Router Installation${NC}"
echo -e "${GREEN}=====================================${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Check Ubuntu version
if ! grep -q "Ubuntu" /etc/os-release; then
    echo -e "${YELLOW}Warning: This script is designed for Ubuntu${NC}"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo -e "${GREEN}[1/10] Updating system packages...${NC}"
apt-get update
apt-get upgrade -y

echo -e "${GREEN}[2/10] Installing core dependencies...${NC}"
apt-get install -y \
    build-essential \
    git \
    curl \
    wget \
    net-tools \
    iproute2 \
    iptables \
    nftables \
    ipset \
    bridge-utils \
    vlan \
    ebtables \
    ethtool

echo -e "${GREEN}[3/10] Installing Go...${NC}"
if ! command -v go &> /dev/null; then
    GO_VERSION="1.21.5"
    wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
    rm go${GO_VERSION}.linux-amd64.tar.gz
    
    # Add to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
    
    echo -e "${GREEN}Go ${GO_VERSION} installed successfully${NC}"
else
    echo -e "${GREEN}Go already installed: $(go version)${NC}"
fi

echo -e "${GREEN}[4/10] Installing networking tools...${NC}"
apt-get install -y \
    dnsmasq \
    hostapd \
    frrouting \
    conntrack \
    conntrackd \
    tcpdump \
    iftop \
    bmon \
    vnstat

echo -e "${GREEN}[5/10] Installing monitoring tools...${NC}"
apt-get install -y \
    prometheus \
    grafana \
    node-exporter

echo -e "${GREEN}[6/10] Installing database...${NC}"
apt-get install -y \
    postgresql \
    postgresql-contrib \
    redis-server

echo -e "${GREEN}[7/10] Installing security tools...${NC}"
apt-get install -y \
    suricata \
    fail2ban \
    aide

# Optional: nDPI for DPI functionality
echo -e "${GREEN}[8/10] Installing nDPI (optional)...${NC}"
if [ ! -d "/opt/nDPI" ]; then
    cd /opt
    git clone https://github.com/ntop/nDPI.git
    cd nDPI
    ./autogen.sh
    ./configure
    make
    make install
    ldconfig
    cd -
fi

echo -e "${GREEN}[9/10] Configuring kernel parameters...${NC}"

# Backup original sysctl.conf
cp /etc/sysctl.conf /etc/sysctl.conf.backup

# Configure kernel parameters for routing
cat >> /etc/sysctl.conf <<EOF

# Router optimizations
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1

# Performance tuning
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.core.netdev_max_backlog=5000
net.ipv4.tcp_rmem=4096 87380 134217728
net.ipv4.tcp_wmem=4096 65536 134217728
net.ipv4.tcp_congestion_control=bbr

# Security
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1

# SYN flood protection
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=5

# Connection tracking
net.netfilter.nf_conntrack_max=1000000
net.netfilter.nf_conntrack_tcp_timeout_established=7200
EOF

# Apply sysctl changes
sysctl -p

echo -e "${GREEN}[10/10] Setting up systemd services...${NC}"

# Create router service
cat > /etc/systemd/system/gocloud-router.service <<EOF
[Unit]
Description=GoCloud Router Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/gocloud-router
ExecStart=/opt/gocloud-router/bin/router
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create API service
cat > /etc/systemd/system/gocloud-api.service <<EOF
[Unit]
Description=GoCloud API Service
After=network.target gocloud-router.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/gocloud-router
ExecStart=/opt/gocloud-router/bin/api
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create portal service
cat > /etc/systemd/system/gocloud-portal.service <<EOF
[Unit]
Description=GoCloud Captive Portal Service
After=network.target gocloud-router.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/gocloud-router
ExecStart=/opt/gocloud-router/bin/portal
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}Installation complete!${NC}"
echo -e "${GREEN}=====================================${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Build the Go applications:"
echo "   cd /path/to/ubuntu-gocloud-router"
echo "   go build -o bin/router cmd/router/main.go"
echo "   go build -o bin/api cmd/api/main.go"
echo "   go build -o bin/portal cmd/portal/main.go"
echo ""
echo "2. Copy binaries to /opt/gocloud-router/bin/"
echo ""
echo "3. Configure your network interfaces in /etc/gocloud/config.yaml"
echo ""
echo "4. Start services:"
echo "   systemctl start gocloud-router"
echo "   systemctl start gocloud-api"
echo "   systemctl start gocloud-portal"
echo ""
echo "5. Enable services to start on boot:"
echo "   systemctl enable gocloud-router"
echo "   systemctl enable gocloud-api"
echo "   systemctl enable gocloud-portal"
echo ""
echo -e "${GREEN}Access web interface at: https://your-ip:8443${NC}"
