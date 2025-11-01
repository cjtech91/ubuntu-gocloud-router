# Quick Start Guide

## Prerequisites

- Ubuntu 22.04 LTS or later
- Multi-NIC hardware (minimum 2 network interfaces)
- Root/sudo access
- 2GB+ RAM recommended

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/cjtech91/ubuntu-gocloud-router.git
cd ubuntu-gocloud-router
```

### 2. Run Installation Script

```bash
sudo chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

This will install all dependencies including:
- Go programming language
- Network tools (iproute2, nftables, tc)
- Monitoring tools (Prometheus, Grafana)
- Database (PostgreSQL, Redis)
- Security tools (Suricata, fail2ban)

### 3. Configure Network Interfaces

Edit the configuration file:

```bash
sudo nano config/config.yaml
```

Update the interface names to match your system:

```yaml
interfaces:
  wan:
    - name: "eth0"  # Change to your WAN interface
      type: "dhcp"
      enabled: true
  
  lan:
    - name: "eth1"  # Change to your LAN interface
      ip: "192.168.1.1"
      netmask: "255.255.255.0"
```

Check your interface names:
```bash
ip link show
```

### 4. Build the Applications

```bash
# Install Go dependencies
go mod download

# Build binaries
mkdir -p bin
go build -o bin/router cmd/router/main.go
```

### 5. Deploy to System

```bash
# Create installation directory
sudo mkdir -p /opt/gocloud-router/bin
sudo mkdir -p /etc/gocloud

# Copy files
sudo cp bin/router /opt/gocloud-router/bin/
sudo cp config/config.yaml /etc/gocloud/

# Set permissions
sudo chmod +x /opt/gocloud-router/bin/router
```

### 6. Start the Router

```bash
# Start the service
sudo systemctl start gocloud-router

# Check status
sudo systemctl status gocloud-router

# View logs
sudo journalctl -u gocloud-router -f
```

### 7. Enable on Boot

```bash
sudo systemctl enable gocloud-router
```

## Basic Configuration

### Configure Multi-WAN

1. Edit `/etc/gocloud/config.yaml`
2. Add multiple WAN interfaces:

```yaml
interfaces:
  wan:
    - name: "eth0"
      type: "dhcp"
      metric: 100
      weight: 10
      enabled: true
    
    - name: "eth1"
      type: "dhcp"
      metric: 200
      weight: 5
      enabled: true

multi_wan:
  enabled: true
  mode: "load_balance"  # or "failover"
```

3. Restart service: `sudo systemctl restart gocloud-router`

### Setup VLANs

```yaml
vlans:
  - id: 10
    name: "Guest Network"
    interface: "eth2"
    ip: "192.168.10.1"
    netmask: "255.255.255.0"
    dhcp_enabled: true
    isolated: true
```

### Configure QoS

```yaml
qos:
  enabled: true
  total_bandwidth: "100mbit"
  
  classes:
    - name: "High Priority"
      priority: 1
      min_rate: "20mbit"
      max_rate: "100mbit"
```

### Enable Captive Portal

```yaml
portal:
  enabled: true
  listen_addr: ":8080"
  session_timeout: "24h"
  redirect_url: "https://www.google.com"
```

## Web Interface

Access the web interface:
- API: `http://20.0.0.218:8443`
- Portal: `http://20.0.0.218:8080`

Default credentials (change these!):
- Username: `admin`
- Password: `admin`

## API Examples

### Get WAN Status

```bash
curl http://localhost:8443/api/v1/wan
```

### Add Bandwidth Limit

```bash
curl -X POST http://localhost:8443/api/v1/qos/bandwidth \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.100",
    "upload_max": "10mbit",
    "down_max": "50mbit"
  }'
```

### Add Firewall Rule

```bash
curl -X POST http://localhost:8443/api/v1/firewall/rules \
  -H "Content-Type: application/json" \
  -d '{
    "protocol": "tcp",
    "dst_port": "80",
    "action": "accept"
  }'
```

## Monitoring

### View Traffic Statistics

```bash
# Real-time bandwidth monitoring
sudo iftop -i eth0

# Traffic statistics
sudo vnstat -i eth0

# Connection tracking
sudo conntrack -L
```

### Grafana Dashboard

Access Grafana at: `http://20.0.0.218:3000`

Default credentials:
- Username: `admin`
- Password: `admin`

## Troubleshooting

### Check Service Status

```bash
sudo systemctl status gocloud-router
sudo journalctl -u gocloud-router -n 50
```

### Verify IP Forwarding

```bash
cat /proc/sys/net/ipv4/ip_forward
# Should output: 1
```

### Check Firewall Rules

```bash
sudo nft list ruleset
```

### Test WAN Connectivity

```bash
# Test from router
ping -I eth0 8.8.8.8

# Check routing table
ip route show
```

### Debug Mode

Run the router in debug mode:

```bash
sudo /opt/gocloud-router/bin/router -config /etc/gocloud/config.yaml
```

## Common Issues

### Interface Not Found

**Problem**: Error about interface not existing

**Solution**: 
```bash
# List interfaces
ip link show

# Update config.yaml with correct interface names
```

### Permission Denied

**Problem**: Cannot modify network settings

**Solution**: Make sure you're running as root:
```bash
sudo /opt/gocloud-router/bin/router
```

### Port Already in Use

**Problem**: API server won't start

**Solution**: Check what's using the port:
```bash
sudo lsof -i :8443
# Kill the process or change the port in config.yaml
```

## Next Steps

- Configure SSL certificates for HTTPS
- Set up Prometheus monitoring
- Configure VPN access
- Integrate with RADIUS/LDAP
- Enable cloud management

## Documentation

See full documentation in the `docs/` directory.

## Support

- GitHub Issues: https://github.com/cjtech91/ubuntu-gocloud-router/issues
- Documentation: https://github.com/cjtech91/ubuntu-gocloud-router/wiki
