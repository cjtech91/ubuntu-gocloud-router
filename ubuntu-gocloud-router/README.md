# Ubuntu GoCloud Router System

A comprehensive enterprise-grade router system built on Ubuntu, featuring all capabilities of commercial solutions like GoCloud.

## Features

### Core Routing
- Multi-WAN load balancing & failover
- VLAN segmentation and management
- Static/dynamic routing (RIP, OSPF, BGP)
- PPPoE multi-session support
- IPv4/IPv6 dual-stack

### Traffic Management
- Per-user/IP/application bandwidth control
- QoS prioritization with HTB and fq_codel
- Deep Packet Inspection (DPI)
- Application recognition and flow control
- Connection tracking and limiting

### Access Control
- Captive portal authentication (web/SMS/social)
- User behavior management
- URL filtering with blacklist/whitelist
- MAC/IP binding and enforcement
- Time-based access policies

### Security
- Stateful firewall with nftables
- ARP spoofing protection
- DoS/DDoS mitigation
- VPN support (WireGuard, OpenVPN, IPSec)
- Intrusion detection (Suricata)

### Management
- Web-based admin interface
- REST API for automation
- Real-time monitoring dashboard
- Remote cloud management
- Automatic firmware updates
- Mobile app support

### Enterprise Features
- Multi-tenant support
- RADIUS/LDAP integration
- Game acceleration & caching
- Guest network isolation
- Bandwidth pooling
- Detailed analytics and reporting

## Architecture

```
├── core/               # Core routing and networking
├── traffic/            # Traffic management and QoS
├── auth/              # Authentication and user management
├── security/          # Firewall, IDS, VPN
├── monitoring/        # Logging, metrics, alerts
├── api/               # REST API server
├── web/               # Web management interface
├── cloud/             # Cloud management client
└── scripts/           # Installation and maintenance scripts
```

## Requirements

- Ubuntu 22.04 LTS or later
- Multi-NIC hardware (minimum 2 interfaces)
- Minimum 2GB RAM, 4GB+ recommended
- 20GB+ storage

## Quick Start

```bash
# Clone repository
git clone https://github.com/cjtech91/ubuntu-gocloud-router.git
cd ubuntu-gocloud-router

# Run installation
sudo ./scripts/install.sh

# Access web interface
# https://20.0.0.218:8443
```

## Technology Stack

- **Routing**: FRRouting, iproute2
- **Firewall**: nftables, iptables
- **Traffic Control**: tc, HTB, fq_codel
- **DPI**: nDPI
- **Auth**: FreeRADIUS, custom portal
- **VPN**: WireGuard, OpenVPN, strongSwan
- **IDS**: Suricata
- **Backend**: Go, Python
- **Frontend**: React, TypeScript
- **Database**: PostgreSQL, Redis
- **Monitoring**: Prometheus, Grafana

## License

MIT License
