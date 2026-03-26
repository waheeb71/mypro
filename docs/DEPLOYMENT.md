# Enterprise CyberNexus - Deployment Guide

## 📋 Prerequisites

### System Requirements

**Minimum**:
- **OS**: Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+)
- **Kernel**: 4.15+ (5.0+ recommended for XDP native mode)
- **CPU**: 2 cores
- **RAM**: 4 GB
- **Disk**: 20 GB
- **Network**: 1 Gbps NIC

**Recommended (Production)**:
- **OS**: Ubuntu 22.04 LTS or RHEL 9
- **Kernel**: 5.15+ (latest stable)
- **CPU**: 8+ cores
- **RAM**: 16+ GB
- **Disk**: 100+ GB SSD
- **Network**: 10 Gbps NIC with XDP support

### Software Dependencies

```bash
# Python 3.9+
python3 --version

# pip
python3 -m pip --version

# Git
git --version

# Optional: BCC for eBPF/XDP
# Check availability
which bpftool
```

---

## 🚀 Installation

### 1. Clone Repository

```bash
cd /opt
sudo git clone <repository-url> enterprise_CyberNexus
cd enterprise_CyberNexus
sudo chown -R $(whoami):$(whoami) .
```

### 2. Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install production dependencies
pip install --upgrade pip
pip install -r requirements/production.txt
```

### 3. Install eBPF Tools (Optional, for XDP)

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y \
    linux-headers-$(uname -r) \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc \
    libbpf-dev
```

#### RHEL/CentOS:
```bash
sudo yum install -y \
    kernel-devel-$(uname -r) \
    bcc-tools \
    python3-bcc \
    libbpf-devel
```

### 4. Verify Installation

```bash
# Check Python dependencies
pip list | grep -E "(fastapi|uvicorn|prometheus|aiohttp)"

# Check BCC (if installed)
python3 -c "from bcc import BPF; print('BCC available')"

# Check kernel version
uname -r
```

---

## ⚙️ Configuration

### 1. Create Configuration File

```bash
# Copy example config
cp config/config.example.yaml config/config.yaml

# Edit configuration
nano config/config.yaml
```

### 2. Basic Configuration

**config/config.yaml**:
```yaml
general:
  mode: transparent  # transparent, forward, or reverse
  log_level: info    # debug, info, warning, error

network:
  listen_address: "0.0.0.0"
  listen_port: 8080
  upstream_timeout: 30

ebpf:
  enabled: true
  interface: eth0        # Your network interface
  xdp_mode: native       # native, generic, or offload
  buffer_size: 4096

decision_engine:
  policy_mode: balanced  # permissive, balanced, strict, paranoid
  fail_mode: fail_open   # fail_open or fail_closed
  ttl_cleanup_interval: 60

threat_intel:
  feeds:
    - name: example_feed
      url: https://example.com/threats.json
      update_interval: 3600
      format: json
      enabled: true

event_sink:
  buffer_size: 1000
  flush_interval: 5
  batch_size: 100
  backends:
    - type: file
      output_dir: /var/log/CyberNexus
      format: json
      rotation: daily
```

### 3. SSL/TLS Certificates (for HTTPS inspection)

```bash
# Generate CA certificate
mkdir -p /etc/CyberNexus/certs
openssl req -x509 -newkey rsa:4096 \
  -keyout /etc/CyberNexus/certs/ca-key.pem \
  -out /etc/CyberNexus/certs/ca-cert.pem \
  -days 3650 -nodes \
  -subj "/CN=Enterprise CyberNexus CA"

# Set permissions
sudo chmod 600 /etc/CyberNexus/certs/ca-key.pem
sudo chmod 644 /etc/CyberNexus/certs/ca-cert.pem
```

### 4. Environment Variables

```bash
# Create .env file
cat > /opt/enterprise_CyberNexus/.env << 'EOF'
CyberNexus_CONFIG=/opt/enterprise_CyberNexus/config/config.yaml
CyberNexus_SECRET_KEY=your-secret-key-here-min-32-chars
CyberNexus_ADMIN_PASSWORD=admin-password-here
CyberNexus_OPERATOR_PASSWORD=operator-password-here
CyberNexus_ALLOWED_ORIGINS=http://localhost:3000,https://dashboard.company.com
CyberNexus_ENV=production
EOF

# Set permissions
chmod 600 /opt/enterprise_CyberNexus/.env
```

---

## 🏃 Running

### Development Mode

```bash
cd /opt/enterprise_CyberNexus
source venv/bin/activate

# Run directly
python main.py -c config/config.yaml

# Or with specific log level
python main.py -c config/config.yaml --log-level debug
```

### Production Mode (systemd)

#### 1. Create Systemd Service

```bash
sudo cp systemd/CyberNexus.service /etc/systemd/system/
sudo nano /etc/systemd/system/CyberNexus.service
```

**Verify paths in service file**:
```ini
[Unit]
Description=Enterprise Next-Generation Firewall
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/enterprise_CyberNexus
Environment="PATH=/opt/enterprise_CyberNexus/venv/bin"
EnvironmentFile=/opt/enterprise_CyberNexus/.env
ExecStart=/opt/enterprise_CyberNexus/venv/bin/python3 main.py -c /opt/enterprise_CyberNexus/config/config.yaml
Restart=on-failure
RestartSec=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=CyberNexus

# Security  CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

#### 2. Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable CyberNexus

# Start service
sudo systemctl start CyberNexus

# Check status
sudo systemctl status CyberNexus

# View logs
sudo journalctl -u CyberNexus -f
```

---

## 🔍 Verification

### 1. Health Checks

```bash
# Basic health
curl http://localhost:8080/health

# Liveness probe
curl http://localhost:8080/api/v1/health/liveness

# Readiness probe
curl http://localhost:8080/api/v1/health/readiness
```

**Expected Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-02-14T00:00:00Z",
  "uptime": 123.45
}
```

### 2. Authentication

```bash
# Get JWT token
TOKEN=$(curl -X POST http://localhost:8080/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-admin-password"}' \
  | jq -r '.access_token')

echo "Token: $TOKEN"
```

### 3. Test API Endpoints

```bash
# Get system status (requires auth)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/status

# List rules
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/rules

# Check metrics
curl http://localhost:8080/metrics
```

### 4. Verify XDP (if enabled)

```bash
# Check XDP attachment
ip link show eth0 | grep -i xdp

# List BPF programs
sudo bpftool prog show

# List BPF maps
sudo bpftool map show
```

---

## 📊 Monitoring Setup

### Prometheus Configuration

**prometheus.yml**:
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'CyberNexus'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
```

### Grafana Dashboard

```bash
# Import dashboard (TODO: create dashboard JSON)
# Or create custom dashboard using metrics from /metrics endpoint
```

---

## 🔧 Network Configuration

### Transparent Proxy Mode

#### 1. Enable IP Forwarding

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Make persistent
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" | sudo tee -a /etc/sysctl.conf
```

#### 2. Configure iptables

```bash
# Redirect HTTP/HTTPS to CyberNexus
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080

# Save iptables rules
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

#### 3. Set as Default Gateway

Configure client machines to use CyberNexus server as default gateway.

---

## 🔐 Security Hardening

### 1. File Permissions

```bash
# Configuration files
sudo chmod 600 /opt/enterprise_CyberNexus/config/config.yaml
sudo chmod 600 /opt/enterprise_CyberNexus/.env

# Certificates
sudo chmod 600 /etc/CyberNexus/certs/ca-key.pem
sudo chmod 644 /etc/CyberNexus/certs/ca-cert.pem

# Log directory
sudo mkdir -p /var/log/CyberNexus
sudo chmod 750 /var/log/CyberNexus
sudo chown CyberNexus:CyberNexus /var/log/CyberNexus  # If running as non-root
```

### 2. Firewall Rules

```bash
# Allow only necessary ports
sudo ufw allow 8080/tcp  # CyberNexus API
sudo ufw allow 22/tcp    # SSH (management)
sudo ufw enable
```

### 3 Change Default Credentials

```bash
# Update .env file with strong passwords
CyberNexus_SECRET_KEY=$(openssl rand -hex 32)
CyberNexus_ADMIN_PASSWORD=$(openssl rand -base64 24)
CyberNexus_OPERATOR_PASSWORD=$(openssl rand -base64 24)
```

---

## 🔄 Maintenance

### Logs

```bash
# View systemd logs
sudo journalctl -u CyberNexus -n 100 --no-pager

# Follow logs in real-time
sudo journalctl -u CyberNexus -f

# Application logs (if file backend configured)
tail -f /var/log/CyberNexus/events_*.json
```

### Backups

```bash
# Backup configuration
sudo cp -r /opt/enterprise_CyberNexus/config /backup/CyberNexus-config-$(date +%Y%m%d)

# Backup certificates
sudo cp -r /etc/CyberNexus/certs /backup/CyberNexus-certs-$(date +%Y%m%d)

# Backup database (if using SQLite)
sudo cp /var/lib/CyberNexus/CyberNexus.db /backup/CyberNexus-db-$(date +%Y%m%d).db
```

### Updates

```bash
# Pull latest code
cd /opt/enterprise_CyberNexus
git pull

# Update dependencies
source venv/bin/activate
pip install --upgrade -r requirements/production.txt

# Restart service
sudo systemctl restart CyberNexus
```

---

## 🐳 Docker Deployment (Alternative)

### Build Image

```bash
docker build -t enterprise-CyberNexus:latest .
```

### Run Container

```bash
docker run -d \
  --name CyberNexus \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v /opt/CyberNexus/config:/app/config:ro \
  -v /var/log/CyberNexus:/var/log/CyberNexus \
  -e CyberNexus_CONFIG=/app/config/config.yaml \
  enterprise-CyberNexus:latest
```

### Docker Compose

```yaml
version: '3.8'

services:
  CyberNexus:
    image: enterprise-CyberNexus:latest
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ./config:/app/config:ro
      - ./logs:/var/log/CyberNexus
    environment:
      - CyberNexus_CONFIG=/app/config/config.yaml
    restart: unless-stopped
```

---

## 🚨 Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status CyberNexus

# Check logs
sudo journalctl -u CyberNexus -n 50 --no-pager

# Check configuration
python -c "import yaml; yaml.safe_load(open('config/config.yaml'))"

# Check port availability
sudo netstat -tulpn | grep 8080
```

### XDP Not Working

```bash
# Check kernel support
zgrep CONFIG_BPF /proc/config.gz | grep -v "^#"

# Check driver support (for native mode)
ethtool -i eth0

# Try generic mode
# In config.yaml: xdp_mode: generic

# Check BCC installation
python3 -c "from bcc import BPF; print('OK')"
```

### High CPU Usage

```bash
# Check process stats
top -p $(pgrep -f "python.*main.py")

# Reduce event buffer sizes in config
# buffer_size: 1000 → 500
# batch_size: 100 → 50

# Disable XDP if not needed
# ebpf.enabled: false
```

### Memory Issues

```bash
# Check memory usage
free -h
ps aux | grep python

# Reduce buffer sizes
# Increase flush_interval for less frequent writes
```

---

## 📈 Performance Tuning

### Kernel Parameters

```bash
# /etc/sysctl.conf
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.core.netdev_max_backlog=5000
net.ipv4.tcp_congestion_control=bbr

# Apply
sudo sysctl -p
```

### Application Tuning

**config/config.yaml**:
```yaml
event_sink:
  buffer_size: 10000     # Increase for high traffic
  flush_interval: 1      # Faster flushing
  batch_size: 200        # Larger batches

ebpf:
  buffer_size: 8192      # Larger XDP buffer
```

---

## ✅ Post-Deployment Checklist

- [ ] Service starts successfully
- [ ] Health checks return 200 OK
- [ ] Authentication works
- [ ] API endpoints respond correctly
- [ ] Metrics endpoint accessible
- [ ] XDP attached (if enabled)
- [ ] Logs being written
- [ ] Prometheus scraping metrics
- [ ] Backups configured
- [ ] Monitoring alerts configured
- [ ] Documentation reviewed

---

## 📞 Support

For deployment issues:
1. Check logs: `sudo journalctl -u CyberNexus -f`
2. Review configuration: `cat config/config.yaml`
3. Test health: `curl http://localhost:8080/health`
4. Check [troubleshooting section](#🚨-troubleshooting)
