# 🧪 Lab Setup Guide: Kali Linux Firewall

This guide explains how to set up **Enterprise NGFW** on a **Kali Linux** machine acting as a gateway/firewall between an **Attacker** and a **Target Server**, without using Docker.

## 📐 Network Topology

We will use a standard "Man-in-the-Middle" (Gateway) topology.

```
       [ Attacker ]                [ Kali Firewall ]                 [ Target Server ]
     IP: 192.168.10.2             IP 1: 192.168.10.1 (eth1)           IP: 192.168.20.2
     GW: 192.168.10.1             IP 2: 192.168.20.1 (eth0)           GW: 192.168.20.1
           |                              |                                   |
           |                              |                                   |
    (LAN Network) ------------------------+------------------------- (WAN/Server Network)
```

### Virtual Machine Configuration
1.  **Kali Linux (Firewall):**
    - **Network Adapter 1 (eth0):** Bridged or NAT (Connects to Internet/Server).
    - **Network Adapter 2 (eth1):** Host-Only or Internal Network (Connects to Attacker).
2.  **Attacker Machine:**
    - Network Adapter: Host-Only/Internal (Same as Kali eth1).
    - Gateway IP: Set to Kali's eth1 IP (e.g., 192.168.10.1).
3.  **Target Server:**
    - Network Adapter: Bridged/NAT (Same as Kali eth0).

---

## 🛠️ Phase 1: Kali Linux Setup

### 1. Install Prerequisites
Open a terminal on Kali and run:
```bash
sudo apt update
sudo apt install -y python3-pip python3-venv build-essential libpcap-dev libssl-dev iptables
```

### 2. Prepare the Project
Copy the project to Kali (using git or drag-and-drop):
```bash
cd /opt
sudo git clone https://your-repo/enterprise_ngfw.git
sudo chown -R kali:kali enterprise_ngfw
cd enterprise_ngfw
```

### 3. Setup Python Environment
Create a virtual environment to isolate dependencies:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements/base.txt
pip install -r requirements/phase2_3.txt  # If exists
```

### 4. Configure Environment
```bash
cp .env.example .env
nano .env
# Set NGFW_SECRET_KEY, NGFW_ADMIN_PASSWORD, etc.
```

---

## ⚙️ Phase 2: Network Configuration (Crucial)

### 1. Enable IP Forwarding
Allow Kali to route packets between interfaces:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
# To make it permanent: echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

### 2. Configure NAT (Masquerading)
Allow Attacker to reach the Internet/Server through Kali:
```bash
# Replace 'eth0' with your WAN interface name
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### 3. Redirect Traffic to NGFW (Transparent Proxy)
Intercept HTTP (80) and HTTPS (443) traffic and send it to NGFW listening on port **8443**:

```bash
# Redirect HTTP
sudo iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 8080

# Redirect HTTPS
sudo iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 443 -j REDIRECT --to-port 8443
```

> **Note:** `eth1` is the interface connected to the Attacker. Adjust if your interface name is different (check with `ip a`).

---

## 🚀 Phase 3: Run the Firewall

### 1. Start the API & Core Engine
On Kali, run:
```bash
source venv/bin/activate
# Run as root to allow port binding and eBPF access
sudo venv/bin/python main.py
```

### 2. Start the Dashboard (Optional)
Open a new terminal:
```bash
cd /opt/enterprise_ngfw/api/dashboard
python3 -m http.server 8080
```

---

## 🧪 Phase 4: Testing

1.  **On Attacker Machine:**
    - Open Browser.
    - Try to access `http://example.com` or `https://google.com`.
    - The traffic should flow through Kali.

2.  **On Kali (Firewall):**
    - Check the logs in the terminal running `main.py`. You should see "New connection from..."
    - Open Dashboard: `http://localhost:8080`.

3.  **On Target Server:**
    - If hosting a web server, check access logs to see connections coming from Kali's IP (due to NAT).

---

## 🛡️ Troubleshooting

### "Connection Refused"
- Check if `main.py` is running and listing on ports 8080/8443.
- Check `iptables` rules: `sudo iptables -t nat -L -v`.

### "No Internet on Attacker"
- Ensure IP Forwarding is enabled (`cat /proc/sys/net/ipv4/ip_forward` should be `1`).
- Ensure NAT Masquerade rule is active.

### "SSL Errors"
- Since this is a transparent proxy, the Attacker will see a "Self-Signed Certificate" warning because the NGFW is intercepting HTTPS.
- To fix this, import the NGFW's Root CA certificate into the Attacker's browser/OS trust store.
