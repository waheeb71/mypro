# CyberNexus Enterprise NGFW — Full System Documentation
> Version 2.0.0 · March 2026 · Proprietary

---

## 1. Overview

**CyberNexus** is a software-defined Enterprise Next-Generation Firewall (NGFW) built on Python 3.10+ and React. It merges classical packet routing with deep Layer 7 application inspection, multi-layer AI-driven threat detection, eBPF kernel acceleration, and a fully web-first management interface.

### Design Philosophy
- **Zero Configuration Required**: Automatic network interface discovery and role assignment.
- **Web-First Management**: Every tuning knob, log line, and metric is exposed via the React Dashboard. No CLI required for day-to-day operations.
- **AI-Native**: The system learns the baseline of each host and autonomously adapts firewall sensitivity to the current threat level.
- **Defense in Depth**: Multiple independent detection layers — signatures, behavioral ML models, and RL-based policy optimization — must all be bypassed simultaneously for a threat to succeed.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    INTERNET / WAN                           │
└───────────────────────────┬─────────────────────────────────┘
                            │
              ┌─────────────▼─────────────┐
              │    eBPF XDP Engine        │  ← Layer 2/3: Kernel-level block
              │  (Known Bad IPs dropped   │    (<1μs latency, zero CPU cost)
              │   before user-space)      │
              └─────────────┬─────────────┘
                            │
              ┌─────────────▼─────────────┐
              │    Traffic Router         │  ← Layer 3/4: ACL, Zone, Schedule rules
              │ (ACL Engine, Zone Mgmt,   │
              │  Time Schedules, QoS)     │
              └─────────────┬─────────────┘
                            │
       ┌────────────────────┼───────────────────┐
       │                    │                   │
 ┌─────▼────┐        ┌──────▼──────┐    ┌──────▼──────┐
 │Transparent│       │  Forward    │    │  Reverse    │
 │  Proxy   │        │  Proxy      │    │  Proxy      │
 │(MITM SSL)│        │(HTTP CONNECT│    │(App Gateway │
 └─────┬────┘        └──────┬──────┘    │ + WAF)      │
       │                    │           └──────┬──────┘
       └────────────────────┼───────────────────┘
                            │
              ┌─────────────▼──────────────┐
              │   Inspection Pipeline (DPI)│  ← Layer 7: Deep Packet Inspection
              │  ┌────────┐ ┌────────────┐ │
              │  │  WAF   │ │    DLP     │ │
              │  └────────┘ └────────────┘ │
              │  ┌────────────────────────┐ │
              │  │  AI Inspector (DL)     │ │
              │  └────────────────────────┘ │
              └─────────────┬───────────────┘
                            │
              ┌─────────────▼──────────────┐
              │     ML / AI Stack          │  ← Layers 4–7: Machine Intelligence
              │  AnomalyDetector (ONNX)    │
              │  DeepTrafficClassifier     │
              │  UserBehaviorAnalytics     │
              │  AttackForecaster          │
              │  RLPolicyOptimizer         │
              └─────────────┬──────────────┘
                            │
              ┌─────────────▼──────────────┐
              │  Mitigation Orchestrator   │  ← Autonomous Response
              │  + Recovery Manager        │
              └────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Core Engine (`core/engine.py`)
The `NGFWApplication` class is the supervisor for all sub-systems. Responsible for:
- Loading and validating `config.yaml`.
- Initializing each component in the correct dependency order.
- Managing graceful startup and shutdown.
- Starting/stopping the firewall data plane independently from the REST API.

### 3.2 eBPF XDP Engine (`acceleration/ebpf/`)
Leverages Linux eBPF (Extended Berkeley Packet Filter) maps and XDP (eXpress Data Path) hooks. Any IP address added to the `blocked_ips` BPF map is dropped at the NIC driver level **before** it reaches any Python code. This protects against volumetric DDoS attacks with no CPU impact.

### 3.3 SSL/TLS Interception Engine (`core/ssl_engine/`)
| Component | Role |
|---|---|
| `CAPoolManager` | Manages the root CA key pair; generates per-site leaf certificates on-the-fly |
| `SSLInspector` | Creates MiTM SSL tunnels; decrypts traffic for DPI layer |
| `SSLPolicyEngine` | Decides which domains/IPs to bypass inspection (e.g., banking, medical) |

**Client Setup Required:** The NGFW Root CA certificate (downloadable from the Web UI → Certificate Manager) must be installed in the Trusted Store of each intercepted device.

### 3.4 Inspection Pipeline (`inspection/`)
An ordered plugin pipeline. Each plugin inspects the decrypted HTTP payload and can block or allow:

| Plugin | What It Catches |
|---|---|
| `WAFInspectorPlugin` | SQL Injection, XSS, Path Traversal, Command Injection |
| `DLPInspectorPlugin` | Credit Card numbers (Luhn), Social Security Numbers, sensitive keywords |
| `AIInspector` | Unknown protocol fingerprints via the Deep Traffic Classifier |

### 3.5 ML / AI Stack (`ml/`)
The system loads `.onnx`, `.pkl`, or `.joblib` model files at startup:

| Model | Algorithm | Role |
|---|---|---|
| Anomaly Detector | Isolation Forest | Detect statistically rare connections |
| Deep Classifier | Neural Network (DL) | Protocol and app fingerprinting |
| RL Optimizer | Q-Learning | Autonomous rate-limit & sensitivity tuning |
| Attack Forecaster | ARIMA + Trend | Predict incoming DDoS 10–60s in advance |
| User Behavior Analytics | Baseline + Z-Score | Detect insider threats and compromised accounts |

### 3.6 Autonomous Response (`response/`)
When the ML engine sets a high-confidence threat event:
1. `MitigationOrchestrator.handle_threat(event)` is called.
2. The Orchestrator creates a `MitigationPlan` appropriate to the threat type.
3. It pushes the malicious IP to the XDP block map OR throttles the subnet via QoS.
4. The `RecoveryManager` tracks every action and automatically reverts it after the cooldown period.

### 3.7 High Availability (`core/ha/`)
- **Election Protocol**: VRRP-like priority election. The node with the highest priority becomes `MASTER`.
- **State Synchronization**: New TCP connections on the MASTER node are broadcast to the BACKUP via `StateSynchronizer` UDP multicasts — ensuring zero dropped connections on failover.

---

## 4. REST API Reference

Base URL: `http://<host>:8000/api/v1`

All endpoints (except `/auth/login` and `/health`) require a JWT Bearer token.

### Authentication
| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/login` | Returns a 30-minute JWT access token |

### System
| Method | Path | Description |
|---|---|---|
| `GET` | `/status` | CPU, memory, HA state, uptime |
| `GET` | `/system/logs?limit=500` | Recent application log ring buffer |
| `POST` | `/system/engine/start` | Dynamically start the firewall data plane |
| `POST` | `/system/engine/stop` | Gracefully stop the data plane (keeps API alive) |
| `GET` | `/health` | No-auth health probe for load balancers |

### Firewall Rules
| Method | Path | Description |
|---|---|---|
| `GET` | `/rules` | List all active ACL rules |
| `POST` | `/rules` | Create a new rule (Zone, App Category, Schedule) |
| `PUT` | `/rules/{id}` | Modify an existing rule |
| `DELETE` | `/rules/{id}` | Remove a rule |
| `POST` | `/policy/evaluate` | Test a connection against current policy |
| `POST` | `/block/{ip}` | Immediately block an IP at kernel level |
| `DELETE` | `/block/{ip}` | Lift an IP block |

### Network Interfaces
| Method | Path | Description |
|---|---|---|
| `GET` | `/interfaces` | List all physical NICs with status and current role |
| `POST` | `/interfaces/assign` | Assign WAN/LAN/DMZ/MGMT/HA role to an interface |

### VPN (WireGuard)
| Method | Path | Description |
|---|---|---|
| `GET` | `/vpn/status` | WireGuard interface link state |
| `GET` | `/vpn/peers` | List all configured peers |
| `POST` | `/vpn/peers` | Add a new peer |
| `DELETE` | `/vpn/peers/{key}` | Revoke a peer |

### QoS
| Method | Path | Description |
|---|---|---|
| `GET` | `/qos/config` | Read current QoS policy |
| `PUT` | `/qos/config` | Update bandwidth limits |

### Certificates
| Method | Path | Description |
|---|---|---|
| `GET` | `/certificates/ca/info` | Fetch CA subject, validity, SHA-256 fingerprint |
| `GET` | `/certificates/ca/download?format=pem` | Download cert (pem/der/p12) |
| `POST` | `/certificates/ca/generate` | Rotate Root CA (breaks existing client trust) |

### AI Models
| Method | Path | Description |
|---|---|---|
| `GET` | `/ai/models` | List expected models and their load status |
| `POST` | `/ai/models/upload/{model_id}` | Upload `.onnx`, `.pkl`, or `.joblib` model file |

### Traffic Analytics
| Method | Path | Description |
|---|---|---|
| `GET` | `/traffic/stats` | Packets/sec, bytes/sec, protocol breakdown |
| `GET` | `/anomalies` | Recent ML-detected anomaly events |

---

## 5. Web Dashboard (UI) Pages

| Page | Route | Description |
|---|---|---|
| Dashboard | `/` | Live system health, CPU, memory, active threats |
| Live Traffic | `/traffic` | Real-time packet flow visualization |
| Firewall Rules | `/rules` | Advanced ACL builder with zones and schedules |
| Alerts | `/alerts` | Security incident log |
| AI Pipeline | `/ai-pipeline` | ML model status and upload, eBPF insights |
| VPN Manager | `/vpn` | WireGuard peer management |
| QoS Traffic | `/qos` | Bandwidth allocation controls |
| System HA | `/ha` | Cluster node state and health |
| Hardware Map | `/interfaces` | Physical NIC discovery and zone assignment |
| Certificate Manager | `/certificates` | Root CA, download links, rotation |
| System Terminal | `/terminal` | Live streaming system log viewer |
| System Management | `/system` | Engine start/stop, script execution |
| Settings | `/settings` | Language, theme, and user preferences |

---

## 6. Running the System

### Start Everything (Production)
```bash
# Must be run as root for kernel/socket access
sudo python main.py -c /etc/ngfw/config.yaml
```

### Start API Only (Development / UI Testing)
```bash
# Run API in isolation — no kernel features
python -m uvicorn api.rest.main:app --host 0.0.0.0 --port 8000 --reload
```

### Start React Dashboard
```bash
cd web-ui
npm install
npm run dev
# UI available at http://localhost:5173
```

### Default Login Credentials
| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | Administrator |
| `operator` | `operator123` | Read-only Operator |

> ⚠️ **Change these immediately** via the Settings page before deploying to any network.

---

## 7. Configuration Reference (`config/defaults/base.yaml`)

```yaml
proxy:
  mode: transparent           # transparent | forward | reverse | all
  forward_listen_port: 8080
  transparent_intercept_port: 8443
  
tls:
  ca_cert_path: /etc/ngfw/certs/ca.crt
  ca_key_path: /etc/ngfw/certs/ca.key
  inspect: true               # Enable SSL decryption
  bypass_domains:             # Domains to never inspect
    - "*.bank.com"
    - "*.healthcare.gov"

ebpf:
  enabled: true
  interface: "eth0"           # Physical NIC to attach XDP program

ml:
  enabled: true
  anomaly_contamination: 0.1  # Expected ratio of anomalous traffic (0.0–0.5)

vpn:
  enabled: false
  interface: wg0
  ip_address: "10.8.0.1/24"
  listen_port: 51820

ha:
  enabled: false
  node_id: "node_1"
  priority: 100               # Higher = becomes MASTER in election
  peer_ip: "192.168.1.2"

api:
  host: "0.0.0.0"
  port: 8000
  enabled: true

logging:
  level: INFO
  file: /var/log/ngfw/ngfw.log
  max_bytes: 104857600        # 100 MB before rotation
  backup_count: 10
```

---

## 8. Security Notes

1. **Run as Root Safely**: Use Linux capabilities (`CAP_NET_ADMIN`, `CAP_BPF`) instead of full root where possible.
2. **JWT Secret**: Set `NGFW_SECRET_KEY` environment variable to a strong random string in production.  
   ```bash
   export NGFW_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
   ```
3. **CORS**: Set `NGFW_ALLOWED_ORIGINS` to only your dashboard host.
4. **CA Private Key**: The file `/etc/ngfw/certs/ca.key` must have `chmod 600` and never leave the appliance.

---

*CyberNexus Enterprise NGFW — All Rights Reserved © 2026*
