# Enterprise NGFW - System Architecture

## 📐 Architecture Overview

Enterprise NGFW implements a **hybrid architecture** combining kernel-level packet filtering with user-space deep inspection, providing both performance and flexibility.

---

## 🏛️ High-Level Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                           Network Traffic                              │
└────────────────────────────┬──────────────────────────────────────────┘
                             │
                             ▼
        ┌────────────────────────────────────────────────┐
        │         XDP/eBPF Fast Path (Kernel)            │
        │  ┌──────────────────────────────────────────┐  │
        │  │  • Port filtering                        │  │
        │  │  • IP blocklist matching                 │  │
        │  │  • Basic rate limiting                   │  │
        │  │  • XDP_PASS / XDP_DROP / XDP_REDIRECT    │  │
        │  └──────────────────────────────────────────┘  │
        └─────────────┬──────────────────┬───────────────┘
                      │                  │
             XDP_PASS │                  │ XDP_DROP (logged)
                      │                  │
                      ▼                  ▼
        ┌──────────────────────┐  ┌──────────────┐
        │  User-Space Queue    │  │  Event Sink  │
        └──────────┬───────────┘  └──────────────┘
                   │
                   ▼
        ┌────────────────────────────────────────────────┐
        │       Decision Engine (User-Space)             │
        │  ┌──────────────────────────────────────────┐  │
        │  │  • Threat Intelligence                   │  │
        │  │  • Reputation Engine                     │  │
        │  │  • Geo-IP Filtering                      │  │
        │  │  • ML Predictions                        │  │
        │  │  • TTL Manager                           │  │
        │  └──────────────────────────────────────────┘  │
        └─────────────┬──────────────────┬───────────────┘
                      │                  │
          ALLOW/      │                  │ BLOCK/RATE_LIMIT/
          MONITOR     │                  │ QUARANTINE
                      │                  │
                      ▼                  ▼
        ┌──────────────────────┐  ┌──────────────────┐
        │    Proxy Modes       │  │   Event Sink     │
        │  • Transparent       │  │   • File         │
        │  • Forward           │  │   • Database     │
        │  • Reverse           │  │   • Streaming    │
        └──────────────────────┘  └──────────────────┘
```

---

## 🔧 Component Architecture

### 1. eBPF/XDP Layer

**Location**: `acceleration/ebpf/`

**Purpose**: Ultra-fast kernel-level packet filtering

**Components**:
- **XDP Program** (`port_filter.c`): C/eBPF code running in kernel
- **XDP Engine** (`xdp_engine.py`): Python manager for XDP programs
- **Mode Switcher** (`xdp_mode_switcher.py`): Runtime mode switching

**Data Flow**:
```
Packet arrival → XDP program → Decision (PASS/DROP/REDIRECT)
                                    │
                                    ├─→ PASS: to user-space
                                    ├─→ DROP: discard + log event
                                    └─→ REDIRECT: to specific queue
```

**Modes**:
- **Native XDP**: Best performance, requires driver support
- **Generic XDP**: Kernel fallback, works everywhere
- **Offload XDP**: NIC firmware offload (rare)

---

### 2. Decision Engine

**Location**: `policy/smart_blocker/`

**Purpose**: Intelligent traffic analysis and policy enforcement

**Component Diagram**:
```
┌─────────────────────────────────────────────────┐
│           Decision Engine Core                   │
│                                                  │
│  ┌───────────────────────────────────────────┐  │
│  │   Threat Intelligence                     │  │
│  │   - Known malicious IPs/domains           │  │
│  │   - Threat levels (LOW/MED/HIGH/CRITICAL) │  │
│  │   - Automated feed updates                │  │
│  └───────────────────────────────────────────┘  │
│                      ▼                           │
│  ┌───────────────────────────────────────────┐  │
│  │   Reputation Engine                       │  │
│  │   - IP reputation scores (0-100)          │  │
│  │   - Domain reputation                     │  │
│  │   - Historical behavior                   │  │
│  └───────────────────────────────────────────┘  │
│                      ▼                           │
│  ┌───────────────────────────────────────────┐  │
│  │   Geo-IP Filter                           │  │
│  │   - Country allowlist/blocklist           │  │
│  │   - Continent-based rules                 │  │
│  └───────────────────────────────────────────┘  │
│                      ▼                           │
│  ┌───────────────────────────────────────────┐  │
│  │   Category Blocker                        │  │
│  │   - Content categories (90+)              │  │
│  │   - Domain categorization                 │  │
│  └───────────────────────────────────────────┘  │
│                      ▼                           │
│  ┌───────────────────────────────────────────┐  │
│  │   Policy Rules                            │  │
│  │   - Custom firewall rules                 │  │
│  │   - Time-based schedules                  │  │
│  └───────────────────────────────────────────┘  │
│                      ▼                           │
│  ┌───────────────────────────────────────────┐  │
│  │   TTL Manager                             │  │
│  │   - Temporary blocks                      │  │
│  │   - Rate limits                           │  │
│  │   - Quarantine                            │  │
│  └───────────────────────────────────────────┘  │
│                      ▼                           │
│  ┌───────────────────────────────────────────┐  │
│  │   Final Decision                          │  │
│  │   ALLOW / BLOCK / RATE_LIMIT / QUARANTINE │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

**Decision Flow**:
1. Check TTL restrictions (highest priority - active decisions)
2. Check threat intelligence feeds
3. Check IP/domain reputation
4. Check geo-IP rules
5. Check content categories
6. Apply firewall policy rules
7. Apply policy mode adjustments
8. Return final decision

**Fail-Safe Modes**:
- **Fail-Open**: Allow traffic if components fail (availability priority)
- **Fail-Closed**: Block traffic if components fail (security priority)

---

### 3. Event System

**Location**: `core/events/`

**Purpose**: Unified event collection, buffering, and distribution

**Architecture**:
```
┌────────────────────────────────────────────────────────┐
│                   Event Sources                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐     │
│  │   XDP    │  │  Proxy   │  │  Decision Engine │     │
│  └────┬─────┘  └────┬─────┘  └────────┬─────────┘     │
│       │             │                  │               │
│       └─────────────┴──────────────────┘               │
│                     │                                   │
└─────────────────────┼───────────────────────────────────┘
                      ▼
        ┌──────────────────────────┐
        │   Unified Event Sink     │
        │  ┌────────────────────┐  │
        │  │  Event Buffer      │  │
        │  │  (ring buffer)     │  │
        │  └─────────┬──────────┘  │
        │            │              │
        │            ▼              │
        │  ┌────────────────────┐  │
        │  │  Batch Processor   │  │
        │  │  • Aggregation     │  │
        │  │  • Deduplication   │  │
        │  └─────────┬──────────┘  │
        │            │              │
        └────────────┼──────────────┘
                     │
        ┌────────────┴────────────┐
        │                         │
        ▼                         ▼
┌──────────────┐         ┌──────────────┐
│ File Backend │         │ DB Backend   │
│ • JSON       │         │ • PostgreSQL │
│ • CSV        │         │ • SQLite     │
│ • Rotation   │         └──────────────┘
└──────────────┘                 │
        │                        │
        ▼                        ▼
┌──────────────┐         ┌──────────────┐
│ Log Files    │         │  Database    │
└──────────────┘         └──────────────┘
        │                        │
        └────────────┬───────────┘
                     ▼
        ┌──────────────────────┐
        │ Streaming Backend    │
        │ • Kafka              │
        │ • Redis Streams      │
        └──────────────────────┘
```

**Event Schema**:
```python
EventSchema:
  - timestamp
  - flow_id
  - src_ip, dst_ip, src_port, dst_port
  - protocol
  - bytes, packets
  - direction (inbound/outbound/internal/external)
  - source_path (xdp/normal/hybrid)
  - verdict (allow/drop/rate_limit/quarantine/log_only)
  - reason
  - ML fields (ml_score, ml_label, confidence, feature_vector_ref)
  - HTTP fields (url, method, user_agent, response_code)
  - metadata (flexible dict)
```

---

### 4. Proxy Modes

**Location**: `core/proxy_modes/`

**Modes**:

#### Transparent Proxy
```
Client → [NGFW as gateway] → Internet
         (intercepts traffic)
```
- Zero client configuration
- Requires network routing setup
- Full packet inspection

#### Forward Proxy
```
Client → [Explicit proxy config] → NGFW → Internet
```
- Requires client configuration
- Supports authentication
- HTTP CONNECT for HTTPS

#### Reverse Proxy
```
Internet → NGFW → Backend Servers
          (protects servers)
```
- Load balancing
- SSL termination
- WAF protection

---

### 5. TTL Management

**Location**: `policy/decision_ttl.py`

**Purpose**: Time-based temporary decisions with automatic expiry

**Data Structure**:
```python
TTLEntry:
  - target: str          # IP address
  - action: str          # BLOCK/RATE_LIMIT/QUARANTINE
  - created_at: datetime
  - expires_at: datetime
  - reason: str
  - metadata: dict       # e.g., rate limit value

TTLManager:
  _entries: Dict[action_type, Dict[target, TTLEntry]]
  
  Operations:
    - add_temporary_block(ip, ttl, reason)
    - add_rate_limit(ip, ttl, rate, reason)
    - add_quarantine(ip, ttl, reason)
    - extend_ttl(action, target, additional_time)
    - remove_entry(action, target)
    - cleanup_expired()  # Automatic background task
```

**Cleanup Process**:
```
┌─────────────────────┐
│  TTL Manager        │
│                     │
│  Background Task    │
│  (every 60s)        │
└──────────┬──────────┘
           │
           ▼
    Check all entries
           │
           ▼
    Find expired entries
           │
           ▼
    Remove expired
           │
           ▼
    Update statistics
```

---

### 6. Threat Intelligence Automation

**Location**: `policy/smart_blocker/feed_updater.py`

**Architecture**:
```
┌────────────────────────────────────────────┐
│        Threat Feed Updater                  │
│                                             │
│  Feed 1 ─┐                                  │
│  Feed 2 ─┼─→ Update Tasks                  │
│  Feed 3 ─┘   (async loops)                 │
│          │                                  │
│          ▼                                  │
│    ┌──────────────────┐                    │
│    │  Download Feed   │                    │
│    └────────┬─────────┘                    │
│             │                               │
│             ▼                               │
│    ┌──────────────────┐                    │
│    │ Verify Integrity │                    │
│    │  (SHA256 check)  │                    │
│    └────────┬─────────┘                    │
│             │                               │
│             ▼                               │
│    ┌──────────────────┐                    │
│    │  Parse & Validate│                    │
│    │  (JSON/CSV/TXT)  │                    │
│    └────────┬─────────┘                    │
│             │                               │
│             ▼                               │
│    ┌──────────────────┐                    │
│    │ Apply to Threat  │                    │
│    │  Intelligence    │                    │
│    └────────┬─────────┘                    │
│             │                               │
│             ▼                               │
│    ┌──────────────────┐                    │
│    │   Audit Log      │                    │
│    │  (JSON trail)    │                    │
│    └──────────────────┘                    │
└────────────────────────────────────────────┘
```

---

## 🔄 Data Flow Examples

### Example 1: XDP Fast Path (Blocked IP)
```
1. Packet arrives → eth0
2. XDP program checks IP against blocklist map
3. IP found in blocklist → XDP_DROP
4. Event logged to ring buffer
5. User-space reads event from ring buffer
6. Event sent to Unified Event Sink
7. Event written to backends (file/db/streaming)
```
**Latency**: ~5-10 μs

### Example 2: User-Space Inspection (HTTPS)
```
1. Packet arrives → eth0
2. XDP program: Not in blocklist → XDP_PASS
3. Packet reaches user-space proxy
4. TLS handshake interception
5. Certificate generation/validation
6. Decrypt HTTPS traffic
7. Decision Engine evaluation:
   a. Check threat intelligence
   b. Check reputation
   c. Check geo-IP
   d. Check categories
   e. Apply policy rules
8. Decision: ALLOW/BLOCK/RATE_LIMIT/QUARANTINE
9. Event created and sent to Unified Event Sink
10. If ALLOW: Re-encrypt and forward
11. If BLOCK: Drop connection + send block page
```
**Latency**: ~50-200 ms (includes TLS inspection)

### Example 3: Rate Limiting Decision
```
1. API request from 10.0.0.100
2. Decision Engine evaluates connection
3. Check TTL Manager: No active restrictions
4. Rate monitor detects: 1000 req/s from this IP
5. Decision Engine applies rate limit:
   - Action: RATE_LIMIT
   - Rate: 100 req/s
   - TTL: 3600s (1 hour)
6. TTL Manager adds entry
7. Subsequent requests from 10.0.0.100:
   - TTL Manager check: RATE_LIMIT active
   - Apply rate limiting (token bucket)
   - Log violations
8. After 1 hour: TTL Manager cleanup removes entry
```

---

## 🔒 Security Architecture

### Defense in Depth

```
Layer 1: XDP/eBPF (Kernel)
  ├─ Port filtering
  ├─ IP blocklists
  └─ Basic rate limiting

Layer 2: Decision Engine
  ├─ Threat intelligence
  ├─ Reputation scoring
  ├─ Geo-IP filtering
  └─ Category blocking

Layer 3: Deep Inspection
  ├─ Protocol analysis
  ├─ WAF rules
  ├─ DLP scanning
  └─ ML predictions

Layer 4: Policy Enforcement
  ├─ Firewall rules
  ├─ TTL restrictions
  └─ Fail-safe modes
```

---

## 📊 Observability Architecture

###Metrics Flow
```
Components → Prometheus Metrics → /metrics endpoint → Prometheus Server
                                                              │
                                                              ▼
                                                        Grafana Dashboard
```

### Health Check System
```
Health Checker ─┬→ Event Sink health
                ├→ Decision Engine health
                ├→ XDP Engine health
                └→ API Server health
                        │
                        ▼
                API Endpoints:
                  - /health
                  - /api/v1/health/liveness
                  - /api/v1/health/readiness
                  - /api/v1/health/detailed
```

---

## 🎭 Design Patterns

### 1. Event-Driven Architecture
- All components emit events to Unified Event Sink
- Decoupled components
- Asynchronous processing

### 2. Strategy Pattern
- Multiple proxy modes (Transparent/Forward/Reverse)
- Pluggable backends (File/Database/Streaming)
- Fail-safe modes (Fail-Open/Fail-Closed)

### 3. Observer Pattern
- Event Sink observes all traffic sources
- Multiple backends observe Event Sink
- Prometheus metrics observe all components

### 4. Chain of Responsibility
- Decision Engine processes requests through chain:
  TTL → Threat Intel → Reputation → Geo-IP → Categories → Policy

---

## 🔧 Scalability Considerations

### Horizontal Scaling
- **Multiple NGFW Instances**: Deploy behind load balancer
- **Shared Backend**: Use database/streaming backend for centralized events
- **Distributed TTL**: Use Redis for shared TTL state

### Vertical Scaling
- **XDP Multi-Queue**: Distribute packet processing across CPU cores
- **Async I/O**: Non-blocking operations throughout
- **Buffer Tuning**: Adjust event buffer sizes based on traffic

### Performance Tuning
- **XDP Native Mode**: Use native XDP for best performance
- **Batch Processing**: Event Sink batches writes
- **Connection Pooling**: Reuse database connections

---

## 📚 Technology Stack

- **Language**: Python 3.9+ (asyncio-based)
- **Kernel**: eBPF/XDP (C)
- **Web Framework**: FastAPI
- **BPF Toolkit**: BCC (BPF Compiler Collection)
- **Database**: PostgreSQL/SQLite
- **Streaming**: Kafka/Redis Streams
- **Metrics**: Prometheus
- **Testing**: pytest
- **Authentication**: JWT

---

## 🎯 Design Goals

1. **Performance**: Sub-microsecond kernel-level filtering
2. **Flexibility**: Multiple modes and configurations
3. **Observability**: Comprehensive metrics and logging
4. **Reliability**: Fail-safe modes and graceful degradation
5. **Security**: Defense in depth with multiple layers
6. **Maintainability**: Clean architecture and comprehensive testing
