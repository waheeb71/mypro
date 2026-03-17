# Enterprise NGFW - API Reference

## 🔐 Authentication

All authenticated endpoints require a JWT token in the Authorization header.

### Get JWT Token

**Endpoint**: `POST /api/v1/auth/token`

**Request**:
```json
{
  "username": "admin",
  "password": "your-password"
}
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

**Usage**:
```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/v1/status
```

---

## 📊 System Endpoints

### Get System Status

**Endpoint**: `GET /api/v1/status`  
**Auth**: Required  
**Rate Limit**: 30/minute

**Response**:
```json
{
  "status": "running",
  "version": "1.0.0",
  "uptime": 123.45,
  "mode": "transparent",
  "components": {
    "event_sink": "healthy",
    "decision_engine": "healthy",
    "xdp_engine": "healthy"
  }
}
```

### Get Statistics

**Endpoint**: `GET /api/v1/stats`  
**Auth**: Required  
**Rate Limit**: 30/minute

**Response**:
```json
{
  "total_connections": 12345,
  "blocked_connections": 234,
  "allowed_connections": 12111,
  "events_processed": 50000,
  "active_ttl_entries": {
    "BLOCK": 10,
    "RATE_LIMIT": 5,
    "QUARANTINE": 2
  },
  "xdp_stats": {
    "packets_processed": 1000000,
    "packets_dropped": 5000,
    "packets_passed": 995000
  }
}
```

---

## 🛡️ Policy & Rules

### List Rules

**Endpoint**: `GET /api/v1/rules`  
**Auth**: Required  
**Rate Limit**: 30/minute

**Query Parameters**:
- `page` (int, default: 1): Page number
- `limit` (int, default: 50): Items per page
- `enabled` (bool, optional): Filter by enabled status

**Response**:
```json
{
  "rules": [
    {
      "id": "rule-001",
      "name": "Block malicious network",
      "enabled": true,
      "priority": 100,
      "src_ip": "203.0.113.0/24",
      "dst_ip": "*",
      "dst_port": "*",
      "protocol": "*",
      "action": "block",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 15,
  "page": 1,
  "pages": 1
}
```

### Get Rule by ID

**Endpoint**: `GET /api/v1/rules/{rule_id}`  
**Auth**: Required

**Response**:
```json
{
  "id": "rule-001",
  "name": "Block malicious network",
  "description": "Blocks known malicious IP range",
  "enabled": true,
  "priority": 100,
  "src_ip": "203.0.113.0/24",
  "dst_ip": "*",
  "dst_port": "*",
  "protocol": "*",
  "action": "block",
  "schedule": null,
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

### Create Rule

**Endpoint**: `POST /api/v1/rules`  
**Auth**: Required (admin only)

**Request**:
```json
{
  "name": "Block SSH from external",
  "description": "Block SSH access from internet",
  "enabled": true,
  "priority": 90,
  "src_ip": "*",
  "dst_port": 22,
  "protocol": "tcp",
  "action": "block"
}
```

**Response** (201 Created):
```json
{
  "id": "rule-002",
  "name": "Block SSH from external",
  "message": "Rule created successfully"
}
```

### Update Rule

**Endpoint**: `PUT /api/v1/rules/{rule_id}`  
**Auth**: Required (admin only)

**Request**:
```json
{
  "enabled": false,
  "priority": 95
}
```

**Response** (200 OK):
```json
{
  "id": "rule-002",
  "message": "Rule updated successfully"
}
```

### Delete Rule

**Endpoint**: `DELETE /api/v1/rules/{rule_id}`  
**Auth**: Required (admin only)

**Response** (200 OK):
```json
{
  "message": "Rule deleted successfully"
}
```

---

## 🚫 Access Control

### Block IP

**Endpoint**: `POST /api/v1/control/block`  
**Auth**: Required (admin only)

**Request**:
```json
{
  "ip": "192.168.1.100",
  "ttl": 3600,
  "reason": "Suspicious activity detected"
}
```

**Response** (200 OK):
```json
{
  "status": "success",
  "action": "block",
  "ip": "192.168.1.100",
  "ttl": 3600,
  "expires_at": "2024-02-14T01:00:00Z",
  "message": "IP blocked successfully"
}
```

### Unblock IP

**Endpoint**: `DELETE /api/v1/control/block/{ip}`  
**Auth**: Required (admin only)

**Response** (200 OK):
```json
{
  "status": "success",
  "ip": "192.168.1.100",
  "message": "IP unblocked successfully"
}
```

### Apply Rate Limit

**Endpoint**: `POST /api/v1/control/rate-limit`  
**Auth**: Required (admin only)

**Request**:
```json
{
  "ip": "10.0.0.50",
  "rate": 100,
  "ttl": 3600,
  "reason": "API rate limit"
}
```

**Response** (200 OK):
```json
{
  "status": "success",
  "action": "rate_limit",
  "ip": "10.0.0.50",
  "rate": 100,
  "ttl": 3600,
  "expires_at": "2024-02-14T01:00:00Z"
}
```

### Quarantine IP

**Endpoint**: `POST /api/v1/control/quarantine`  
**Auth**: Required (admin only)

**Request**:
```json
{
  "ip": "172.16.0.100",
  "ttl": 7200,
  "reason": "Port scanning detected"
}
```

**Response** (200 OK):
```json
{
  "status": "success",
  "action": "quarantine",
  "ip": "172.16.0.100",
  "ttl": 7200,
  "expires_at": "2024-02-14T02:00:00Z"
}
```

### List Active Restrictions

**Endpoint**: `GET /api/v1/control/restrictions`  
**Auth**: Required

**Query Parameters**:
- `action` (string, optional): Filter by action (BLOCK, RATE_LIMIT, QUARANTINE)
- `ip` (string, optional): Filter by IP address

**Response**:
```json
{
  "restrictions": [
    {
      "ip": "192.168.1.100",
      "action": "BLOCK",
      "created_at": "2024-02-14T00:00:00Z",
      "expires_at": "2024-02-14T01:00:00Z",
      "time_remaining": 3456,
      "reason": "Suspicious activity"
    },
    {
      "ip": "10.0.0.50",
      "action": "RATE_LIMIT",
      "rate": 100,
      "created_at": "2024-02-14T00:30:00Z",
      "expires_at": "2024-02-14T01:30:00Z",
      "time_remaining": 5256,
      "reason": "API rate limit"
    }
  ],
  "total": 2
}
```

---

## 🔍 Monitoring & Health

### Basic Health Check

**Endpoint**: `GET /health`  
**Auth**: Not required

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-02-14T00:00:00Z"
}
```

### Liveness Probe

**Endpoint**: `GET /api/v1/health/liveness`  
**Auth**: Not required

**Response** (200 OK if alive):
```json
{
  "status": "alive"
}
```

### Readiness Probe

**Endpoint**: `GET /api/v1/health/readiness`  
**Auth**: Not required

**Response** (200 OK if ready):
```json
{
  "status": "ready",
  "components": {
    "event_sink": true,
    "decision_engine": true,
    "xdp_engine": true
  }
}
```

### Detailed Health Check

**Endpoint**: `GET /api/v1/health/detailed`  
**Auth**: Required  
**Rate Limit**: 10/minute

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-02-14T00:00:00Z",
  "uptime": 123.45,
  "components": {
    "event_sink": {
      "status": "healthy",
      "events_buffered": 42,
      "backends_healthy": 3
    },
    "decision_engine": {
      "status": "healthy",
      "total_decisions": 12345,
      "policy_mode": "balanced",
      "fail_mode": "fail_open"
    },
    "xdp_engine": {
      "status": "healthy",
      "mode": "native",
      "interface": "eth0",
      "packets_processed": 1000000
    },
    "ttl_manager": {
      "status": "healthy",
      "active_entries": {
        "BLOCK": 10,
        "RATE_LIMIT": 5,
        "QUARANTINE": 2
      }
    }
  }
}
```

### Prometheus Metrics

**Endpoint**: `GET /metrics`  
**Auth**: Not required

**Response**: Prometheus text format
```prometheus
# HELP ngfw_events_total Total number of events processed
# TYPE ngfw_events_total counter
ngfw_events_total{source_path="xdp",verdict="allow"} 12345.0
ngfw_events_total{source_path="normal",verdict="drop"} 234.0

# HELP ngfw_decisions_total Total number of decisions made
# TYPE ngfw_decisions_total counter
ngfw_decisions_total{action="block",source="policy"} 456.0
ngfw_decisions_total{action="rate_limit",source="ttl"} 89.0

# HELP ngfw_ttl_entries_active Number of active TTL entries
# TYPE ngfw_ttl_entries_active gauge
ngfw_ttl_entries_active{action_type="BLOCK"} 10.0
ngfw_ttl_entries_active{action_type="RATE_LIMIT"} 5.0
```

---

## 🎯 XDP Control

### Get XDP Status

**Endpoint**: `GET /api/v1/xdp/status`  
**Auth**: Required

**Response**:
```json
{
  "enabled": true,
  "mode": "native",
  "interface": "eth0",
  "stats": {
    "packets_processed": 1000000,
    "packets_dropped": 5000,
    "packets_passed": 995000,
    "drop_rate": 0.5
  }
}
```

### Switch XDP Mode

**Endpoint**: `POST /api/v1/xdp/mode`  
**Auth**: Required (admin only)

**Request**:
```json
{
  "mode": "generic",
  "interface": "eth0"
}
```

**Response** (200 OK):
```json
{
  "status": "success",
  "old_mode": "native",
  "new_mode": "generic",
  "message": "XDP mode switched successfully"
}
```

**Modes**:
- `native`: Native XDP (best performance)
- `generic`: Generic XDP (fallback)
- `offload`: XDP offload (NIC firmware)
- `disabled`: XDP disabled

---

## 📋 Events & Logs

### Query Events

**Endpoint**: `GET /api/v1/events`  
**Auth**: Required  
**Rate Limit**: 30/minute

**Query Parameters**:
- `start_time` (ISO 8601, optional): Start timestamp
- `end_time` (ISO 8601, optional): End timestamp
- `source_path` (string, optional): xdp, normal, hybrid
- `verdict` (string, optional): allow, drop, rate_limit, quarantine
- `src_ip` (string, optional): Source IP filter
- `dst_ip` (string, optional): Destination IP filter
- `limit` (int, default: 100): Max results

**Response**:
```json
{
  "events": [
    {
      "timestamp": "2024-02-14T00:00:00Z",
      "flow_id": "flow-12345",
      "src_ip": "192.168.1.100",
      "dst_ip": "8.8.8.8",
      "src_port": 45123,
      "dst_port": 443,
      "protocol": "tcp",
      "bytes": 4096,
      "packets": 20,
      "source_path": "normal",
      "verdict": "allow",
      "reason": "Policy allow"
    }
  ],
  "total": 1500,
  "returned": 100
}
```

---

## ⚙️ Configuration

### Get Configuration

**Endpoint**: `GET /api/v1/config`  
**Auth**: Required (admin only)

**Response**:
```json
{
  "general": {
    "mode": "transparent",
    "log_level": "info"
  },
  "decision_engine": {
    "policy_mode": "balanced",
    "fail_mode": "fail_open"
  },
  "event_sink": {
    "buffer_size": 1000,
    "flush_interval": 5
  }
}
```

### Update Configuration

**Endpoint**: `PATCH /api/v1/config`  
**Auth**: Required (admin only)

**Request**:
```json
{
  "decision_engine": {
    "policy_mode": "strict"
  }
}
```

**Response** (200 OK):
```json
{
  "status": "success",
  "message": "Configuration updated",
  "restart_required": false
}
```

---

## ⚠️ Error Responses

### Standard Error Format

```json
{
  "error": "Error description",
  "timestamp": "2024-02-14T00:00:00Z",
  "detail": "Additional error details"
}
```

### HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Missing or invalid authentication
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

---

## 🔢 Rate Limits

| Endpoint Pattern | Limit | Window |
|-----------------|-------|--------|
| `/api/v1/auth/*` | 5 | 1 minute |
| `/api/v1/status` | 30 | 1 minute |
| `/api/v1/rules` (GET) | 30 | 1 minute |
| `/api/v1/rules` (POST/PUT/DELETE) | 10 | 1 minute |
| `/api/v1/control/*` | 20 | 1 minute |
| `/api/v1/health/detailed` | 10 | 1 minute |
| `/api/v1/events` | 30 | 1 minute |

Rate limit headers returned in response:
- `X-RateLimit-Limit`: Requests allowed per window
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Timestamp when limit resets

---

## 📝 Examples

### Complete Workflow Example

```bash
#!/bin/bash

# 1. Authenticate
TOKEN=$(curl -X POST http://localhost:8080/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-password"}' \
  | jq -r '.access_token')

# 2. Check system status
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/status

# 3. Create a firewall rule
curl -X POST http://localhost:8080/api/v1/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block malicious subnet",
    "src_ip": "203.0.113.0/24",
    "action": "block",
    "enabled": true
  }'

# 4. Block a specific IP temporarily
curl -X POST http://localhost:8080/api/v1/control/block \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.200",
    "ttl": 3600,
    "reason": "Brute force attempt"
  }'

# 5. Query recent events
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/events?limit=10&verdict=drop"

# 6. Check Prometheus metrics
curl http://localhost:8080/metrics
```

---

## 🔗 WebSocket API (Future)

Coming soon: Real-time event streaming via WebSocket

**Endpoint**: `WS /api/v1/ws/events`

---

## 📚 Additional Resources

- [Architecture Documentation](ARCHITECTURE.md)
- [Deployment Guide](DEPLOYMENT.md)
- [README](../README.md)
