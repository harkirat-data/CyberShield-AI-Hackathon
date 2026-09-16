# VALENS REST & WebSocket Telemetry API Reference

## Base URL
- **Local Dev**: `http://127.0.0.1:8050`
- **Prototype Port**: `http://127.0.0.1:8090`
- **WebSocket Route**: `ws://127.0.0.1:8050/ws`

---

## 1. System Health & Sensor Status

### `GET /api/v1/health`
Retrieves cluster telemetry status, listener health, and active honeypot counts.

**Response:**
```json
{
  "status": "healthy",
  "active_decoys": 12,
  "listeners": {
    "http": 8050,
    "ssh": 2222,
    "mysql": 3306,
    "waf": 8080
  },
  "ai_agent_status": "ONLINE",
  "timestamp": "2026-09-16T10:35:15Z"
}
```

---

## 2. Telemetry Event Stream

### `GET /api/v1/telemetry/events`
Returns recent honeypot intrusion triggers and forensic logs.

**Query Parameters:**
- `limit` *(optional, default: 50)*: Number of events to retrieve.
- `severity` *(optional)*: Filter by `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.

**Response:**
```json
[
  {
    "id": "evt-7718",
    "timestamp": "2026-09-16T10:30:00Z",
    "source_ip": "198.51.100.12",
    "target_port": 3306,
    "protocol": "MySQL",
    "threat_score": 88,
    "quarantined": true
  }
]
```

---

## 3. Quarantine Management

### `POST /api/v1/quarantine/block`
Dispatches an immediate IP quarantine rule to the WAF edge reverse proxy.

**Request Body:**
```json
{
  "ip_address": "198.51.100.12",
  "reason": "Repeated unauthorized MySQL decoy probe",
  "duration_seconds": 86400
}
```

**Response:**
```json
{
  "success": true,
  "action": "IP_QUARANTINED",
  "rule_id": "waf-rule-9921",
  "enforced_at": "2026-09-16T10:35:15Z"
}
```
