# Baseline API

The Baseline module provides REST endpoints for querying anomalies, device profiles, and settings.

## GET /api/baseline/anomalies

Returns all open anomalies.

### Response

```json
{
  "anomalies": [
    {
      "id": 1,
      "ts": 1695312000,
      "device": "office-mac",
      "mac": "34:d2:70:98:9a:43",
      "kind": "new_country",
      "severity": "high",
      "title": "First connection to IE",
      "detail": "Device office-mac (34:d2:70:98:9a:43) first connected to IE. Known countries: US, CA",
      "acked": 0
    }
  ]
}
```

### Fields

- `id` (int): Finding ID.
- `ts` (int): Unix timestamp when the anomaly was first detected.
- `device` (string): Device name.
- `mac` (string): MAC address.
- `kind` (string): Type of anomaly (new_country, new_port, beaconing, etc.).
- `severity` (string): critical, high, medium, low.
- `title` (string): Short description.
- `detail` (string): Full context including the baseline.
- `acked` (int): 1 if acknowledged, 0 if open.

---

## GET /api/baseline/profile

Returns the baseline profile for a device (by IP or MAC).

### Query Parameters

- `ip` (string, optional): IPv4 or IPv6 address to look up.
- `mac` (string, optional): MAC address to look up.

Must specify one of `ip` or `mac`.

### Response

```json
{
  "profile": {
    "mac": "34:d2:70:98:9a:43",
    "first_seen": 1694707200,
    "countries": {
      "US": {
        "first_seen": 1694707200,
        "last_seen": 1695312000,
        "count": 124,
        "bytes": 5240000
      },
      "CA": {
        "first_seen": 1694966400,
        "last_seen": 1695225600,
        "count": 18,
        "bytes": 480000
      }
    },
    "ports": {
      "tcp:443": {
        "first_seen": 1694707200,
        "last_seen": 1695312000,
        "count": 89,
        "bytes": 4150000
      },
      "udp:53": {
        "first_seen": 1694707200,
        "last_seen": 1695312000,
        "count": 1240,
        "bytes": 42000
      }
    },
    "destinations": {
      "8.8.8.8": {
        "first_seen": 1694707200,
        "last_seen": 1695312000,
        "count": 302,
        "bytes": 18000
      }
    }
  }
}
```

### Fields

- `mac` (string): MAC address.
- `first_seen` (int): Unix timestamp when the device was first seen.
- `countries` (object): Map of country code to country record.
  - `first_seen`, `last_seen` (int): Unix timestamps.
  - `count` (int): Number of flows.
  - `bytes` (int): Total bytes sent to this country.
- `ports` (object): Map of "proto:port" to port record (same fields as countries).
- `destinations` (object): Map of IP/domain to destination record.

---

## POST /api/baseline/ack

Acknowledges (marks as reviewed) an open anomaly.

### Request Body

```json
{
  "id": 1
}
```

### Parameters

- `id` (int): Finding ID to acknowledge.

### Response

```json
{
  "ok": true
}
```

---

## GET /api/baseline/status

Returns module status and active settings.

### Response

```json
{
  "devices": 42,
  "settings": {
    "learning_days": 7,
    "max_destinations": 50,
    "bytes_multiplier": 2.0,
    "beaconing_min_sessions": 5,
    "beaconing_cv_threshold": 0.2,
    "dns_tunnel_min_length": 20,
    "dns_tunnel_min_entropy": 5.0,
    "dns_tunnel_min_rate": 0.3,
    "cooldown_minutes": 60,
    "excluded_zones": ["guest"]
  }
}
```

### Fields

- `devices` (int): Number of devices with active profiles.
- `settings` (object): Current module configuration.

---

## Error Responses

All endpoints return errors as JSON:

```json
{
  "error": "unknown device"
}
```

Common codes:

- 400: Bad request (missing required parameter).
- 404: Not found (device unknown).
- 500: Server error (database, internal).
