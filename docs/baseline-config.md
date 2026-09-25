# Baseline Configuration

The Baseline module detects anomalies by learning what is normal for each device and then flagging deviations.

## Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `learning_days` | int | 7 | Number of days before anomaly detection begins for a device. During this learning period, no findings are raised. |
| `max_destinations` | int | 50 | Maximum number of destination addresses to track per device. When exceeded, the least frequently contacted destinations are pruned. |
| `bytes_multiplier` | float | 2.0 | Flag outbound bytes when they exceed this multiple of the device's daily median. |
| `beaconing_min_sessions` | int | 5 | Minimum number of sessions to a destination before checking for beaconing patterns. |
| `beaconing_cv_threshold` | float | 0.2 | Flag beaconing when inter-arrival times have a coefficient of variation below this. Lower values flag more regular (suspicious) patterns. |
| `dns_tunnel_min_length` | int | 20 | Flag DNS queries with mean label length at or above this (in characters). |
| `dns_tunnel_min_entropy` | float | 5.0 | Flag DNS queries with entropy at or above this (bits). |
| `dns_tunnel_min_rate` | float | 0.3 | Flag when NXDOMAIN rate (0-1) exceeds this and is far above the device's historical baseline. |
| `cooldown_minutes` | int | 60 | Deduplication window: suppress repeat findings for the same device and kind within this many minutes. |
| `excluded_zones` | list | [] | Device zones never to flag. E.g., `["guest", "untrusted"]`. |

## Detection Kinds

- **new_country**: First connection to a new country (outside the learning window).
- **new_port**: First connection to a port/protocol pair.
- **new_destination**: First connection to a destination (IPv4, IPv6, or domain).
- **beaconing**: Regularly timed connections to a destination with near-constant payload size.
- **dns_tunneling**: DNS queries with high entropy/label length and high NXDOMAIN rate.
- **bytes_anomaly**: Outbound bytes above the device's normal pattern.
- **night_activity**: Activity during hours the device has never shown activity before.

## Learning and Detection Phases

- **Learning phase** (default: 7 days): The module collects baseline data but does not raise findings.
- **Detection phase** (after learning): Anomalies are detected and findings are created.

Each device's learning period is independent, starting from its first sight.

## Profile Data Stored

For each device, the module stores:

- **Countries**: ISO 3166-1 country codes the device has contacted, with first/last seen and traffic counts.
- **Ports**: Unique protocol/port pairs with connection counts.
- **Destinations**: IP addresses and domains the device has contacted, with counts and bytes.
- **Activity**: Hourly and daily byte counts to detect time-of-day anomalies.
- **DNS**: Per-domain query statistics, including NXDOMAIN rates and label entropy.

## Integration with Alerting

When the alerting module is available, findings trigger alerts with rule keys like:

- `baseline.new_country`
- `baseline.new_port`
- `baseline.new_destination`
- `baseline.beaconing`
- `baseline.dns_tunneling`

Policy rules can filter by these keys to route alerts or suppress them by zone.
