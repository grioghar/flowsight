# Configuration reference

Every setting lives under **FlowSight › Settings** (module by module) and in `flowsight.json` under `modules.<name>`. The file holds only what you change; the defaults below apply otherwise. Settings marked *restart* take effect at the next service restart; everything else applies immediately.

The core keys `bind`, `port`, `api_token`, `data_dir` and `paths` can only be changed in the file, never through the API or the UI.

## Core (`flowsight.json`)

| Key | Default | Meaning |
|---|---|---|
| `site_name` | hostname | Shown in the UI header and in reports. |
| `bind` / `port` | `127.0.0.1` / `8080` | Where the API and UI listen. On OPNsense the GUI proxies to it; elsewhere put a reverse proxy in front or bind to a LAN address and rely on the token. |
| `api_token` | generated on Linux, empty on OPNsense | Required for writes from anything that is not the OPNsense GUI or loopback. |
| `data_dir` | `/var/db/flowsight` (OPNsense/FreeBSD), `/var/lib/flowsight` (Linux) | The SQLite store, caches, the country database and the TLS material. |
| `log_level` | `info` | `debug`, `info`, `warn`, `error`. |
| `memory_limit_mb` | `256` | Soft limit handed to the Go runtime; the daemon trims caches and collects earlier as it nears it. |
| `retention.*` | flows 7, dns 7, alerts 30, events 30, rollups 400, tls 30 days | Capped by the license tier (Community 7 days, Pro 90, Business 365) except rollups. |
| `paths.*` | per platform | Where the backends keep their files (Unbound config, squid binary, pf, Suricata EVE log, DHCP leases). |

## Modules

### alerting

Notification channels and alert rules.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `channels` | Notification channels | list | `[]` | Configured channels for sending notifications. |

### appcontrol

Application control: denied applications, identified by nDPI, are cut off at the firewall.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `kill_states` | Kill existing connections on a match | bool | `true` |  |
| `table_ttl_hours` | Forget blocked addresses after (hours) | int | `24` | Addresses of denied applications age out so a shared CDN address is not blocked forever. |

### categories

Web-content categories from open domain feeds, cached for policy and used to classify traffic.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `update_hours` | Refresh interval (h) | int | `24` |  |
| `classify` | Classify observed domains | bool | `true` | Keeps the lists in memory to tag flows and DNS with categories. Costs roughly 60 bytes per domain. |
| `classify_max` | Max domains held in memory | int | `3000000` |  |
| `disabled` | Disabled categories | list | `[]` |  |

### dns

Resolver visibility from Unbound's reply log and cache; per-group DNS blocking and safe search.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `log_path` | Resolver log | string | `""` | File that receives Unbound's log. Empty uses the platform default. |
| `manage_logging` | Enable reply logging in Unbound | bool | `true` | Writes a small include that turns on log-replies; without it there is nothing to read. |
| `cache_names_seconds` | Cache snapshot interval (s) | int | `60` |  |
| `max_zone_domains` | Max domains per policy zone | int | `1500000` | Each policy becomes one response policy zone; memory grows with its size. The compiler refuses larger ones. |

### enrich

Names and countries for bare addresses: reverse DNS and an IP geolocation database. Both off by default.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `reverse_dns` | Reverse DNS names | bool | `true` | Look up PTR records for addresses shown without a name, through the gateway's own resolver. Results are cached. |
| `geoip` | Country lookup | bool | `true` | Show the country of public addresses. Downloads a country database (DB-IP Lite by default, refreshed monthly) into the data directory. |
| `geoip_url` | Country database URL | string | `"https://download.db-ip.com/free/dbip-country-lite-{YYYY-MM}.mmdb.gz"` | A MaxMind-format (.mmdb, optionally .gz) country database. {YYYY-MM} is replaced by the current month. Empty: DB-IP Lite. |
| `cache_hours` | Name cache (hours) | int | `24` |  |

### enroll

Device identification and zone-based segmentation.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `enabled` | Enable device enrollment | bool | `true` |  |
| `captive_port` | Captive portal port | int | `8083` |  |
| `manage_dnsmasq_logging` | Enable dnsmasq DHCP logging | bool | `true` |  |
| `reconcile_seconds` | Reconcile interval (s) | int | `60` |  |

### firewall

FlowSight's own pf anchors: policy blocks, proxy redirects and dynamic address tables.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `log_blocks` | Log blocked packets to pflog | bool | `true` |  |

### identity

Names and MAC addresses for every host, from DHCP, ARP/NDP, DNS answers and the OUI registry.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `refresh_seconds` | Refresh interval (s) | int | `30` |  |
| `local_networks` | Local networks | list | `[]` | CIDRs considered local. Empty: derived from the firewall's own interfaces. |
| `extra_lease_files` | Extra lease files | list | `[]` |  |

### ids

Suricata alerts and TLS observations from the EVE log.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `eve_path` | EVE log path | string | `""` | Empty uses the platform default. |
| `poll_seconds` | Poll interval (s) | int | `5` |  |
| `tls_records` | Record TLS sessions and certificates | bool | `true` |  |

### license

Entitlements: Community, Pro and Business tiers, activated online or with a signed license file.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `server_url` | License server | string | `"http://192.168.1.245:8770"` | Used for online activation and lease refresh. Offline license files never contact it. |
| `check_hours` | Refresh interval (hours) | int | `24` |  |

### policy

The declarative policy document, its compiler and continuous reconciliation onto every backend.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `enforce` | Enforce policy | bool | `true` | Off: the document is compiled and planned but never written to a backend. On: every provider is kept in step with it. |
| `reconcile_seconds` | Reconcile interval (s) | int | `60` |  |

### reports

HTML reports and CSV exports with scheduling.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `schedules` | Report schedules | list | `[]` | Configured report schedules. |

### rulehygiene

Firewall ruleset analysis: shadowed, unused, redundant and overly permissive rules.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `analyse_minutes` | Analysis interval (minutes) | int | `15` |  |
| `min_evaluations_unused` | Min evaluations for unused detection | int | `1000` |  |
| `min_loaded_hours_unused` | Min loaded hours for unused detection | int | `24` |  |
| `wan_interfaces` | WAN interfaces (empty = auto-detect) | list | `[]` |  |
| `mgmt_ports` | Management ports (22, 80, 443) | list | `["22", "80", "443"]` |  |

### telemetry (Business tier)

Export metrics, events and alerts to an OpenTelemetry/HTTP endpoint (Grafana Mimir/Loki).

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `enabled` | Enabled | bool | `false` |  |
| `metrics_endpoint` | Metrics endpoint | string | `"http://127.0.0.1:4318/v1/metrics"` |  |
| `logs_endpoint` | Logs endpoint | string | `"http://127.0.0.1:4318/v1/logs"` |  |
| `interval_seconds` | Export interval (seconds) | int | `30` |  |
| `host_name` | Host name (default: hostname) | string | `""` |  |
| `headers` | HTTP headers (JSON map) | text | `{}` | Authentication headers, e.g. {"Authorization": "Bearer token"} |
| `events` | Also export events/alerts as log records | bool | `false` |  |

### tls

SSL transparency: the inspection CA, the certificate inventory and certificate findings.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `ca_name` | CA common name | string · restart | `"FlowSight Inspection CA"` |  |
| `ca_years` | CA validity (years) | int | `10` |  |
| `expiry_warn_days` | Warn on certificates expiring within (days) | int | `14` |  |

### ui

Interface preferences: colour theme.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `theme` | Theme | choice (auto, light, dark) | `"auto"` | auto follows the OPNsense theme when FlowSight is shown inside the OPNsense GUI (light, dark, or the GUI's own automatic mode), and the operating system preference otherwise. |

### updater

In-line self-update with manifest, signature and sha256 verification.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `enabled` | Enabled | bool | `true` |  |
| `channel` | Release channel | choice (stable, beta) | `"stable"` |  |
| `manifest_url` | Manifest URL | string | `"https://github.com/grioghar/flowsight/releases/latest/download/manifest.json"` |  |
| `check_hours` | Check interval (hours) | int | `6` |  |
| `auto_apply` | Apply updates automatically | bool | `false` |  |

### visibility

Flows, hosts, applications and throughput from ntopng/nDPI.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `ntopng_url` | ntopng URL | string | `""` | Empty uses the platform default. |
| `ntopng_user` | ntopng user | string | `"flowsight"` |  |
| `ntopng_password` | ntopng password | secret | `(secret)` |  |
| `ntopng_token` | ntopng API token | secret | `(secret)` | Preferred over a password when set. |
| `auto_account` | Create an ntopng account automatically | bool | `true` | When ntopng refuses the configured credentials, provision a 'flowsight' user through redis. |
| `redis_addr` | ntopng redis address | string | `"127.0.0.1:6379"` |  |
| `poll_seconds` | Poll interval (s) | int | `10` |  |
| `max_flows` | Flows per poll | int | `2000` |  |

### web

Transparent proxy: server names on every web session, inline blocking at the TLS handshake, optional inspection.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `intercept` | Intercept web traffic | bool | `true` | Redirect port 80 and 443 from the local networks through the proxy. Off: the proxy runs but sees nothing. |
| `networks` | Networks to intercept | list | `[]` | CIDRs. Empty: every local network. |
| `interfaces` | Interfaces | list | `[]` | pf interface names (vtnet0, igb1). Empty: any. |
| `http_port` | HTTP listener port | int | `3128` |  |
| `https_port` | HTTPS listener port | int | `3129` |  |
| `peek_server_cert` | Record server certificates without inspecting | bool | `false` | Peeks one step further into the handshake to log the server certificate, then splices. A few servers dislike it. |
| `ipv6_listener` | IPv6 listener address | string | `"fd99::1"` | An IPv6 address the firewall holds on the LAN (a unique local address as a virtual IP works well). Empty: IPv6 web traffic is not intercepted. |
| `block_page_port` | Block page port | int | `8082` |  |
| `workers` | Squid workers | int | `1` |  |

