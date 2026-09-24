# Configuration reference

Every setting lives under **FlowSight › Settings** (module by module) and in `flowsight.json` under `modules.<name>`. The file holds only what you change; the defaults below apply otherwise. Settings marked *restart* take effect at the next service restart; everything else applies immediately.

The core keys `bind`, `port`, `api_token`, `data_dir` and `paths` can only be changed in the file, never through the API or the UI. Where an empty value means "platform default", the settings page shows the value actually in use beneath the field.

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

### egress (Business tier)

What is leaving the network right now, read from pf's live connection counters rather than from a log, so a transfer is visible while it is running.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `interval_seconds` | Sample the connection table every (seconds) | int | `5` | The difference between noticing data leaving and reading about it later. |
| `watch_groups` | Destination groups to watch | list | cloud-storage, file-transfer, code-host, webmail, messaging, ai, remote-access, tunnel, unknown | Groups not listed are still measured and shown; they just raise nothing on their own. |
| `alert_upload_mb` | Flag a single transfer above (MB sent) | int | `250` | Raised while the transfer is still running. |
| `alert_rate_mbps` | Flag a sustained upload rate above (Mbit/s) | int | `25` |  |
| `sustain_seconds` | ...held for at least (seconds) | int | `30` | Stops a brief burst raising anything. |
| `ratio_floor_mb` | Flag upload-dominant transfers above (MB sent) | int | `20` | Ordinary use pulls more than it pushes. |
| `ratio` | ...when sent exceeds received by a factor of | int | `4` |  |
| `flag_unnamed` | Flag uploads to a destination with no name | bool | `true` | No DNS answer, no server name, no reverse lookup. |
| `flag_first_use` | Flag the first time a device uses a watched group | bool | `true` |  |
| `quiet_hours` | Treat these hours as quiet | string | `""` | For example `23:00-06:00`. Anything flagged inside the window is raised one severity. |
| `min_report_kb` | Ignore connections smaller than (KB) | int | `64` |  |
| `keep_events` | Events kept in memory | int | `500` |  |

### enrich

Names and countries for bare addresses: reverse DNS and an IP geolocation database. Both off by default.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `reverse_dns` | Reverse DNS names | bool | `true` | Look up PTR records for addresses shown without a name, through the gateway's own resolver. Results are cached. |
| `geoip` | Location lookup | bool | `false` | Downloads a database (DB-IP Lite by default, refreshed monthly) into the data directory. |
| `geoip_detail` | How much detail | choice (country, city) | `"country"` | Country is a few megabytes. City is a much larger download (about 60 MB compressed) and adds the city, region and the coordinates a map needs. |
| `geoip_url` | Database URL | string | `""` | A MaxMind-format (.mmdb, optionally .gz) database. `{YYYY-MM}` is replaced by the current month. Empty: the DB-IP Lite file matching the detail level. |
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

### mitm (Business tier)

Deep inspection: the proxy hands each decrypted request and response over by ICAP on loopback, FlowSight reads it and answers "no modification". Bodies are previewed for the decoders that are switched on and never stored.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `active` | Inspect decrypted sessions | bool | `false` | Off: nothing is handed over and the proxy behaves as before. Only sessions a policy already decrypts ever arrive. |
| `all_clients` | Inspect everything that crosses the firewall | bool | `false` | On: every intercepted client is decrypted, not only those a policy names. A device that does not trust the FlowSight CA fails until the pinned-site detector relays that name untouched. Excluded hosts are never touched. |
| `port` | ICAP port (loopback) | int · restart | `1344` | Loopback only; nothing else can reach it. |
| `clients` | Limit to these clients | list | `[]` | Addresses or CIDRs. Empty: every client whose sessions are decrypted. |
| `names` | Limit to these names | list | `[]` | Server names, one per line. Empty: every decrypted name. |
| `record_headers` | Record request headers | bool | `true` | Cookies and authorization headers are recorded as their length only, never their value. |
| `decode_doh` | Decode DNS-over-HTTPS queries | bool | `true` | Reads the question out of a DoH request and files it in the DNS history. |
| `preview_bytes` | Body preview (bytes) | int | `4096` | How much of each body the proxy sends for decoding. Nothing is stored. |
| `keep_requests` | Recent requests kept in memory | int | `500` |  |

### paths (Pro tier)

Traces the route to destinations this network already contacts, and keeps what it finds.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `active` | Trace paths | bool | `false` | Off: nothing is traced. Nothing is ever probed that the network has not already contacted. |
| `per_run` | Destinations traced per run | int | `6` | A traceroute takes seconds; runs are five minutes apart. |
| `retrace_hours` | Trace a destination again after (hours) | int | `24` | How stale a route may get before it is measured again. |
| `max_destinations` | Destinations kept | int | `300` | Busiest first; the long tail is left alone. |
| `trace_ipv6` | Trace IPv6 destinations too | bool | `true` |  |
| `home` | Your location | string | `""` | Latitude and longitude, comma separated. The origin the map is drawn from, and the reference for checking a hop could really be where the database says. Empty: worked out from the gateway's public address. The Map page can fill it in from your browser. |

Needs `enrich` with `geoip_detail` set to `city`, since the country database carries no coordinates.

### policy

The declarative policy document, its compiler and continuous reconciliation onto every backend.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `enforce` | Enforce policy | bool | `true` | Off: the document is compiled and planned but never written to a backend. On: every provider is kept in step with it. |
| `reconcile_seconds` | Reconcile interval (s) | int | `60` |  |

### qos (Pro tier)

Traffic priority. Moves the bottleneck off the carrier and onto this firewall with dummynet, then shares the link by weight.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `active` | Shape traffic | bool | `false` | Off: nothing is queued and the link behaves exactly as it does now. On: every packet passes through a pipe on this firewall. |
| `download_mbit` | Download the link really carries (Mbit/s) | int | `0` | Measure it. Set above the real rate and the pipe never fills, the carrier stays the bottleneck and nothing else here has any effect. |
| `upload_mbit` | Upload the link really carries (Mbit/s) | int | `0` | The more important of the two: a saturated upload delays the acknowledgements downloads depend on. |
| `headroom_percent` | Keep back (percent) | int | `7` | How far under the measured rate the pipes are sized. |
| `lan_interface` | LAN interface | string | `""` | Where shaping is applied; addresses are untranslated here. Empty: detected from the local networks. |
| `default_class` | Class for everything not named | choice (high, normal, low) | `"normal"` |  |
| `weight_high` | Weight: high | int | `70` | Shares, not reservations. |
| `weight_normal` | Weight: normal | int | `25` |  |
| `weight_low` | Weight: low | int | `5` |  |
| `rules` | Rules | list | `[]` | One per line: `what = class`, optionally with a rate as a ceiling. See the Priority page in the user guide. |

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
| `probe_certificates` | Complete the inventory by asking | bool | `true` | The proxy log names a certificate but carries no dates. With this on, FlowSight opens one TLS connection per recently seen server name to read its certificate: expiry, key, signature, alternative names and whether the chain verifies. A name is asked at most once a day. |
| `probe_per_run` | Names asked per run | int | `25` |  |
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
| `auto_bypass_pinned` | Relay pinned sites without inspecting | bool | `true` | A client that pins its certificate refuses the inspection certificate and the site fails to load. With this on, FlowSight recognises that refusal and relays the name untouched from then on. No proxy can decrypt a pinned client. |
| `pinned_failures` | Refusals before a name counts as pinned | int | `3` |  |
| `pinned_window_minutes` | Refusal window (minutes) | int | `10` |  |
| `pinned_retest_hours` | Try inspecting a pinned name again after (hours) | int | `168` | 0 never retries. |

