# Configuration reference

Every setting lives under **FlowSight › Settings** (module by module) and in `flowsight.json` under `modules.<name>`. The file holds only what you change; the defaults below apply otherwise. Settings marked *restart* take effect at the next service restart; everything else applies immediately.

The core keys `bind`, `port`, `api_token`, `data_dir` and `paths` can only be changed in the file, never through the API or the UI. Where an empty value means "platform default", the settings page shows the value actually in use beneath the field. With a token set, bind the daemon to `0.0.0.0` (the OPNsense WAN rules still block it from outside) and the OPNsense page reads the token from `flowsight.json` and presents it on every proxied request, so the GUI keeps working while LAN clients must send `X-Flowsight-Token`.

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

Stateful Packet Inspection: the proxy hands each decrypted request and response over by ICAP on loopback, FlowSight reads it and answers "no modification". Bodies are previewed for the decoders that are switched on and never stored.

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
| `cables` | Show submarine cables | bool | `false` | Fetches TeleGeography's public cable map (about a megabyte, refreshed monthly) and draws it behind the routes. Not bundled: their data is a free public resource but is not openly licensed. |
| `cable_near_km` | A cable serves a place within (km) | int | `400` | How close a cable must pass to count as a candidate. Deliberately loose. |
| `origin_slack_km` | Your own position could be wrong by (km) | int | `100` | Every distance is measured from your origin, and unless you declared it that came from the address database. A placement is only called impossible if it misses its floor by more than this; it only ever withdraws accusations. A declared origin gets no allowance. |
| `land_detour_pct` | Fibre on land runs longer than the crow flies by (%) | int | `35` | Decides the second of the two thresholds each hop is judged against: not what light forbids, but what a built route could manage. Zero turns that category off. |
| `hop_delay_us` | Each hop adds (microseconds) | int | `200` | A router must finish receiving a packet before it starts sending it on. Small individually; over twenty hops worth counting. |
| `terrestrial` | Use published land-route maps | bool | `false` | Downloads open maps of long-haul fibre on land and measures along them where they reach. Never raises the impossible threshold: over water a cable is the only way across, on land a straight line is merely unbuilt. Refreshed monthly. |
| `terrestrial_urls` | Land-route sources | text | *(AfTerFibre)* | One GeoJSON URL per line, replacing the defaults. `#` and `//` comment a line out. |
| `ai_provider` | Ask a language model about hops nothing else can place | choice | `off` | off, anthropic, openai, google, azure, ollama, custom. Setup for each is in the field's help. |
| `ai_endpoint` | Endpoint | string | *(provider default)* | Required for azure and custom. |
| `ai_model` | Model | string | *(provider default)* | claude-haiku-4-5, gpt-4o-mini, gemini-2.0-flash, llama3.1 by default. |
| `ai_key` | API key | secret | *(empty)* | Sent only to the endpoint. |
| `ai_per_hour` | Questions per hour | int | `20` | Each hop at most once a month; this caps new questions. |
| `fcc_username` | FCC broadband map username | string | *(empty)* | National Broadband Map account username (free at broadbandmap.fcc.gov). |
| `fcc_token` | FCC API token | secret | *(empty)* | Sent as `hash_value` header to broadbandmap.fcc.gov only. With both fields set, FlowSight checks in monthly for the current release, records the file catalogue, and keeps the national fixed and mobile broadband provider summaries plus the origin state's census-place summary of who serves where and with what technology. Per-location files are skipped to stay under the gateway's memory limit. |
| `shodan_key` | Shodan API key | secret | *(empty)* | Optional; without it InternetDB (free) is used. Sent only to api.shodan.io. |
| `shodan_mode` | Look hops up on Shodan | choice | `click` | off, click (the card's button), all (every hop, twenty per five-minute run; spends credits when a key is set). |
| `abuseipdb_key` | AbuseIPDB API key | secret | *(empty)* | Enables reputation lookups for route hops: abuse confidence, reports, ISP, usage type. Twenty addresses per five-minute run, answers kept a week. Free key: abuseipdb.com › Account › API › Create Key. |
| `geofeeds` | Follow geofeeds named in the registry | bool | `true` | RFC 8805 files named in registry objects of hops on routes are fetched weekly and used like provider range lists. |
| `anycast_census` | Know which addresses are anycast | bool | `true` | LACeS census prefixes and sites, fetched weekly; anycast hops are placed at the site nearest the hop before them and labelled as regional instances. |
| `identify` | Ask anycast servers to identify themselves | bool | `true` | CHAOS TXT `id.server` / `hostname.bind` to anycast hops, twenty per five-minute run, kept a week; root-servers.org site lists fetched weekly to look the answers up. |
| `provider_feeds` | Use the clouds' published address ranges | bool | `true` | AWS, Google Cloud, Azure, Oracle, DigitalOcean, Linode regional ranges and Cloudflare/Fastly anycast ranges, one feed per half-hour run until all are under a week old, throttled to 2 MB/s; the operator's own statement outranks the database and a measurement; anycast positions are set aside. |
| `azure_service_tags_url` | Azure service tags file | string | *(discovered weekly)* | Only if the link cannot be found on Microsoft's download page. |
| `osm_telecom` | Use OpenStreetMap telecom lines (low weight) | bool | `true` | Overpass-fetched telecom/communication lines, one ten-degree tile every twenty minutes while any are outstanding (a few hundred tiles; the first pass takes about five days), kept a month, counted at half weight in the expected time only. |
| `osm_overpass_url` | Overpass API | string | *(overpass-api.de)* | Your own Overpass instance, if you run one. |
| `osm_overpass_local` | My Overpass is on this network | bool | `false` | Allows the Overpass API URL to be a private address; the only exemption from the public-host rule. | With a private server FlowSight fetches up to twelve regions per run and falls back to the public service for any region the private server has no data for.
| `learn_corrections` | Remember what the database gets wrong | bool | `true` | A router name or RIPE measurement that places a hop over 500 km from the database's position teaches the map where that announced prefix is; a registrant coordinate contradicted twice for one network is set aside. Listed at `/api/paths/corrections`; items can be forgotten. |
| `ipmap` | Ask RIPE where each router is | bool | `true` | RIPE's IPmap publishes positions worked out by measuring addresses from thousands of probes. The one source here that is measurement rather than paperwork; it outranks the address database. Asked slowly, kept a month, backs off on refusal. |
| `ipmap_per_minute` | Addresses asked about per minute | int | `20` | Deliberately small: answers last a month and the service belongs to somebody else. |
| `registry` | Look up who runs each hop | bool | `true` | Asks the public routing table which network announces a hop's address, and the regional registry who that block is allocated to. The registry's postal address is a head office, not the room the router is in, and is labelled that way wherever it is shown. Cached for a month. |
| `facilities` | List buildings the operator occupies | bool | `true` | Adds street addresses from PeeringDB, where operators publish which data centres they are in. Narrowed to a hop only when the router's own hostname gave away its city; otherwise presented as the unrelated list it is. |
| `cables_url` | Cable map URL | string | `""` | Empty: TeleGeography's published map. |
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

Flexible report generation with 15+ sections, multi-format output, and scheduling.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `definitions` | Report definitions | list | Built-ins | Custom report templates; built-in definitions are read-only. |
| `keep_runs` | Keep last N runs per definition | number | `10` | Retention per definition; 0 = unlimited. |
| `max_total_mb` | Max total storage (MB) | number | `500` | Global limit for all stored runs; oldest pruned first. |

Reports are stored under `<DataDir>/reports/<definition>/<run>.<format>` with metadata indexed in KV. Scheduled delivery through alerting channels requires the alerting module.

### rulehygiene

Firewall ruleset analysis: shadowed, unused, redundant and overly permissive rules.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `analyse_minutes` | Analysis interval (minutes) | int | `15` |  |
| `min_evaluations_unused` | Min evaluations for unused detection | int | `1000` |  |
| `min_loaded_hours_unused` | Min loaded hours for unused detection | int | `24` |  |
| `wan_interfaces` | WAN interfaces (empty = auto-detect) | list | `[]` |  |
| `mgmt_ports` | Management ports (22, 80, 443) | list | `["22", "80", "443"]` |  |

### space (Pro tier)

Physical space mapping and device placement visualization.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `address` | Address | string | `""` | Your physical address for geocoding (US Census Geocoder). |
| `lat` | Latitude | float | `0.0` | Cached latitude from geocoding. |
| `lon` | Longitude | float | `0.0` | Cached longitude from geocoding. |
| `floor_height_m` | Default floor ceiling height (m) | float | `2.6` | Default height for new rooms. |
| `units` | Measurement units | string | `"metric"` | `"metric"` for metres, `"imperial"` for feet. |

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


### scan

Active network scanning for local devices: ICMP, TCP/UDP probes, service detection, OS fingerprinting. Restricted to locally-known networks; off by default. Optional nmap enhancement when installed.

| Key | Setting | Type | Default | Notes |
|---|---|---|---|---|
| `scanning` | Allow active scanning | bool | `false` | Master switch. Off: all scans are refused. |
| `max_parallel_hosts` | Max parallel hosts | int | `2` | Job queue limit. |
| `max_parallel_ports` | Max parallel ports per host | int | `64` | TCP connect limit per target. |
| `port_set` | Port set | string | `"top100"` | `top100`, `top1000`, or `custom`. |
| `custom_ports` | Custom ports | string | `""` | Comma-separated list (e.g. `"22,80,443,3389"`). Used if `port_set` is `custom`. |
| `os_probe` | Probe for OS fingerprints | bool | `true` | TTL, mDNS, SSDP, SNMP, NetBIOS heuristics; nmap OS detection when installed. |
| `use_nmap` | Use nmap when installed | bool | `true` | Run nmap (if available) to enhance port service versions and OS accuracy. |
| `sweep_every_hours` | Sweep interval | int | `0` | 0: disabled. >0: scan all devices seen in the last 7 days every N hours. |
| `sweep_window` | Sweep time window | string | `""` | Optional UTC time window, e.g. `"02:00-05:00"`. Sweeps only run inside it. |
| `rate_limit_pps` | Rate limit (packets/sec) | int | `200` | ICMP and UDP probe rate; TCP respects connection limits. |

### Proxmox

The Proxmox module maps Proxmox VE cluster inventory into FlowSight: nodes, QEMU VMs, and LXC containers with their network addresses, OS information, and optional guest agent data. It enriches FlowSight's host database and optionally writes notes to guest descriptions.

**Settings**

| Key | Type | Default | Purpose |
|-----|------|---------|---------|
| `hosts` | list | empty | One or more Proxmox node URLs, e.g. `https://pve.local:8006`. Leave empty to disable. |
| `token_id` | string | empty | API token ID: `user@realm!tokenname`, e.g. `flowsight@pve!flowsight`. |
| `token_secret` | secret | empty | The API token secret. |
| `fingerprint` | string | empty | TLS certificate SHA-256 fingerprint pin (colon-separated hex), e.g. `4C:9E:F6:8A:...` |
| `verify_tls` | bool | false | When on, verify TLS with system CA roots. When off, use fingerprint pinning. |
| `poll_minutes` | int | 5 | Poll interval in minutes. |
| `write_notes` | bool | false | Write FlowSight notes blocks to guest descriptions (opt-in). |
| `notes_targets` | string | guests | Scope: `guests` or `guests+nodes`. |
| `exclude_vmids` | list | empty | VMID list to skip during polling. |
| `name_guests` | bool | true | Use guest names when no DHCP lease hostname. |
| `gateway_url` | string | | FlowSight URL used only to build the link back to the host page inside each guest's Notes. |
| `probe_sockets` | bool | false | For running QEMU guests with agent: query socket connections via `ss`. Requires VM.Monitor privilege. |

**Least-Privilege Token Setup**

Create a token with minimal privileges:

```bash
pveum role add FlowSight -privs "VM.Audit VM.Config.Options Sys.Audit Datastore.Audit VM.GuestAgent.Audit"
pveum user add flowsight@pve
pveum user token add flowsight@pve flowsight --privsep 0
pveum acl modify / --users flowsight@pve --roles FlowSight
```

Privileges:
- `VM.Audit`: query guests, config, status, agent info
- `VM.Config.Options`: write guest descriptions (notes only)
- `Sys.Audit`: read node status and version

**TLS Fingerprint**

Read from your Proxmox node:

```bash
pvenode cert info | grep Fingerprint
# or remotely
openssl s_client -connect pve.local:8006 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

Enter with colons (case-insensitive). Verification is automatic when `verify_tls` is off.
