# API reference

FlowSight is driven entirely through a JSON HTTP API; the UI uses nothing else. On OPNsense the GUI page proxies it at `/flowsight.php?api=<path>` with the session's CSRF token; on other systems it listens at `http://127.0.0.1:8080` by default.

## API Explorer

An interactive OpenAPI explorer is built into FlowSight at the **API** page under Administration. It provides:
- Grouped operations by area (Monitor, Inventory, Protect, Administration)
- Parameter and request body templates
- Live request/response with timing
- Copy as curl for easy CLI testing

Download the full OpenAPI 3.0 specification at `GET /api/openapi.json` for use with Swagger UI, Insomnia, Postman, or other tools.

## Conventions

- Every write (POST) needs the header `X-Requested-With: Flowsight`. From anything that is not the OPNsense GUI or loopback, also send the API token in `X-Flowsight-Token` (or sign in once at `POST /api/login` with `{"token": …}` to get a session cookie).
- Responses are JSON objects. Errors are `{"error": "message"}` with a matching status: 400 invalid input, 402 the feature needs a higher license tier or the license has expired (`locked` or `expired` is set, with `feature` and `required`), 403 forbidden (missing header, read-only instance, locked key), 404 unknown route, 500 a backend failed.
- Time windows take `hours` (default 24). Lists take `limit`.
- The machine-readable description is at `GET /api/openapi.json`.
- Every write is recorded in the audit log (`GET /api/system/audit`) with the user and client address.

## Routes

### 

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/captive` | Serve the captive portal page for device enrollment and policy acceptance | none |
| POST | `/captive` | Handle captive portal form submission for device enrollment or policy acceptance | none |

### alerting

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/alerting/channel-types` | List all notification channel types grouped by family, with configuration schemas | none |
| GET | `/api/alerting/channels` | List all configured notification channels | none |

**Create operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/alerting/channels` | Create a new notification channel | none |
| POST | `/api/alerting/rules` | Create a new alert rule that evaluates conditions and sends notifications | none |

**Update operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| PUT | `/api/alerting/channels/{id}` | Update a notification channel | id, id |
| PUT | `/api/alerting/rules/{id}` | Update an existing alert rule with new conditions and settings | id |

**Delete operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| DELETE | `/api/alerting/channels/{id}` | Delete a notification channel | id, id |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/alerting/ack/{alert_key}` | Acknowledge an active alert | id, alert_key |
| GET | `/api/alerting/channels/{id}` | Get a specific notification channel | id, id |
| POST | `/api/alerting/channels/{id}/test` | Send a test message to a channel | id, id |
| GET | `/api/alerting/deliveries` | Get notification delivery history | channel, limit |
| GET | `/api/alerting/feed.xml` | RSS feed of recent alerts with token-based authorization | none |
| POST | `/api/alerting/import-apprise` | Import Apprise notification URL | none |
| GET | `/api/alerting/maintenance` | Get current maintenance mode status | none |
| POST | `/api/alerting/maintenance` | Enable or disable maintenance mode (suppresses alerts) | none |
| GET | `/api/alerting/notifications` | Retrieve recent notification delivery history with optional limit | limit |
| POST | `/api/alerting/resolve/{alert_key}` | Resolve an acknowledged alert | id, alert_key |
| GET | `/api/alerting/rules` | Retrieve all configured alert rules with their conditions and channels | none |
| DELETE | `/api/alerting/rules/{id}` | Remove an alert rule permanently from the system | id |
| GET | `/api/alerting/rules/{id}` | Retrieve details of a specific alert rule by ID | id |
| POST | `/api/alerting/simulate` | Generate a test alert to verify rules | none |
| GET | `/api/alerting/status` | Query status of all channels and recent notification delivery events | none |

### appcontrol

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/appcontrol/blocked` | List recent application blocks with timestamps and details | hours, limit |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/appcontrol/status` | Retrieve active application control rules with current block counts and enforcement status | none |

### dns

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/dns/log` | Historical DNS query log with optional filtering by domain or client | client, domain, blocked, limit |
| GET | `/api/dns/lookup` | Retrieve hostname assignments given to a specific IP address | ip |
| GET | `/api/dns/summary` | Query summary with volumes, block rates, top domains, clients and lists | hours, limit |
| GET | `/api/dns/timeseries` | Time series of DNS queries and blocks with automatic step adjustment | hours |

### egress

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/egress/events` | Connection lifecycle events from the firewall connection table | limit |
| GET | `/api/egress/live` | Show live connections carrying data with rates and traffic totals by device | group, min_kb |
| POST | `/api/egress/stop` | Terminate an active outbound transfer connection at the firewall gateway | none |
| GET | `/api/egress/summary` | Total outbound traffic aggregated by device and destination group | none |

### enrich

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/enrich/countries` | List all countries available in the GeoIP database for location lookups | none |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/enrich/lookup` | Batch lookup of DNS names and geolocation countries for IP addresses; unknown names are cached | none |
| GET | `/api/enrich/status` | Query what enrichment is enabled, cache size, and database state | none |

### enroll

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/enroll/devices` | List all enrolled devices with optional filtering by zone or name search | zone, q |
| GET | `/api/enroll/services` | List applications used and ports offered by each device, keyed by MAC address | hours |

**Create operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/enroll/zones` | Create or replace all enrollment zones with new rules and classification | none |

**Update operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| PUT | `/api/enroll/zones/{id}` | Update a specific enrollment zone by its ID with new rules or settings | id |

**Delete operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| DELETE | `/api/enroll/zones/{id}` | Delete an enrollment zone by its ID and reassign devices to unclassified | id |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/enroll` | Retrieve current enrollment status including device counts by zone and unidentified devices | none |
| POST | `/api/enroll/apply` | Apply the enrollment plan to enforce zone assignments on all devices | none |
| POST | `/api/enroll/assign` | Assign a device to a specific zone or unpin it for automatic rule-based classification | none |
| DELETE | `/api/enroll/devices/{mac}` | Remove a device from the enrollment list and forget its identification | mac |
| GET | `/api/enroll/devices/{mac}` | Retrieve detailed information about a specific device by its MAC address | mac |
| POST | `/api/enroll/mode` | Set enrollment mode between monitor and enforce for device assignment | none |
| GET | `/api/enroll/plan` | Preview what changes apply would make to device enrollment assignments | none |
| POST | `/api/enroll/reconcile` | Trigger re-evaluation of device classification against current rules | none |
| GET | `/api/enroll/rules` | Retrieve all device classification rules used in zone assignment | none |
| POST | `/api/enroll/rules` | Replace all device classification rules used for zone assignment | none |
| GET | `/api/enroll/zones` | Retrieve all enrollment zones with their rules and captive portal settings | none |
| GET | `/api/enroll/zones/{id}` | Retrieve a specific enrollment zone by its ID with detailed configuration | id |

### identity

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/identity/hosts` | List all known hosts with their names, MAC addresses, vendors and last activity time | hours, all |
| GET | `/api/identity/leases` | List all current DHCP leases issued by the gateway DHCP server | none |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/identity/lookup` | Lookup details for a specific IP address including MAC, vendor and display name | ip |
| POST | `/api/identity/name` | Assign or update a custom display name for a network device by IP address | none |
| DELETE | `/api/identity/name/{ip}` | Remove a custom name override and revert to automatic identification for a device | ip |

### ids

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/ids/alerts` | List recent IDS alerts with filtering by severity, IP address and acknowledgment status | hours, severity, ip, unacked, limit |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/ids/alerts/ack` | Acknowledge one or multiple IDS alerts to mark them as reviewed | none |
| GET | `/api/ids/summary` | Get summary of IDS alerts grouped by severity, category, signature and source host | hours |

### license

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/license/features` | List all features with enabled status and limits by tier | none |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/license` | Retrieve current license tier, key, limits, and refresh status | none |
| POST | `/api/license/activate` | Activate an activation key or license code through the online license server | none |
| POST | `/api/license/install` | Install a signed offline license file for air-gapped deployments | none |
| POST | `/api/license/refresh` | Refresh online license lease status with the license server immediately | none |
| POST | `/api/license/remove` | Remove current license and revert to Community tier after notifying server | none |

### mitm

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/mitm/requests` | Retrieve recent decrypted HTTPS requests with headers, methods and hostnames | limit, q |
| GET | `/api/mitm/status` | Check if deep packet inspection is listening and retrieve decoded traffic statistics | none |

### paths

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/paths/corrections` | List corrections to address geolocation and IP prefix data learned from traffic analysis | none |
| GET | `/api/paths/destinations` | List all destinations with measured routes and associated traffic metrics | hours, limit |
| GET | `/api/paths/devices` | List all devices with measured network paths and their trace status | none |
| GET | `/api/paths/fcc/files` | List files from the FCC broadband deployment release with optional filtering | filter, limit |
| GET | `/api/paths/geofeeds` | List RFC 8805 geofeeds discovered in WHOIS registry objects with their fetch state | none |
| GET | `/api/paths/talkers` | List all devices and their applications that have traffic to a specific destination | dst, hours |
| GET | `/api/paths/who` | List all devices whose traffic reached any of the given destination IP addresses | dsts, hours |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/paths/cables` | Submarine cable map simplified for display with optional detail level | detail |
| POST | `/api/paths/corrections/forget` | Forget a learned correction to revert to database values | none |
| POST | `/api/paths/fcc/check` | Test FCC broadband map credentials and record the current available release | none |
| POST | `/api/paths/fcc/pull` | Trigger monthly FCC broadband map data pull and update local database | none |
| GET | `/api/paths/fcc/summary` | Summarize fixed-broadband providers and census places from the FCC broadband map | full |
| GET | `/api/paths/graph` | Complete network graph as nodes and edges with location, latency and traffic data | device, country, max_latency, max_hops, hours |
| GET | `/api/paths/home` | Get the current map origin point and its detected or configured geolocation | none |
| POST | `/api/paths/home` | Set the map origin to a specific location or clear for automatic geolocation | none |
| GET | `/api/paths/path` | Retrieve complete hop-by-hop path to a destination with geolocation and latency data | dst, device, hours |
| GET | `/api/paths/shodan` | Retrieve Shodan/InternetDB data for a network hop including services and vulnerabilities | ip, now |
| GET | `/api/paths/status` | Get current tracing status including destination count and last trace time | none |

### pihole

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/pihole/pull` | Pull from every server now | none |
| GET | `/api/pihole/status` | Retrieve Pi-hole server status with pull history and error details | none |

### policy

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/policy/capabilities` | List all registered providers, their capabilities, and what policies require | none |
| GET | `/api/policy/groups` | List all device groups defined in the policy with their member counts | none |
| GET | `/api/policy/schedules` | List all schedules defined in the policy with their time windows and rules | none |

**Create operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/policy/group` | Create a new device group or update an existing one with member definitions | none |
| POST | `/api/policy/policy` | Create a new policy or update an existing one with validation and compilation | none |
| POST | `/api/policy/schedule` | Create a new schedule or update an existing one for policy time-based enforcement | none |

**Update operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| PUT | `/api/policy/groups/{name}` | Update an existing device group with new member definitions and properties | name |
| PUT | `/api/policy/schedules/{name}` | Update an existing schedule with new time windows and day-of-week rules | name |

**Delete operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/policy/group/delete` | Delete a device group from the policy document with validation against usage | none |
| DELETE | `/api/policy/groups/{name}` | Delete a device group via REST DELETE method with validation against usage | name |
| POST | `/api/policy/policy/delete` | Delete a policy from the document by name with validation and recompilation | none |
| POST | `/api/policy/schedule/delete` | Delete a schedule from the policy document with validation against policy usage | none |
| DELETE | `/api/policy/schedules/{name}` | Delete a schedule via REST DELETE method with validation against policy usage | name |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/policy` | Retrieve the current policy document, its compilation status, plan, and enforcement state | none |
| POST | `/api/policy` | Replace the entire policy document after validation and preview compilation | none |
| POST | `/api/policy/apply` | Apply the current plan immediately to all providers (requires enforcement to be enabled) | none |
| POST | `/api/policy/exclusions` | Replace the device exclusions list and global policy enforcement options | none |
| GET | `/api/policy/export` | Export the entire policy document in YAML format for version control or sharing | none |
| GET | `/api/policy/groups/{name}` | Retrieve a specific device group definition with its member list and tags | name |
| POST | `/api/policy/import` | Replace the policy document from YAML or JSON text with validation and compilation | none |
| GET | `/api/policy/matches` | Analyze which devices and far-ends match a specific policy rule, with session details and firewall log records | name, hours |
| GET | `/api/policy/plan` | Compile the policy onto every registered provider and show what would change without applying | none |
| POST | `/api/policy/policy/move` | Reorder policies in the document list for evaluation priority and display order | none |
| GET | `/api/policy/schedules/{name}` | Retrieve a specific schedule definition with its time windows and active days | name |

### proxmox

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/proxmox/inventory` | List all Proxmox nodes and virtual machines with their status and configuration | none |

**Update operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/proxmox/notes/write` | Update the notes section for a Proxmox guest with new content and formatting | none |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/proxmox/guest` | Retrieve detailed configuration and status for a specific virtual machine or container | vmid, node |
| GET | `/api/proxmox/map` | Show network dependencies and traffic patterns between guests and external destinations | hours |
| GET | `/api/proxmox/notes/preview` | Preview the formatted notes section for a guest container or virtual machine | vmid, node |
| POST | `/api/proxmox/poll` | Trigger an immediate poll of Proxmox API for latest node and VM status | none |
| GET | `/api/proxmox/requirements` | Analyze a guest's resource requirements based on historical usage patterns and current load | vmid, node, hours |
| GET | `/api/proxmox/status` | Check Proxmox connection status and display timestamp of last successful poll | none |

### qos

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/qos/rules` | List all configured traffic shaping rules with their criteria and priority order | none |

**Create operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/qos/rules` | Create a new traffic shaping rule to prioritize or limit specific network traffic | none |

**Delete operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| DELETE | `/api/qos/rules/{id}` | Delete a traffic shaping rule and recalculate policy priority | id |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/qos/preview` | Preview firewall rules that would be generated from current QoS settings without applying them | none |
| GET | `/api/qos/status` | Get current traffic shaping status including enabled pipes, rules and queue statistics | none |

### reports

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/reports/definitions` | List all configured report definitions with their schedules and settings | none |
| GET | `/api/reports/runs` | List all generated report runs with execution status and download information | definition |

**Create operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/reports/definitions` | Create a new report definition with name, queries and delivery settings | none |

**Update operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| PUT | `/api/reports/definitions/{id}` | Update an existing report definition with modified query or delivery settings | id |

**Delete operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| DELETE | `/api/reports/definitions/{id}` | Delete a report definition and all associated scheduled runs | id |
| DELETE | `/api/reports/runs/{run}` | Delete a generated report run and free associated storage resources | run |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/reports/definitions/{id}` | Retrieve a specific report definition with all its settings and query criteria | id |
| POST | `/api/reports/preview` | Generate a test report with current data to preview before running scheduled | none |
| POST | `/api/reports/run/{id}` | Execute a report definition immediately and schedule generation of output | id |
| GET | `/api/reports/runs/{run}` | Retrieve details and status of a specific report run including metrics | run |
| GET | `/api/reports/runs/{run}/download` | Download a generated report in the requested format (HTML, PDF, or CSV) | run, format |

### rulehygiene

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/rulehygiene/changes` | Recent configuration changes and rule modifications tracked from firewall system | none |
| GET | `/api/rulehygiene/findings` | Open findings from firewall rule analysis including policy recommendations | none |
| GET | `/api/rulehygiene/rules` | Complete list of firewall rules with hit counters, descriptions and associated findings | none |
| POST | `/api/rulehygiene/run` | Trigger immediate firewall rule analysis to detect policy issues and cleanup opportunities | none |
| GET | `/api/rulehygiene/summary` | Summary of firewall rule health including risk score and analysis statistics | none |

### scan

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/scan/results` | List the latest scan results for all recently scanned IP addresses and hosts | none |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/scan/cancel` | Cancel a currently running or queued scan operation for an IP or MAC address | none |
| GET | `/api/scan/result` | Retrieve the latest scan result for a specific IP address with detected services | none |
| POST | `/api/scan/start` | Start a network scan on a specific IP address or MAC address to detect services | none |
| GET | `/api/scan/status` | Get current scan queue status, running jobs and last automatic sweep time | none |
| POST | `/api/scan/sweep` | Start a comprehensive network sweep scanning all local devices for services | none |

### setup

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/setup/apply` | Apply answers from the current setup wizard step and advance to the next | none |
| POST | `/api/setup/reset` | Reset setup wizard progress to initial state | none |
| GET | `/api/setup/state` | Get current setup wizard state and auto-detected network configuration facts | none |
| POST | `/api/setup/test` | Test and validate configuration values provided in the current setup step | none |

### ui

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/ui/prefs` | Get user interface preferences and display settings applied at front-end startup | none |

### updater

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/updater/apply` | Download and apply the latest available update to the application | none |
| POST | `/api/updater/check` | Trigger an immediate check for newer application versions from the update server | none |
| POST | `/api/updater/rollback` | Revert to the previous application version if current update has issues | none |
| GET | `/api/updater/status` | Get current application version, latest available version and update readiness status | none |

### visibility

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/visibility/catalog` | List all known applications and content categories available for filtering and classification | none |
| GET | `/api/visibility/flows` | List recent network flows with detailed source, destination and application information | minutes, ip, app, limit, country, abroad, blocked, anycast |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/visibility/abroad` | Show per-device traffic to foreign countries with session and byte counts by country | hours, ip |
| GET | `/api/visibility/apps` | Breakdown of network traffic by application type with byte counts and session metrics | hours, ip |
| GET | `/api/visibility/host` | Comprehensive analysis of a single host including connections, applications and countries | ip, hours |
| GET | `/api/visibility/summary` | Get current network statistics including throughput, active flow count, and connected hosts | none |
| GET | `/api/visibility/timeseries` | Fetch metric time series data for building charts and analyzing traffic trends | hours, metric, step |
| GET | `/api/visibility/top` | Top hosts, applications, categories and destinations ranked by traffic volume | hours, limit |

## Authentication

The API accepts authentication in three ways:

1. **Token header**: Send `X-Flowsight-Token: your-api-token` with every request.
2. **Bearer token**: Send `Authorization: Bearer your-api-token` with every request.
3. **Session cookie**: POST `{"token": "your-api-token"}` to `/api/login` to receive an `fs_session` cookie.

Loopback clients (127.0.0.1, ::1) without a token configured are trusted.

## Common parameters

Many endpoints accept query parameters to control scope and pagination:
- `hours`: Time window in hours (default varies by endpoint; max 9600 hours).
- `minutes`: Time window in minutes (alternative to hours).
- `limit`: Maximum number of records to return (default 100; max 10000).
- `offset`: Pagination offset for large result sets.

## Response format

All responses are JSON. Successful requests return the requested data. Errors return:

```json
{"error": "error message"}
```

Status codes:
- `200` OK
- `400` Bad request (invalid input or missing required field)
- `402` License tier or feature required, or license expired
- `403` Forbidden (insufficient permissions, read-only instance, or missing header)
- `404` Not found
- `500` Internal server error

