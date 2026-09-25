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
| GET | `/captive` | Captive portal page | none |
| POST | `/captive` | Captive portal action | none |

### alerting

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/alerting/channel-types` | List all notification channel types grouped by family, with configuration schemas | none |
| GET | `/api/alerting/channels` | List all configured notification channels | none |
| GET | `/api/alerting/rules` | List all alert rules | none |

**Create operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/alerting/channels` | Create a new notification channel | none |
| POST | `/api/alerting/rules` | Create a new alert rule | none |

**Update operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| PUT | `/api/alerting/channels/{id}` | Update a notification channel | id, id |
| PUT | `/api/alerting/rules/{id}` | Update an alert rule | id, id |

**Delete operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| DELETE | `/api/alerting/channels/{id}` | Delete a notification channel | id, id |
| DELETE | `/api/alerting/rules/{id}` | Delete an alert rule | id, id |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/alerting/ack/{alert_key}` | Acknowledge an active alert | id, alert_key |
| GET | `/api/alerting/channels/{id}` | Get a specific notification channel | id, id |
| POST | `/api/alerting/channels/{id}/test` | Send a test message to a channel | id, id |
| GET | `/api/alerting/deliveries` | Get notification delivery history | channel, limit |
| GET | `/api/alerting/feed.xml` | RSS feed of recent alerts (requires token in Authorization header) | none |
| POST | `/api/alerting/import-apprise` | Import Apprise notification URL | none |
| GET | `/api/alerting/maintenance` | Get current maintenance mode status | none |
| POST | `/api/alerting/maintenance` | Enable or disable maintenance mode (suppresses alerts) | none |
| GET | `/api/alerting/notifications` | Recent notifications | limit |
| POST | `/api/alerting/resolve/{alert_key}` | Resolve an acknowledged alert | id, alert_key |
| GET | `/api/alerting/rules/{id}` | Get a specific alert rule | id, id |
| POST | `/api/alerting/simulate` | Generate a test alert to verify rules | none |
| GET | `/api/alerting/status` | Channel status and recent notifications | none |

### appcontrol

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/appcontrol/blocked` | Recent application blocks | hours, limit |
| GET | `/api/appcontrol/status` | Active application rules and what they have blocked | none |

### dns

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/dns/log` | Recent queries | blocked, client, domain, limit |
| GET | `/api/dns/lookup` | Names the resolver handed out for an address | ip |
| GET | `/api/dns/summary` | Query volumes, block rate, top domains and clients | hours |
| GET | `/api/dns/timeseries` | Queries and blocks over time | hours |

### egress

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/egress/events` | Transfers that crossed a threshold, most recent first | limit |
| GET | `/api/egress/live` | Connections carrying data right now, newest sample | group, min_kb |
| POST | `/api/egress/stop` | Drop a transfer that is running ({local, peer, port}); the connection is killed at the firewall | none |
| GET | `/api/egress/summary` | What is leaving now, totalled by device and by destination group | none |

### enrich

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/enrich/countries` | Countries available in the GeoIP database | none |
| POST | `/api/enrich/lookup` | Names and countries for a list of addresses (up to 500); unknown names are resolved in the background and answered on the next call | none |
| GET | `/api/enrich/status` | What is enabled, cache size, country database state | none |

### enroll

**Update operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/enroll/rules` | Update rules | none |
| POST | `/api/enroll/zones` | Update zones | none |
| PUT | `/api/enroll/zones/{id}` | Update a zone | id |

**Delete operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| DELETE | `/api/enroll/devices/{mac}` | Delete a device | mac |
| DELETE | `/api/enroll/zones/{id}` | Delete a zone | id |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/enroll` | Enrollment status, zones and device counts | none |
| POST | `/api/enroll/apply` | Apply enforcement | none |
| POST | `/api/enroll/assign` | Assign a device to a zone and pin it there; an empty zone unpins it so the rules place it ({mac, zone}) | none |
| GET | `/api/enroll/devices` | All devices with filtering | q, zone |
| GET | `/api/enroll/devices/{mac}` | Get a device by MAC | mac |
| POST | `/api/enroll/mode` | Set monitor/enforce mode | none |
| GET | `/api/enroll/plan` | Plan of what apply would do | none |
| POST | `/api/enroll/reconcile` | Re-classify devices | none |
| GET | `/api/enroll/rules` | Current rules configuration | none |
| GET | `/api/enroll/services` | What each device uses (applications) and offers (ports other local hosts connect to), by MAC | hours |
| GET | `/api/enroll/zones` | Current zones configuration | none |
| GET | `/api/enroll/zones/{id}` | Get a zone by ID | id |

### identity

**Delete operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| DELETE | `/api/identity/name/{ip}` | Delete a name override by IP | ip |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/identity/hosts` | Known hosts with names, MACs, vendors and last activity | all, hours |
| GET | `/api/identity/leases` | Current DHCP leases | none |
| GET | `/api/identity/lookup` | Name, MAC and vendor for one address | ip |
| POST | `/api/identity/name` | Assign a display name to an address | none |

### ids

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/ids/alerts` | Recent alerts | hours, ip, limit, severity |
| POST | `/api/ids/alerts/ack` | Acknowledge alerts | none |
| GET | `/api/ids/summary` | Alert counts by severity, category, signature and host | hours |

### license

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/license` | Current tier, license, features and limits | none |
| POST | `/api/license/activate` | Activate an activation key against the license server | none |
| GET | `/api/license/features` | The feature catalogue with what this installation has | none |
| POST | `/api/license/install` | Install a signed license file (offline) | none |
| POST | `/api/license/refresh` | Refresh the online lease now | none |
| POST | `/api/license/remove` | Remove the license and return to Community (tells the server, when it was an online activation) | none |

### mitm

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/mitm/requests` | The most recent decrypted requests with their headers | limit, q |
| GET | `/api/mitm/status` | Stateful Packet Inspection: whether it is listening and what it has seen | none |

### paths

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/paths/cables` | The submarine cable map, simplified for drawing | detail |
| GET | `/api/paths/corrections` | What the address database has been shown to get wrong: corrected prefixes and distrusted registrant coordinates | none |
| POST | `/api/paths/corrections/forget` | Forget one learned correction (prefix) or distrusted coordinate (key) | none |
| GET | `/api/paths/destinations` | Destinations with a measured route | limit |
| GET | `/api/paths/devices` | Devices whose traffic has a measured route, one entry per device | none |
| POST | `/api/paths/fcc/check` | Test the FCC broadband map credentials and record the current release | none |
| GET | `/api/paths/fcc/files` | The FCC release's file catalogue from the last check | filter, limit |
| POST | `/api/paths/fcc/pull` | Run the monthly FCC pull now | none |
| GET | `/api/paths/fcc/summary` | What was kept from the FCC release: national fixed-broadband providers and the origin state's census places | full |
| GET | `/api/paths/geofeeds` | RFC 8805 geofeeds discovered in registry objects, with fetch state | none |
| GET | `/api/paths/graph` | The whole picture as nodes and legs, with shared legs collapsed | country, device, max_latency |
| GET | `/api/paths/home` | The origin the map is drawn from, and what could be detected for it | none |
| POST | `/api/paths/home` | Declare your location ({lat, lon}), or {clear:true} to go back to detecting it | none |
| GET | `/api/paths/path` | Every hop to one destination, with names and locations | dst |
| GET | `/api/paths/shodan` | Shodan record for a hop: InternetDB always, the keyed host record when a key is set; fetched now with now=1 | ip, now |
| GET | `/api/paths/status` | Whether tracing is on, how many destinations have a route, and when | none |
| GET | `/api/paths/talkers` | Which devices talked to an endpoint and over which services (application, name, port) | dst, hours |
| GET | `/api/paths/who` | The devices whose traffic reached any of the given destinations: what a hop click on the map sets its device filter to | dsts, hours |

### pihole

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/pihole/pull` | Pull from every server now | none |
| GET | `/api/pihole/status` | Per-server state: version, last pull, records imported, last error | none |

### policy

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/policy/groups` | List all groups | none |
| GET | `/api/policy/schedules` | List all schedules | none |

**Create operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/policy/group` | Create or update a group | none |
| POST | `/api/policy/policy` | Create or update one policy | none |
| POST | `/api/policy/schedule` | Create or update a schedule | none |

**Update operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| PUT | `/api/policy/groups/{name}` | Update a group | name |
| PUT | `/api/policy/schedules/{name}` | Update a schedule | name |

**Delete operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/policy/group/delete` | Delete a group | none |
| DELETE | `/api/policy/groups/{name}` | Delete a group by name | name |
| POST | `/api/policy/policy/delete` | Delete one policy | none |
| POST | `/api/policy/schedule/delete` | Delete a schedule | none |
| DELETE | `/api/policy/schedules/{name}` | Delete a schedule by name | name |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/policy` | The policy document, its status and the last plan | none |
| POST | `/api/policy` | Replace the whole policy document (validated first) | none |
| POST | `/api/policy/apply` | Apply the plan now (requires enforce) | none |
| GET | `/api/policy/capabilities` | Providers, capabilities and what each policy needs | none |
| POST | `/api/policy/exclusions` | Replace exclusions and options | none |
| GET | `/api/policy/export` | The document as YAML | none |
| GET | `/api/policy/groups/{name}` | Get a group by name | name |
| POST | `/api/policy/import` | Replace the document from YAML or JSON text | none |
| GET | `/api/policy/matches` | What a policy's country rule matches: per device, the far ends in denied countries from the session table (names, domains, bytes), and the packets the firewall's log recorded for the rule | hours, name |
| GET | `/api/policy/plan` | Compile onto every provider and show what would change | none |
| POST | `/api/policy/policy/move` | Reorder a policy | none |
| GET | `/api/policy/schedules/{name}` | Get a schedule by name | name |

### proxmox

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/proxmox/guest` | Guest by VMID and node | none |
| GET | `/api/proxmox/inventory` | Nodes and guests | none |
| GET | `/api/proxmox/map` | Dependency map | none |
| GET | `/api/proxmox/notes/preview` | Preview notes block | none |
| POST | `/api/proxmox/notes/write` | Write notes | none |
| POST | `/api/proxmox/poll` | Poll now | none |
| GET | `/api/proxmox/requirements` | Guest requirements | none |
| GET | `/api/proxmox/status` | Connection status and last poll | none |

### qos

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/qos/rules` | List all traffic shaping rules | none |

**Create operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/qos/rules` | Create a new traffic shaping rule | none |

**Delete operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| DELETE | `/api/qos/rules/{id}` | Delete a traffic shaping rule | id |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/qos/preview` | The firewall rules the current settings would produce, without applying them | none |
| GET | `/api/qos/status` | Whether shaping is on, the pipes in force, the rules and what each queue is holding | none |

### reports

**List operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/reports/definitions` | List all report definitions | none |
| GET | `/api/reports/runs` | List recent report runs | none |

**Create operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/reports/definitions` | Create a custom report definition | none |

**Update operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| PUT | `/api/reports/definitions/{id}` | Update a report definition | id |

**Delete operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| DELETE | `/api/reports/definitions/{id}` | Delete a report definition | id |
| DELETE | `/api/reports/runs/{run}` | Delete a report run | run |

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/reports/definitions/{id}` | Get a report definition | id |
| POST | `/api/reports/preview` | Generate and preview a report | none |
| POST | `/api/reports/run/{id}` | Execute a report definition | id |
| GET | `/api/reports/runs/{run}` | Get report run details | run |
| GET | `/api/reports/runs/{run}/download` | Download report in specified format | run |

### rulehygiene

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/rulehygiene/changes` | Configuration changes from the changes table | none |
| GET | `/api/rulehygiene/findings` | Open findings | none |
| GET | `/api/rulehygiene/rules` | Every rule with counters, description, interface and findings | none |
| POST | `/api/rulehygiene/run` | Run analysis now | none |
| GET | `/api/rulehygiene/summary` | Risk score, finding counts, rules analysed, ruleset loaded since | none |

### scan

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/scan/cancel` | Cancel a scan job | none |
| GET | `/api/scan/result` | Latest result for an IP | none |
| GET | `/api/scan/results` | Latest results for all IPs scanned recently | none |
| POST | `/api/scan/start` | Start a scan on an IP or MAC | none |
| GET | `/api/scan/status` | Queue status, running jobs, last sweep | none |
| POST | `/api/scan/sweep` | Start a sweep of all local devices | none |

### setup

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/setup/apply` | Apply one step's answers | none |
| POST | `/api/setup/reset` | Reset the wizard progress | none |
| GET | `/api/setup/state` | Wizard state and detected facts | none |
| POST | `/api/setup/test` | Test a step's values | none |

### ui

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/ui/prefs` | Interface preferences the front end applies at start (theme) | none |

### updater

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/updater/apply` | Apply the available update | none |
| POST | `/api/updater/check` | Check for updates now | none |
| POST | `/api/updater/rollback` | Rollback to the previous binary | none |
| GET | `/api/updater/status` | Current version, latest version, and update status | none |

### visibility

**Other operations**
| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/visibility/abroad` | Per local device, the foreign countries it reached, sessions and bytes per country, and the destinations behind them | hours, ip |
| GET | `/api/visibility/apps` | Application breakdown over a window | hours, ip |
| GET | `/api/visibility/catalog` | Known applications and categories | none |
| GET | `/api/visibility/flows` | Recent flows | abroad, app, blocked, country, ip, limit, minutes |
| GET | `/api/visibility/host` | Everything about one host | hours, ip |
| GET | `/api/visibility/summary` | Throughput, active flows and hosts right now | none |
| GET | `/api/visibility/timeseries` | Metric series for charts | hours, metric, step |
| GET | `/api/visibility/top` | Top hosts, applications, categories, destinations | hours, limit |

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

