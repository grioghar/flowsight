# API reference

FlowSight is driven entirely through a JSON HTTP API; the UI uses nothing else. On OPNsense the GUI page proxies it at `/flowsight.php?api=<path>` with the session's CSRF token; on other systems it listens at `http://127.0.0.1:8080` by default.

## Conventions

- Every write (POST) needs the header `X-Requested-With: Flowsight`. From anything that is not the OPNsense GUI or loopback, also send the API token in `X-Flowsight-Token` (or sign in once at `POST /api/login` with `{"token": …}` to get a session cookie).
- Responses are JSON objects. Errors are `{"error": "message"}` with a matching status: 400 invalid input, 402 the feature needs a higher license tier or the license has expired (`locked` or `expired` is set, with `feature` and `required`), 403 forbidden (missing header, read-only instance, locked key), 404 unknown route, 500 a backend failed.
- Time windows take `hours` (default 24). Lists take `limit`.
- The machine-readable description is at `GET /api/openapi.json`.
- Every write is recorded in the audit log (`GET /api/system/audit`) with the user and client address.

## Routes

### alerting

| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/alerting/channels` | Replace notification channels |  |
| POST | `/api/alerting/channels/test` | Send test message to a channel |  |
| GET | `/api/alerting/notifications` | Recent notifications | limit (rows) |
| POST | `/api/alerting/rules` | Replace alert rules |  |
| GET | `/api/alerting/status` | Channel status and recent notifications |  |

### appcontrol

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/appcontrol/blocked` | Recent application blocks | hours (window), limit (rows) |
| GET | `/api/appcontrol/status` | Active application rules and what they have blocked |  |

### categories

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/categories` | Categories, sizes and feed status |  |
| POST | `/api/categories/custom` | Create or replace a custom category |  |
| GET | `/api/categories/lookup` | Categories a domain belongs to | domain (name) |
| POST | `/api/categories/update` | Refresh one or all feeds now |  |

### dns

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/dns/log` | Recent queries | blocked (only blocked), client (filter), domain (substring), limit (rows) |
| GET | `/api/dns/lookup` | Names the resolver handed out for an address | ip (address) |
| GET | `/api/dns/summary` | Query volumes, block rate, top domains and clients | hours (window) |
| GET | `/api/dns/timeseries` | Queries and blocks over time | hours (window) |

### egress

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/egress/live` | Connections carrying data right now, newest sample | group (filter), min_kb (floor) |
| GET | `/api/egress/summary` | What is leaving now, totalled by device and by destination group |  |
| GET | `/api/egress/events` | Transfers that crossed a threshold, most recent first | limit (rows) |
| POST | `/api/egress/stop` | Drop a transfer that is running ({local, peer}); the connection is killed at the firewall |  |

### enrich

| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/enrich/lookup` | Names and countries for a list of addresses (up to 500); unknown names are resolved in the background and answered on the next call |  |
| GET | `/api/enrich/status` | What is enabled, cache size, country database state |  |

### enroll

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/enroll` | Enrollment status, zones and device counts |  |
| POST | `/api/enroll/apply` | Apply enforcement |  |
| POST | `/api/enroll/assign` | Assign a device to a zone and pin it there; an empty zone unpins it so the rules place it ({mac, zone}) |  |
| GET | `/api/enroll/devices` | All devices with filtering; each carries `excluded` / `excluded_by` when the policy's exclusion list keeps it out of inspection, and the response's `excluded` lists the entries | q (search query), zone (filter by zone) |
| GET | `/api/enroll/services` | What each device uses (applications, by bytes) and offers (ports other local hosts connected to, with distinct clients), keyed by MAC | hours (1-168, default 24) |
| POST | `/api/enroll/mode` | Set monitor/enforce mode |  |
| GET | `/api/enroll/plan` | Plan of what apply would do |  |
| POST | `/api/enroll/reconcile` | Re-classify devices |  |
| GET | `/api/enroll/rules` | Current rules configuration |  |
| POST | `/api/enroll/rules` | Update rules |  |
| GET | `/api/enroll/zones` | Current zones configuration |  |
| POST | `/api/enroll/zones` | Update zones |  |
| GET | `/captive` | (undocumented) |  |
| POST | `/captive` | (undocumented) |  |

### firewall

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/firewall/status` | Anchor state, tables and rule counters |  |

### identity

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/identity/hosts` | Known hosts with names, MACs, vendors and last activity | all (include inactive), hours (activity window) |
| GET | `/api/identity/leases` | Current DHCP leases |  |
| GET | `/api/identity/lookup` | Name, MAC and vendor for one address | ip (address) |
| POST | `/api/identity/name` | Assign a display name to an address |  |

### ids

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/ids/alerts` | Recent alerts | hours (window), ip (either end), limit (rows), severity (filter) |
| POST | `/api/ids/alerts/ack` | Acknowledge alerts |  |
| GET | `/api/ids/summary` | Alert counts by severity, category, signature and host | hours (window) |

### license

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/license` | Current tier, license, features and limits |  |
| POST | `/api/license/activate` | Activate an activation key against the license server |  |
| GET | `/api/license/features` | The feature catalogue with what this installation has |  |
| POST | `/api/license/install` | Install a signed license file (offline) |  |
| POST | `/api/license/refresh` | Refresh the online lease now |  |
| POST | `/api/license/remove` | Remove the license and return to Community (tells the server, when it was an online activation) |  |

### mitm

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/mitm/status` | Deep inspection: whether it is listening and what it has seen |  |
| GET | `/api/mitm/requests` | The most recent decrypted requests with their headers | limit (rows), q (substring) |

### paths

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/paths/status` | Tracing state plus `sources`: per data source, whether it is on and what it has produced (IPmap answered/queued/back-off, cables and land routes loaded, OSM telecom lines with regions and weight, `providers` with per-feed prefix counts and errors, `reputation` (AbuseIPDB: on, known, asked this session, error), `geofeeds` (found, fetched, rows, failing), `assistant` (provider, model, answered, queued, per hour, error), `identify` (anycast servers asked, placed, queued, root sites on file), `shodan` (mode, keyed, known, error); the `providers.feeds` map includes `census` (LACeS anycast prefixes), learned corrections, registry queue) |  |
| GET | `/api/paths/destinations` | Destinations with a measured route; `bytes_in`/`bytes_out` come from the five-minute rollups and lag the newest flow by up to five minutes | limit (rows), hours (traffic window) |
| GET | `/api/paths/path` | Every hop to one destination, in order, with names, locations and operator detail, plus `inside`: the device on this network that used the route | dst (destination), device (whose flows to count) |
| GET | `/api/paths/fcc/files` | The FCC release's file catalogue recorded at the last check | filter (substring), limit |
| POST | `/api/paths/fcc/check` | Test the FCC broadband map credentials and record the current release and file count |  |
| GET | `/api/paths/fcc/summary` | The national provider summaries (fixed and mobile broadband) and the origin state's census-place summary kept from the last pull, with `providers` and `mobile` (arrays sorted by location count), place name and technology coverage, column headers for the record; `full=1` returns all providers; nothing if not yet pulled | full (1 to get all providers) |
| POST | `/api/paths/fcc/pull` | Pull the national and state summaries from the FCC now, or skip silently if no credentials |  |
| GET | `/api/paths/shodan` | Shodan record for a hop (InternetDB; plus the keyed host record when a key is set) | ip (address), now (1 to fetch if not cached) |
| GET | `/api/paths/geofeeds` | RFC 8805 geofeeds discovered in registry objects: URL, the address whose object named it, fetch time, rows placed, errors |  |
| GET | `/api/paths/talkers` | Devices on this network that talked to an endpoint, each with its services (`app`, `domain`, `port`, `proto`, bytes, flows), plus a cross-device service summary; also embedded as `talkers` in `/api/paths/path` | dst (endpoint), hours (window, default 24) |
| GET | `/api/paths/corrections` | What the address database has been shown to get wrong: `corrections` (prefixes placed by one of their own routers or a RIPE measurement, with `by`, `from`, `from_km`, `seen`) and `distrusted` (registrant coordinates per ASN, with `count` and `examples`; applied once `count` reaches `distrust_after`) |  |
| POST | `/api/paths/corrections/forget` | Forget learned items | body `prefix` (a correction), `key` (a distrusted coordinate), or `all: true` (everything, to be relearned) |
| GET | `/api/paths/devices` | Devices whose traffic has a measured route, one entry per device |  |
| GET | `/api/paths/cables` | The submarine cable map, simplified for drawing | detail (points per cable) |
| GET | `/api/paths/home` | The origin the map is drawn from, this gateway's own public addresses (`public_v4`, `public_v6`, and `public_address` for the one the origin was worked out from), and what could be detected for it |  |
| POST | `/api/paths/home` | Declare your location ({lat, lon}), or {clear:true} to go back to detecting it |  |
| GET | `/api/paths/graph` | The whole picture as nodes and legs, with shared legs collapsed. Hops that never answered are not sent; `silent_count` gives their number. Endpoints carry `bytes_in`/`bytes_out` over the window. Built once and cached for 20 s per distinct query. | device (source address), country (filter), max_latency (ms), max_hops, hours (traffic window, default 24) Includes `rejected`: placements the round trip ruled out and that were set aside, with source, place, timing and floor. |

### policy

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/policy` | The policy document, its status and the last plan |  |
| POST | `/api/policy` | Replace the whole policy document (validated first) |  |
| POST | `/api/policy/apply` | Apply the plan now (requires enforce) |  |
| GET | `/api/policy/capabilities` | Providers, capabilities and what each policy needs |  |
| POST | `/api/policy/exclusions` | Replace exclusions and options |  |
| GET | `/api/policy/export` | The document as YAML |  |
| POST | `/api/policy/group` | Create or update a group |  |
| POST | `/api/policy/group/delete` | Delete a group |  |
| POST | `/api/policy/import` | Replace the document from YAML or JSON text |  |
| GET | `/api/policy/plan` | Compile onto every provider and show what would change |  |
| POST | `/api/policy/policy` | Create or update one policy |  |
| POST | `/api/policy/policy/delete` | Delete one policy |  |
| POST | `/api/policy/policy/move` | Reorder a policy |  |
| POST | `/api/policy/schedule` | Create or update a schedule |  |
| POST | `/api/policy/schedule/delete` | Delete a schedule |  |

### qos

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/qos/status` | Whether shaping is on, the pipes in force, the rules and what each queue is holding |  |
| GET | `/api/qos/preview` | The firewall rules the current settings would produce, without applying them |  |

### reports

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/reports/export` | Export data as CSV | hours (window), kind (flows/dns/alerts/hosts) |
| GET | `/api/reports/preview` | Generate and preview a report as HTML | hours (window) |
| POST | `/api/reports/run` | Generate and send a report now |  |
| GET | `/api/reports/schedules` | List report schedules |  |
| POST | `/api/reports/schedules` | Replace report schedules |  |

### rulehygiene

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/rulehygiene/changes` | Configuration changes from the changes table |  |
| GET | `/api/rulehygiene/findings` | Open findings |  |
| GET | `/api/rulehygiene/rules` | Every rule with counters, description, interface and findings |  |
| POST | `/api/rulehygiene/run` | Run analysis now |  |
| GET | `/api/rulehygiene/summary` | Risk score, finding counts, rules analysed, ruleset loaded since |  |

### system

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/openapi.json` | This document, generated from the route table |  |
| GET | `/api/system/audit` | Recent write operations | limit (rows) |
| GET | `/api/system/changes` | Configuration change history | limit (rows), module (filter) |
| GET | `/api/system/events` | Normalised events | hours (window), kind (event kind), limit (rows) |
| GET | `/api/system/findings` | Open findings across modules | module (filter by module) |
| POST | `/api/system/findings/ack` | Acknowledge a finding |  |
| GET | `/api/system/health` | Module and job health, capabilities, store size |  |
| GET | `/api/system/info` | Version, platform, uptime, site |  |
| GET | `/api/system/profile` | Runtime profile for diagnosis, in pprof format | `kind`: heap (default), allocs, goroutine or cpu; `seconds` (cpu only, 1-30, default 10) |
| POST | `/api/system/jobs/run` | Run a scheduled job now |  |
| GET | `/api/system/logout` | Drop the session |  |
| GET | `/api/system/modules` | Every module with settings and schema |  |
| POST | `/api/system/modules/save` | Save one module's settings |  |
| GET | `/api/system/panels` | UI panels contributed by loaded modules |  |

### tls

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/tls/ca` | The inspection CA: subject, fingerprint, validity, whether it exists |  |
| POST | `/api/tls/ca/create` | Create (or replace) the inspection CA |  |
| POST | `/api/tls/ca/delete` | Delete the inspection CA; inspection stops |  |
| GET | `/api/tls/ca/download` | The CA certificate in PEM (or DER with ?format=der) for installing on devices |  |
| GET | `/api/tls/certs` | Certificates seen on the network | hours (window), limit (rows), problem (only problematic), q (search subject/issuer/sni) |
| GET | `/api/tls/sessions` | Recent TLS sessions | ip (client), limit (rows), sni (substring) |
| GET | `/api/tls/summary` | TLS versions, bump modes, issuers, problems | hours (window) |

### ui

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/ui/prefs` | Interface preferences the front end applies at start (theme) |  |

### updater

| Method | Path | What | Parameters |
|---|---|---|---|
| POST | `/api/updater/apply` | Apply the available update |  |
| POST | `/api/updater/check` | Check for updates now |  |
| POST | `/api/updater/rollback` | Rollback to the previous binary |  |
| GET | `/api/updater/status` | Current version, latest version, and update status |  |

### visibility

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/visibility/apps` | Application breakdown over a window | hours (window), ip (one host) |
| GET | `/api/visibility/catalog` | Known applications and categories |  |
| GET | `/api/visibility/flows` | Recent flows | app (filter), ip (filter by either end), limit (rows), minutes (window) |
| GET | `/api/visibility/host` | Everything about one host | hours (window), ip (address) |
| GET | `/api/visibility/summary` | Throughput, active flows and hosts right now |  |
| GET | `/api/visibility/timeseries` | Metric series for charts | hours (window), metric (name), step (seconds) |
| GET | `/api/visibility/top` | Top hosts, applications, categories, sites (each with `dst_ip`, the endpoint that served it, and `traced`), destinations | hours (window), limit (rows) |

### web

| Method | Path | What | Parameters |
|---|---|---|---|
| GET | `/api/web/log` | Recent web requests | blocked (only blocked), domain (substring), ip (client), limit (rows) |
| GET | `/api/web/pinned` | Names whose clients pin their certificate and are therefore relayed without inspection |  |
| POST | `/api/web/pinned` | Add a name to the pinned list, or remove one ({name, remove}) |  |
| GET | `/api/web/status` | Proxy process state and configuration |  |
| GET | `/api/web/summary` | Web activity: top sites, categories, blocked requests | hours (window) |

## Examples

```sh
# tier and license state
curl -s http://127.0.0.1:8080/api/license

# turn web interception on (loopback needs no token)
curl -s -X POST -H 'X-Requested-With: Flowsight' -H 'Content-Type: application/json' \
  -d '{"module":"web","settings":{"intercept":true}}' http://127.0.0.1:8080/api/system/modules/save

# names and countries for addresses (enrich module switches must be on)
curl -s -X POST -H 'X-Requested-With: Flowsight' -H 'Content-Type: application/json' \
  -d '{"ips":["1.1.1.1","8.8.8.8"]}' http://127.0.0.1:8080/api/enrich/lookup

# apply the policy plan
curl -s -X POST -H 'X-Requested-With: Flowsight' http://127.0.0.1:8080/api/policy/apply

# from another machine, with the token
curl -s -H 'X-Flowsight-Token: …' http://gateway:8080/api/system/health
```

