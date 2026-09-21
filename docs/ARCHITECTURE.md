# Architecture

## Principle

Compose, don't reimplement. Everything that touches packets is an existing,
battle-tested engine: Unbound answers DNS, squid terminates and relays TLS,
pf drops packets, nDPI (through ntopng) names applications, Suricata detects
threats. FlowSight owns the layer above them, which is the layer that never
existed: one policy model, one store, one interface, and the reconciliation
that keeps the engines in step with what the operator declared.

## The daemon

`flowsightd` is one static Go binary. It embeds the UI, opens one SQLite
file, and loads modules. It runs as root because it manages the resolver's
includes, the proxy instance and pf anchors; it listens on loopback only and
is reached through the OPNsense GUI (which authenticates) or, elsewhere,
with a token.

```
flowsightd
├── core        config · store (SQLite, WAL) · scheduler · API · module registry · policy model
├── identity    names and MACs: DHCP leases (dnsmasq/ISC/Kea), ARP/NDP, reservations, resolver answers, OUI
├── visibility  ntopng REST → flows, hosts, apps, throughput; publishes a flow bus
├── web         owns a transparent squid: SNI on every session, web.block, tls.inspect, block page
├── dns         Unbound reply log → DNS log; cache → address names; provider dns.block (RPZ + views)
├── firewall    pf anchors flowsight/*; provider net.block and the tables for app.block
├── appcontrol  subscribes to the flow bus; denied apps → pf table + state kill
├── tls         inspection CA (EC, generated in Go), certificate inventory, findings
├── ids         Suricata EVE → alerts, TLS sessions and certificates
├── categories  open domain feeds, cached; classification index; custom categories
├── policy      the document, validation, plan/diff, apply, reconcile every minute
├── enroll      device identification from DHCP, zones, placement, isolation, captive page
├── rulehygiene pf ruleset analysis with live counters, change tracking, risk score
├── reports     HTML reports, CSV export, schedules by email
├── alerting    rules over the store → email / webhook / Discord / Slack / ntfy
├── telemetry   optional OTLP export of metrics and events
└── updater     signed release manifest, verified download, atomic swap, roll back
```

### Module contract

A module implements `Info()` and `Setup(ctx)`. Through the context it
registers jobs (run on a shared pool; a panic is contained and reported),
API routes (every write passes one gate), policy providers, UI panels and
published services other modules consume. It declares its capabilities;
policy targets capabilities, never modules.

| Capability | Meaning | Provided by |
|---|---|---|
| `traffic.observe`, `app.observe`, `host.inventory` | flows, applications, devices | visibility, identity, enroll |
| `web.observe`, `tls.observe` | server names, sessions, certificates | web, ids, tls |
| `dns.observe` | resolver activity | dns |
| `threat.detect` | signatures | ids |
| `firewall.analyse` | ruleset hygiene | rulehygiene |
| `dns.block` | refuse a name | dns (Unbound RPZ/views) |
| `web.block` | terminate a web session by name | web (squid) |
| `app.block` | cut an application | firewall + appcontrol (pf tables from nDPI) |
| `net.block` | ports, internet | firewall (pf) |
| `tls.inspect` | decrypt selected clients | web + tls (squid bump with the CA) |
| `notify` | deliver a message | alerting |

A module that only observes must never claim a `.block` capability; the
compiler trusts the declaration, and a false one produces a policy that
silently does nothing.

## Data path

FlowSight is not inline. pf redirects port 80 and 443 from the local networks
to squid on loopback; squid peeks at the ClientHello for the server name and
splices (relays untouched) unless the policy says terminate or bump.
Application blocking is reactive: nDPI names the application on the first
packets, the far end goes into a pf table, the state is killed, and every
later connection is dropped at the first packet. DNS blocking happens in the
resolver. If flowsightd dies, nothing changes for traffic already allowed;
interception rules are loaded only while the proxy answers, and withdrawn
the moment it stops, so a proxy failure cannot take the web down.

## The store

One SQLite file in WAL mode. Raw flows, DNS queries, alerts and TLS sessions
are kept for days; five-minute rollups by application, domain, destination
and DNS name are kept for a year and answer every long-window question.
Findings are idempotent on a fingerprint and closed automatically when they
stop being true. Every configuration change is recorded with its diff and
the user who made it.

## Policy compilation

`policy.json` is validated as a whole. Each provider compiles the document to
its artifact (Unbound zones and views, squid configuration and ACL files, pf
rules), shows the diff against what is in place, and applies only when
enforcement is on: write atomically, validate with the backend's own checker,
revert on rejection, reload. Reconciliation runs every minute, so schedule
windows, refreshed category feeds and hand edits converge without a button.
See [POLICY.md](POLICY.md).

## OPNsense integration

The plugin is small on purpose: an rc script, configd actions, a
`plugins.inc.d` hook that registers the service and three pf anchors
(`flowsight/*` quick at the head of the filter rules, and as rdr and nat
anchors at the tail so port forwards and reflection still win), a menu, an
ACL, and one legacy page that serves the embedded UI and proxies its API
with the session's CSRF token and a same-origin check. Everything else is
the daemon.

## Where it beats Zenarmor

No licence gates: exclusions, unlimited policies, every report. No cloud: data
never leaves the firewall, and the category feeds are open. No inline packet
engine to pin a core or drop rings. Policy, groups and schedules as a diffable
document. Firewall hygiene, certificate inventory, device enrolment with zone
placement, self-hosted alerting and reports, signed in-place updates.

## Where it does not, yet

Content inspection inside decrypted sessions is not performed: inspection
today yields URLs, certificates and the ability to block by full URL path in
squid, not keyword or file-type scanning. Country blocking needs a GeoIP
source. User identity from directories (LDAP, RADIUS accounting) and per-user
policy are on the roadmap. Linux enforcement beyond DNS needs nftables
providers.
