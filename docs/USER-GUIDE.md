# User guide

Every page of FlowSight, in the order of the menu. The range buttons at the
top (1h, 6h, 24h, 7d, 30d) set the window for every page that shows
history; the search box takes an address (opens the host), a domain (opens
its sessions) or free text.

**Addresses.** Wherever a host would be shown as a bare address (a
destination no DNS answer named, a client without a lease name), FlowSight
can decorate it with its reverse-DNS name and, for public addresses, a
country flag. Both are switches under *Settings › enrich*, off by default;
turn on *Reverse DNS names* and *Country lookup* to have them. Names are
looked up through the gateway's own resolver and cached; countries come
from a country database downloaded into the data directory (DB-IP Lite
unless you point it at another MaxMind-format file) and refreshed monthly.
While the DB-IP database is in use the menu footer carries its attribution.

**Theme.** *Settings › ui › Theme* is *auto* by default: inside the OPNsense
GUI the pages follow the OPNsense theme (light, dark, or the GUI's own
automatic mode), and on a standalone installation they follow the operating
system preference. Choose *light* or *dark* to pin it.

Pages marked **Pro** or **Business** need that license tier; below it they
show a card that explains what the tier adds and links to the License page.
A lock next to a menu entry means the same.

## Visibility

### Overview

The network at a glance for the window: throughput inbound and outbound
(shown separately, both in the figure and in the chart), active hosts,
sessions, applications, DNS queries, blocked requests. Charts of
throughput over time, one line each for inbound and outbound; the top hosts by traffic; the top applications; web
categories; the busiest DNS names; recent alerts and findings. Every item
links to its detail page.

### Hosts

Every device seen in the window. Columns: name (from DHCP, reservation or
resolver), address, MAC and vendor, whether the MAC is randomised, bytes in
and out, sessions, blocked requests, last seen. Sort by any column; filter
by name or address. A host that stops appearing is not deleted, it just
falls out of the window.

Hosts and Devices overlap on purpose and answer different questions.
**Hosts** is what the traffic shows: one row per address seen in flows and
DNS within the window, with its traffic, and it includes far ends and
transient visitors. **Devices** (under Policy) is the enrolment inventory:
one row per physical device known by its MAC from DHCP, with a class and a
zone, listed whether or not it is talking right now. A device's address
opens its host page; a host page shows the device's class and zone.

**Host page** (click a host): identity details and how each was learned;
throughput over time; applications, sites and DNS names with bytes and
counts; the session list; alerts and blocks; the policies that match it
and which group brought it in; enrolment class and zone.

### Sessions

The flow table: time, client, server, application (nDPI), server name (from
DNS or from the proxy once interception is on), protocol and port, bytes
each way, duration, verdict (observed or blocked and by which policy), TLS
version and SNI when known. Filter by host, domain, application or verdict.
Sessions come from ntopng every few seconds and from the proxy log.

### Applications

Applications ranked by traffic and by hosts using them, with the nDPI
category. Click one for the hosts and the sessions. The catalogue used for
policy (names and categories) is the same one nDPI reports.

### Web

Web activity from the proxy log: top sites, categories, blocked requests,
and the recent request log with client, method, host, category, bump mode
(spliced, bumped, terminated) and TLS version. Empty until interception is
on. The proxy's own state (listening ports, workers, last error) is under
Settings › web.

### DNS

Resolver activity from the Unbound reply log: queries over time, top names,
top clients, response codes, blocked names with the policy that blocked
them. If clients use another resolver (a Pi-hole, a public resolver) this
page shows only what reaches Unbound; that is by design and not a fault.

## Security

### Threats

Suricata alerts from the EVE log: severity, signature, source and
destination, count over time, with the host page one click away. Requires
the IDS to be enabled in OPNsense; the module reports a finding when the
log is missing.

### TLS

Certificate transparency for the network.

- **Inspection CA** (Pro): create the FlowSight CA (EC P-256, generated on
  the box), download the certificate to install on devices, delete it.
  While a CA exists, policies may turn on inspection.
- **Certificates seen**: every server certificate observed by the proxy or
  the IDS, with subject, issuer, validity, key type, first and last seen,
  and the hosts that saw it. Findings flag expired, expiring, self-signed
  and weak certificates.
- **Sessions**: recent TLS sessions with SNI, version, bump mode.

### Firewall hygiene (Pro)

Continuous analysis of the live pf ruleset. **Rules** lists every rule with
its evaluation and packet counters, when the ruleset was loaded, and the
labels OPNsense gives them. **Findings** are the conclusions: never
evaluated since load, unused for a long time, shadowed by an earlier rule,
overly broad, changed since the last analysis. Each carries a severity and
what to do. A **risk score** summarises. **Changes** is the history of
ruleset changes with diffs. *Run now* re-analyses immediately.

## Policy

### Policies

The list in evaluation order with name, action (monitor or block), groups,
schedule, what it denies, whether it is active right now, whether every
requirement is met, and how many members it currently resolves to. Buttons
move a policy up or down, enable or disable it, edit or delete it.

**Editor**: name and description; action; groups to match (or *all*);
schedule; denied applications (search the catalogue), application
categories, web categories, domains, TLDs, ports (`tcp/25`,
`udp/6881-6889`) and *internet*; allowed domains that override the
denials; safe search; YouTube mode; TLS inspection with a bypass list.

**Plan** compiles the document onto every provider and shows, per
provider, the diff between what is in place and what would be written,
plus any unmet requirement. **Apply** writes it (needs *Enforce policy* on
in Settings › policy). **Export** and **Import** move the whole document as
JSON or YAML.

Community allows three policies; Pro removes the limit.

### Groups & schedules

Groups: name, description and members (addresses, networks, `mac:`,
`device:`, `zone:`, `all`), with the members each resolves to right now.
Schedules: name and weekly windows (days, from, to; a window past midnight
is written as from 20:00 to 07:00). Community allows two schedules.

### Categories

The web category catalogue: each category with its source feed, the number
of domains, when it was refreshed, and a lookup box to see which categories
a domain falls into. **Custom categories** are your own lists (domains one
per line) usable in policies like any other. Feeds refresh on a schedule set
in Settings › categories; roughly six million domains are indexed in memory
in a compact form.

### Devices

Every enrolled device with its class (phone, laptop, TV, camera, console,
printer, IoT), why it was classified so, its address (by name when known;
with *Settings › enrich* on, bare addresses gain a reverse-DNS name and
country), vendor, zone and last activity. Change a device's zone from its
row; the zone name links to the Zones page, and the zone chips at the top
filter the list. **Mode** (monitor or enforce) is switched here; enforce is
Pro and writes DHCP reservations and isolation. *Re-identify* re-runs the
classification.

### Zones

The zones with their subnet, isolation policy, how many devices each holds
and who they are (each name links back to the device, each count opens the
Devices page filtered to that zone). Below it the two documents: **zones**
(id, name, subnet, isolation) and **classification rules** (DHCP vendor
class, hostname pattern, OUI to a class and a zone). *Plan placement* shows
what enforce mode would write, *Apply placement* writes it. A captive page
on the LAN explains to an unplaced device what happens next.

## Operations

### Reports

Pick a report (network summary, per host, per application, web, DNS,
security, policy effectiveness) and a window; **Preview** renders it in the
browser. **Schedules** (Pro): the same reports by e-mail daily, weekly or
monthly, to a list of recipients, through a channel from Alerting; *Run
now* sends one immediately. **Export** (Pro): flows, DNS, alerts or hosts
for the window as CSV.

### Alerting

**Rules** evaluated every minute over the store: a new device, a blocked
request from a given group, traffic above a threshold, a threat alert of a
severity, a finding of a severity, a certificate about to expire, a policy
apply failure. Each rule has a severity and, for Pro, channels to notify.
**Channels** (Pro): e-mail (SMTP), webhook (JSON POST), Discord, Slack,
ntfy; *Test* sends a message. **Notifications** is the log of what was
raised and where it went. Without Pro, alerts still appear here and on the
Overview.

### Findings

Every open finding from every module in one list: severity, module, title,
what to do, when first seen. Acknowledge to silence one until it changes.
Findings close on their own when the condition stops being true.

### Events

The event log: configuration changes, applies and their outcome, license
changes, updates, service starts, module errors. Filter by module or kind.
The **Audit** view lists every write operation with the user and client
address, and every configuration change with its diff.

### System

Version, platform, uptime, memory in use and the soft limit, store size and
row counts per table, retention, module health (each module's state and
detail), the job list with last run, duration and failures (a locked job
means the license tier does not include it), and the platform paths in use.
*Run job* triggers any job now. Useful first stop when something looks off.

### Settings

One page per module: enable or disable it (restart to apply), and its
settings with help text. A setting left empty that means "use the platform
default" shows what is actually in use beneath the field (*Using: …*), such
as the detected local networks, the resolver log being followed or the
interfaces interception applies to; the field itself stays empty so the
default keeps following the platform. Saving applies immediately unless the
setting is marked restart. A module above the current tier shows its tier and cannot
be enabled. Every setting is listed in the
[Configuration reference](CONFIGURATION.md).

Two modules hold interface behaviour rather than network function:
**enrich** (reverse-DNS names and country lookup for bare addresses, both
off by default) and **ui** (the theme: auto, light or dark).

### Updates

Installed version, latest published version, release notes. **Check now**
fetches the signed manifest; **Install update** downloads the binary,
verifies its checksum and signature against the key compiled into the
running build, swaps it in atomically and restarts the service (about ten
seconds); **Roll back** restores the previous binary. Only a newer version
is ever applied. *Apply updates automatically* in Settings › updater does
the same on the daily check.

### License

The tier this installation runs, the licensee, expiry and seats, and how
the license got here (online activation with its lease, or a file). Two
forms: **Activate online** with an activation key, and **Install a license
file** for air-gapped installations (the installation id to quote is shown
here). The tier comparison lists every gated feature and the limits. *Remove
license* returns to Community and frees the seat. See
[Licensing](LICENSING.md).

## Keyboard and browser notes

The interface has no build step and no external resources; it works
offline and inside the OPNsense GUI frame. It refreshes pages that show
live data every few seconds while the tab is visible, and stops when it is
hidden. Deep links use the hash (`#host/10.0.0.5`, `#flows?domain=…`), so
the browser back button and bookmarks work.
