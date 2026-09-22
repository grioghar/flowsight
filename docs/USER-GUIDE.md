# User guide

Every page of FlowSight, in the order of the menu. The range buttons at the
top (1h, 6h, 24h, 7d, 30d) set the window for every page that shows
history; the search box takes an address (opens the host), a domain (opens
its sessions) or free text.

**Long tables** show the first hundred rows with the count beneath them,
*Show 100 more* and *Show all*, and an **Infinite scroll** checkbox that
loads further rows as you reach the bottom. The choice is remembered for
every table in this browser.

**Refreshing.** Pages with live data refresh themselves every 10 to 60
seconds. A refresh keeps your place: the scroll position, each table's own
scroll and the column you sorted by all survive it, and it is held back
entirely while a dialog is open, a field has focus or text is selected. The
**pause button** next to the range buttons stops it altogether for this
browser; press it again to resume and refresh at once.

Inside the OPNsense GUI the pages are reached from the **FlowSight**
section of OPNsense's own left-hand menu; the app shows no sidebar of its
own there, only the page, a top bar and a one-line footer with health,
version and attribution. Standalone (Linux, or the daemon opened directly)
the app has its own sidebar with the same entries.

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

A device is one device whatever address it is using. FlowSight ties every
address a device holds, IPv4 and IPv6 alike, to its MAC: names, vendor,
policy membership (`mac:` and `device:` members) and the device inventory
follow all of them, and an address stays associated for a day after it was
last seen so the temporary IPv6 addresses operating systems rotate through
do not shake a device loose from its policy. A host page lists the device's
other addresses and links them.

**Host page** (click a host): identity details and how each was learned;
throughput over time; applications, sites and DNS names with bytes and
counts; the session list; alerts and blocks; a **Blocked queries** card
listing the most recent DNS blocks for the host with the list that blocked
each (FlowSight policy or Pi-hole gravity, regex, denylist) and the
resolver they came through; the policies that match it and which group
brought it in; enrolment class and zone.

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
and the recent request log. Each row names the client, the site and, when
the proxy could see inside the request, the method, path and response code;
an inspected HTTPS request is marked *decrypted*, an uninspected one reads
*encrypted (not inspected)*. The **decrypted only** link above the table is
the view of everything TLS inspection has opened; combine it with a client
(`#web?decrypted=1&client=…`, or from a host page) to see one device. Empty
until interception is on. The proxy's own state (listening ports, workers,
last error) is under Settings › web.

### DNS

Resolver activity: queries over time, top names, top clients, response
codes, blocked names with the policy or list that blocked them. Records
come from the Unbound reply log and, when configured, from Pi-hole servers;
the *Via* column of the query log says which. If clients use a resolver
FlowSight does not read (a public resolver, DoH in a browser) those queries
are simply not seen.

**Pi-hole.** *Settings › pihole*: list the servers (`https://192.168.1.53`)
and give the app password (Pi-hole v6: Settings › Web interface / API ›
Configure app password; v5: the API token). FlowSight pulls the query log
every 30 seconds, going back 24 hours on first contact, deduplicates by
Pi-hole's query ids, and files each query under its client with the
verdict and list (gravity, regex, denylist, upstream blocked). Client
names Pi-hole knows are used for hosts FlowSight has no name for. Nothing is
written to the Pi-holes.

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

**Decrypting sessions, step by step.** Without a CA the proxy only peeks
at handshakes: you see server names, versions and certificates, never the
inside of a session. To decrypt selected devices:

1. **TLS › Create inspection CA** (Pro). The key pair is generated on the
   firewall and never leaves it.
2. **Download the certificate** from the same card and install it as a
   trusted root on each device you intend to inspect. On a Mac: open the
   file in Keychain Access, System keychain, then set the certificate's
   trust to *Always Trust*. Do this *before* step 4, or every HTTPS
   connection from that device fails with a certificate warning.
3. **Groups & schedules**: make a group with those devices (by `mac:` is
   the stable choice).
4. **Policies**: a policy matching the group with *Inspect TLS* on and a
   bypass list for names that must never be decrypted: banking, health,
   the device's own vendor services (Apple, Microsoft, Google account
   traffic), and applications that pin certificates, which break under any
   inspection. *Action* can stay on monitor; inspection is independent of
   blocking.
5. **Apply.** From then on the TLS page shows those sessions as *bumped*
   with the negotiated version and the real server certificate, and the
   **Web page › decrypted only** view lists every decrypted request with its
   method, path and response code; the host page's web log shows the same
   for one device. Web policies on paths inside a site become possible.

What you get is the request layer: URLs, methods, response codes, sizes,
certificates. FlowSight does not record page or file contents, and it
never will by design (see [Security](SECURITY.md)). Traffic that never
crosses the firewall, such as two devices on the same subnet talking to
each other, is not seen by any of this; only routed traffic is.

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

### Status

What the daemon reports about itself, read-only: version, platform,
uptime, memory in use and the soft limit, store size and row counts per
table, retention, module health (each module's state and detail), the job
list with last run, duration and failures (a locked job means the license
tier does not include it), and the platform paths in use. *Run job*
triggers any job now. Useful first stop when something looks off.

Status and Settings are deliberately separate: **Status** is what
FlowSight is doing and how it is faring; **Settings** is what you tell it
to do. Nothing on the Status page changes configuration.

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

**pihole** pulls Pi-hole query logs (see the DNS page above).

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
