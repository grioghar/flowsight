# Changelog

What changed in each release, written for the person running FlowSight
rather than for the person who wrote it: what is different, what you have to
do about it, and what is now possible that was not before.

Versions are `<version>` for a release and `<version>r<YYYYMMDDHHMM>` for a
revision of it, where the suffix is the UTC minute it was built. A revision
carries fixes and small additions; the version number itself moves only when
that is decided deliberately. Every entry below is a git tag of the same
name, and every release's assets carry that string in their file names.

The newest entry is first.

## 0.9.8r202609240714

**Path tracing no longer probes things that are not destinations.** The first
live run traced a multicast group and the gateway's own global address,
twenty timed-out probes each for a row of nothing. Multicast, broadcast and
any address this network's identity module recognises as its own are now
skipped. That last part matters for IPv6: the delegated prefix is globally
routable and still ours, so no fixed list of private ranges can catch it.

## 0.9.8r202609240704

**Paths: where traffic actually goes, measured.** A new page and module under
Visibility. Everything else in FlowSight watches the first hop; this traces
the rest of the route to the destinations your network already contacts, a
few at a time on a timer, and keeps what it finds. Nothing is probed that the
network has not already talked to.

A path belongs to a destination rather than a device, because everything
leaves through the same gateway. Filtering by device is a join over your own
flow history, so it costs no extra probes.

**Many routes fold into one picture.** Every route out starts the same way,
and drawn literally that is a hundred lines on top of each other. A leg used
by several destinations becomes one thicker line in a neutral colour;
coloured lines belong to a single destination. A position answering from
several addresses, which is how a carrier balances across parallel links, is
one point carrying several addresses rather than several points. Filters on
country, latency, distance in hops and device, with wheel to zoom and drag to
pan.

**Three things the map refuses to pretend.** The background is a longitude
and latitude grid, not a drawing of land, because these coordinates are
dependable for end-user addresses and rough for carrier equipment. Hops with
no coordinates are listed underneath rather than placed at zero, which would
pile a stack of routers into the Gulf of Guinea. Hops that never answered are
counted and not drawn, and they keep their place in the numbering so a path
is never quietly reported as shorter than it is.

Needs the city-level location database, since the country one carries no
coordinates.

## 0.9.8r202609240658

**Location lookup can now answer with coordinates, not just a country.**
*Settings › enrich › How much detail* chooses between the country database,
which is a few megabytes, and the city database, which is a much larger
download and adds the city, the region and the latitude and longitude a map
needs. Country stays the default: the larger file is only worth fetching if
something is going to draw with it.

The two are kept in separate files on disk. Sharing one name would let a
country database already downloaded stand in for the city one that was asked
for, and the only symptom would be a map with nothing on it.

Both still come from DB-IP's free files by default, and a configured URL
still wins, so a licensed MaxMind database works as before.

**Worth knowing before trusting a map built on this.** Geolocation is
accurate for end-user addresses and unreliable for infrastructure. In
testing, 1.1.1.1 resolves to Sydney because that is where Cloudflare
registered the block, while the server actually answering is whichever one
is nearest you. Coordinates are absent for a great many addresses, and zero
is reported rather than a guess, so anything drawing a map has to handle
"unknown" as a real answer.

## 0.9.8r202609232121

**Every device was being classified as the first rule in the list.** The rule
loader took the whole rule object as its condition set, so `id`, `zone`,
`confidence` and `why` sat alongside the real conditions, and the matcher
treated any key it did not recognise as a match. Between them, every rule
matched every device. On a live network that filed all 106 devices as
infrastructure, televisions and smart plugs included, which made it
impossible to write a policy that said "IoT" and have it mean anything.

The conditions are now read from the rule's `when` block, and an unrecognised
condition no longer counts as a match. A rule that fails open turns one typo
into "everything" without saying so, which is the worst way for this to be
wrong.

**An exclusion now covers the device, not just one of its addresses.**
Excluding a range exempted traffic in that address family only, so a
television excluded by its IPv4 address was still intercepted over IPv6. The
redirect rules are emitted for both families, and an exclusion written as an
IPv4 range is resolved to the devices inside it and widened to every address
those devices hold. The link between the two is the MAC, the only identifier
that spans both.

## 0.9.8r202609220957

**Priority: decide who waits when the link is full.** A new module and page
under Policy, and the first thing in FlowSight that changes traffic rather
than describing it.

It works by moving the bottleneck. When an uplink fills, the queue that
decides what waits belongs to the modem or the carrier and nothing on this
firewall can reach it, so shaping starts by sending everything through a pipe
sized a little under what the link really carries. Once the queue is on this
side, weights decide who waits. That is why the two rates are settings and
why they have to be honest.

Rules are written the way you would say them: `192.168.1.178 = low`,
`redgifs.com = high`, `10.0.5.0/24 = low, 20Mbit`. An address is understood
as a device here or as something out on the internet depending on which side
of your local networks it falls. A domain matches the addresses the network
has actually been seen using for it, and the page says per rule how many that
currently is, rather than leaving a rule that matches nothing looking
identical to one that works. The generated firewall rules are shown on the
page so they can be read before they are trusted.

Measured on the test gateway, against an unshaped baseline of several
gigabits:

| | |
|---|---|
| Link held to a 46.5 Mbit/s pipe | 44.9 Mbit/s |
| Two flows, weights 70 and 5 | 93% and 7% of the link |
| A rule capped at 10 Mbit/s | 9.7 Mbit/s |

Three things had to be got right for any of that to work, and each looked
fine while wrong. A queue named on a rule that specifies a direction applies
only to that direction, so each rule needs a partner on the reply. Dummynet's
fast path is off by default, and without it the engine dropped 4.6 percent of
every packet it handled, which held a 14 Mbit/s pipe to 4.6 Mbit/s of real
throughput. And a pipe's buffer has to be sized to the rate it carries, or
TCP is throttled by loss long before it reaches the limit you set.

Shaping is off by default and has to be switched on deliberately.

## 0.9.8r202609220914

**Inspecting everything no longer discards your bypass lists.** Turning on
**inspect everything that crosses the firewall** created a policy covering
every local network whose only exemptions were the exclusions and the names
found to pin. The domains you had put on a policy's bypass list, banks,
password managers, anything you had decided must never be decrypted, applied
only to the devices that policy named. So switching the setting on started
decrypting those names for every other device on the network.

That was backwards. Widening who is inspected must not narrow what is
protected: a bank is not something to start decrypting for the tablet
because it was only ever named on the laptop's policy. Every bypass list in
the document is now honoured when inspecting everything, along with the
exclusions and the pinned names, with duplicates collapsed.

On the gateway this was the difference between 35 protected names and 196.

## 0.9.8r202609220830

**Sites that could be inspected were being marked as pinned and relayed.** The
detector treated any bumped CONNECT that carried no bytes as the client
refusing the certificate. The proxy writes that line the same way whether the
client accepted it or not, and then logs the requests made inside. So a
perfectly ordinary decrypted session looked identical to a refusal, and
working sites were added to the bypass list and spliced from then on, quietly
costing inspection coverage on exactly the sites where it was possible.

A bumped connection is now judged by what follows it: a request inside the
tunnel means the client accepted the certificate, and only a connection that
carries nothing for fifteen seconds counts as a refusal. The entries found
with the old test are cleared once at startup. Names that genuinely pin are
detected again within minutes; the rest stop being relayed for no reason.
Entries you added by hand are untouched.

## 0.9.8r202609220812

**Turning deep inspection's settings on now takes effect at once.** The policy
compiler skips its work when nothing it depends on has changed, and the list
of things it depends on did not include the deep inspection module. So
switching on **inspect everything that crosses the firewall** appeared to do
nothing: the setting saved, the page showed it on, and the proxy carried on
with the old configuration until some unrelated change happened to force a
rebuild, which could be ten minutes later. The module is part of that list
now.

## 0.9.8r202609220752

**Data out tells serving apart from reaching out.** A media server streaming
three gigabytes to someone watching from outside has really sent three
gigabytes, and it is not data leaving in the sense anyone means by it. The
firewall records who opened each connection, so those rows are now marked
**serving**, left out of the totals and never alerted on. Only connections a
device here opened count as data leaving.

**A destination is asked about before it is called nameless.** Naming used
only the server names seen in handshakes and the answers to DNS queries, so a
destination reached by address alone looked anonymous when it answers to a
perfectly ordinary name. The reverse lookup is now the last resort before
anything is reported as unnamed, which is the loudest thing this page says.

**Broadcast and multicast are not egress.** Traffic to a broadcast address, a
multicast group or a link-local address never leaves the network and is no
longer counted or listed.

**The sampler no longer reads the database.** Naming meant scanning two tables
that grow all year, on the same job as the sample, which made a five-second
sampler take twelve seconds on a real gateway. Naming is now its own job on a
minute, the sample is pure parsing, and there is an index behind the lookup
that needed one. A sample takes about fifty milliseconds.

## 0.9.8r202609220741

**Data out: what is leaving the network, while it leaves.** A new page and a
new module under Security. Everything else in FlowSight reports what
happened; this reports what is happening, because a transfer you read about
tomorrow is a transfer that already finished.

It does not read logs. It samples the firewall's own connection counters
every few seconds, which means it sees what no inspection can open: sessions
whose certificate is pinned, spliced sessions, QUIC on UDP 443 that never
reaches the proxy, and encrypted tunnels. None of those can be decrypted and
all of them can be measured. Each row is one live connection with the device,
the destination and the name FlowSight can put to it, the current upload
rate, the totals and how long it has been open. **Stop** drops the connection
at the firewall while it is running.

Destinations are grouped by what would change your mind about them: cloud
storage, file transfer and paste sites, code hosting, personal mail,
messaging, AI assistants, remote access, backup, media, telemetry, content
delivery, encrypted tunnels, and **unnamed**. Unnamed means no DNS answer, no
server name in any handshake and no reverse lookup could name the place the
data is going, which makes it the row most worth reading.

Thresholds raise an event mid-transfer: a volume of data sent, a sustained
upload rate, a session that has sent several times what it received, the
first time a device reaches a kind of destination it never has before, and
anything going somewhere unnamed. A quiet-hours window raises the severity of
anything flagged inside it. Events are published to subscribers, which is the
seam a later module will use to act on them rather than only report them.

**Reading the counters the wrong way round would have reported every download
as an upload**, so the direction is pinned by test against a real capture from
the gateway, including the case that matters most here: an intercepted session
names the proxy's own loopback address as one end, and treating that as the
local device silently discarded every inspected session.

## 0.9.8r202609220723

**A certificate opens where you are looking.** Inside the OPNsense panel the
FlowSight page has no scrollbar of its own and can be many screens tall, so a
dialog pinned to the top of that page opened far above whatever you had
scrolled to, and you had to scroll up to find it. Dialogs now open over the
part of the page that is on screen, and follow it if you keep scrolling.

## 0.9.8r202609220648

**Deep inspection, for the Business tier.** A new module reads what a
decrypted session actually carries: the method, the full URL, the response
code, the content type, the size, the timing, and the request headers when
you ask for them. Cookies and authorization headers are recorded as a byte
count and never as a value, and no body is ever stored. It appears as
**Deep inspection** under Security.

The proxy hands each exchange over using ICAP, the protocol squid speaks to
a content adaptation service, and FlowSight answers "no modification", so
nothing is proxied through FlowSight and nothing is altered on the way. It
only ever sees sessions a policy already decrypts: a device without TLS
inspection, an excluded host and a pinned name never reach it.

**DNS-over-HTTPS queries are decoded in full.** A browser that resolves over
HTTPS puts its question in the request body, where a proxy log cannot see
it. Deep inspection reads it and files it in the DNS history like any other
lookup, so the name is visible and attributable to the device that asked.

**Inspect everything that crosses the firewall.** A checkbox in the deep
inspection settings that decrypts every intercepted client rather than only
those a policy names, appliances and televisions included. A device that
does not trust the FlowSight CA fails to connect until the pinned-site
detector notices the refusal and starts relaying that name untouched, so an
appliance you cannot install a certificate on ends up relayed rather than
broken. Excluded hosts are never touched.

**Certificate names are recorded whole.** A distinguished name contains
spaces, and the proxy was logging subject and issuer unquoted, so every name
was cut at the first space: "Let's Encrypt" became "Let's", and the rest of
the name was read as the start of the next field. The names are now logged
in quotes and parsed accordingly. The inventory rows recorded under the old
format cannot be repaired and are cleared once, at startup; the proxy
rebuilds them from the next handshakes it sees.

**The certificate inventory is filled in.** FlowSight now opens a TLS
connection to the server names it has seen and records what is served:
validity dates, key type and size, signature algorithm, serial,
alternative names, fingerprint, and whether the chain verifies against the
system roots. That is what makes the TLS page's **Key**, **Expires** and
**Flags** columns real rather than empty, including for spliced sessions
whose certificate the proxy never sees. It runs every fifteen minutes, a few
names at a time, and can be switched off.

**Certificates open.** Click any row in the TLS inventory for the whole
certificate: both distinguished names unabbreviated, the serial, the key,
the validity with the days remaining, the fingerprint and every subject
alternative name.

**The TLS page is less crowded.** Two donut charts took a third of the
screen to say that nearly everything is TLS 1.3. Protocol version and
session handling are now two proportion bars in one card, which leaves the
issuer chart the room it needed.

## 0.9.8r202609220621

**The updater no longer times out on a large download.** A thirty-second
limit covered the whole transfer, so a fourteen-megabyte binary failed with
a deadline error on any ordinary connection. The limit now applies to
connecting, to the TLS handshake and to the first response header, where it
belongs.

## 0.9.8r202609220614

**DNS over HTTPS is recovered where inspection can see it, and can be shut
off where it cannot.** A DoH request made with GET carries its question in
the URL; that question is decoded and filed in the DNS history. A new
built-in category, **encrypted-dns**, lists the public DoH endpoints along
with the canary name that makes Firefox turn DoH off by itself, so denying
that category sends a client back to the network resolver where every
lookup is visible again.

## 0.9.8r202609220604

**Pinned sites are detected and relayed instead of failing.** A client that
pins its certificate refuses the inspection certificate, and the site simply
does not load. FlowSight now recognises that refusal from the shape of the
failed handshakes, stops decrypting that name and relays it untouched, so
the site works while everything else stays inspected. Detected names are
listed on the TLS page with how many times they refused and which clients
were affected, can be added and cleared by hand, and are retried after a
week in case an application stopped pinning.

## 0.9.8r202609220559

**One scrollbar inside the OPNsense panel.** Tables had a fixed height and
their own scroller, which fought with the host page's scrollbar and produced
a scroll that went nowhere. Embedded tables now grow with the page.

## 0.9.8r202609220546

**A refresh keeps your place.** Sort order, scroll position and how much of
a long table you had loaded now survive the automatic refresh, and there is
a pause button for reading something that keeps moving. Long tables are
paged with a "show more" control, or continuous scrolling if you prefer,
and the choice is remembered.

**An IPv6 address belongs to its device.** Addresses learned over IPv6 are
attributed to the same device as its IPv4 address rather than appearing as a
separate unknown host.

## 0.9.8r202609220530

**Decrypted requests are visible as such.** The Web page shows the request
line for decrypted sessions and offers a decrypted-only view, reachable from
the TLS page by clicking the bump marker on a session.

**Issuer names are readable.** The issuer chart showed full distinguished
names, which do not fit; it now shows the organisation with the full name on
hover.

**Assets are versioned.** The interface is served under a version directory,
so a browser cannot keep yesterday's script after an update.

## 0.9.8r202609220505

**FlowSight lives in the OPNsense panel, not beside it.** The extra panel is
gone, the name is spaced like every other entry in the menu, and the theme
follows the host's light or dark setting.

**Rollups are keyed to when traffic was observed**, not to when FlowSight
got round to aggregating it, so a graph no longer shows a spike where a
restart was. Chart labels are drawn as text in their own gutter rather than
inside the plot.

## 0.9.8r202609211728

**The effective local networks list has no repeats.**

## 0.9.8 — 2026-09-21

**Pi-hole as a DNS source.** A module that pulls query logs from one or more
Pi-hole instances, parses them and associates each query with the device
that made it. Blocked queries appear on the host pages with the list that
blocked them and the resolver that answered.

**Hosts and Devices are explained** on the page and in the guide: a host is
an address FlowSight has seen, a device is a thing it has identified.

**Devices and Zones are two pages**, cross-linked, with reverse-lookup and
country lookup available for any address.

**Settings show the platform default** beneath an empty field, so you can
see what is in force without the value being silently written into your
configuration.

**Throughput separates inbound from outbound.**

**The manual.** Fourteen chapters covering installation, concepts, policy,
interception, configuration, the API, operations, security, licensing and
architecture, shipped as HTML, one PDF per chapter and a single merged PDF,
inside the packages.

## 0.9.4 — 2026-09-20

**Licensing.** Community, Pro and Business tiers, online activation against
a license server with signed offline license files as the fallback, and a
soft expiry that warns rather than switches features off.

## 0.9.3 — 2026-09-20

**Release pipeline.** Signed release manifests, an injectable signing key and
per-architecture package names, so the daemon can verify and install its own
updates.

## Earlier

Before 0.9.3 FlowSight was assembled rather than released: the Go daemon and
its module contract, the embedded store, identity and enrolment, DNS
visibility and enforcement, transparent interception with peek-and-splice,
the inspection CA, category feeds, firewall hygiene, alerting, reports and
the OPNsense plugin. The commit history is the record of that period.
