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
