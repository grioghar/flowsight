# User guide

Every page of FlowSight, in the order of the menu. The range buttons at the
top (1h, 6h, 24h, 7d, 30d) set the window for every page that shows
history; the search box takes an address (opens the host), a domain (opens
its sessions) or free text.

Inside the OPNsense GUI there is one scrollbar, the page's own: tables grow
with their rows instead of scrolling inside a box. Standalone, a long table
keeps its own scroll area.

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

Each row under *Top sites* carries a *map* link: the route, on the Map page,
to the endpoint that served the site (the one with a measured route where
there is one, else the busiest). A dashed link means the map has not traced
that endpoint yet; it will when it can.

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

**DNS over HTTPS.** A client that resolves through a provider over HTTPS
bypasses the network's resolver, and those lookups are invisible. Two things
help. With TLS inspection on for that device, FlowSight reads the request:
a client using the GET form puts the question in the URL, so the name is
recovered and appears here like any other lookup, marked *DoH provider* in
the *Via* column; a client using POST (Firefox and Chrome do) keeps the
question in the body, which the proxy log does not carry, so only the fact
of a DoH request to that provider is recorded. To get every name back, deny
the built-in **encrypted-dns** category in a policy: it holds the public DoH
endpoints and Firefox's canary name, which turns Firefox's own DoH off, so
clients fall back to the resolver where everything is visible.

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
- **Versions and handling**: two proportion bars, one for the protocol
  version negotiated and one for what FlowSight did with the session
  (peeked, spliced, decrypted, terminated). Hover a segment for the count.
- **Certificates seen**: every server certificate observed by the proxy or
  the IDS, with subject, issuer, validity, key type, first and last seen,
  and the hosts that saw it. **Click any row for the whole certificate**:
  both distinguished names unabbreviated, the serial, the key, the validity
  with days remaining, the fingerprint and every subject alternative name.
  Findings flag expired, expiring, self-signed and weak certificates.
- **Where the details come from.** A proxy log names a certificate by its
  subject and issuer and nothing else, and a spliced session shows no
  certificate at all, so the validity, key and trust columns would be empty
  for most names. FlowSight fills them in: for server names it has seen and
  knows too little about, it opens a TLS connection from the firewall, reads
  what is served and records the whole record, including whether the chain
  verifies against the system roots. That runs every fifteen minutes, a few
  names at a time, and is *Settings › tls › Probe certificates*.
- **Sessions**: recent TLS sessions with SNI, version, bump mode.
- **Pinned sites**: names whose clients refuse the inspection certificate.
  A pinned client carries the certificate it expects and accepts no other,
  so no proxy can decrypt it; FlowSight recognises the refusal, relays the
  name untouched from then on so the site keeps working, and still records
  its server name, timing and volume. The card lists what was detected and
  what you added by hand, lets you add a name, and lets you put one back
  under inspection. The behaviour is *Settings › web › Relay pinned sites
  without inspecting*, on by default, with the number of refusals, the
  window and the retry interval beside it.

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

### Map (Pro)

Where traffic actually goes, measured rather than assumed. Everything else in
FlowSight watches the first hop; this traces the rest of the route and keeps
what it finds.

**It only traces what you already talk to.** Destinations come from your own
flow history, a few per run on a timer. Nothing is probed that this network
has not already contacted, and addresses inside the network are skipped
because they have no route worth drawing.

**A path belongs to a destination, not to a device.** Everything leaves
through the same gateway, so the route to a given address is the same
whichever device asked for it. Filtering by device is a join: it shows the
routes used by the destinations that device has talked to, without tracing
anything extra.

**Clicking a hop lights the routes through it**, and dims the rest. A dashed
grey leg means the route continues through hops that could not be placed: the
traffic went that way, but where it was in between is unknown, so it is not
drawn as though it were one router to the next.

**Shared legs are drawn once.** Every route out of your network starts the
same way, and drawn literally that is a hundred lines on top of each other. A
leg used by several destinations becomes one thicker grey line carrying them
all; coloured lines belong to a single destination. Where one position
answers from several addresses, which is how a carrier balances across
parallel links, that is one point carrying several addresses rather than
several points.

The map is drawn two to one, the world's own proportion, so zoomed out it
shows pole to pole and fills its frame exactly. The hop detail sits beside it
and the route beneath it, so nothing you click scrolls what it fills out of
view. On a screen wider than about 1750 pixels the tables move into a second
column beside the map, and the whole page is one screenful. *About this map*
under it unfolds the notes on where the land and cable data come from and what
the map does not claim. The key sits in
the map's bottom corner and stays there at any zoom; fold it away with *Key*
if it is covering something.

**One route at a time.** Click a destination in the table and the page draws
that route as a trail under the map, left to right, one step per link: the machine on your
network that made the connection, your gateway, each carrier router in turn,
and the address reached, marked as the endpoint. Hovering a step lights up its
dot on the map and opens its detail; the route's legs are lifted out of the
rest and the others dimmed rather than hidden, because a route means little
without the routes it diverges from. *Show every route* goes back.

Clicking a step travels to it: the map slides to that hop at the zoom you are
already using, so you can see which way the route went. Clicking the last step
frames the whole route instead, zoomed to fit it rather than to the world.

You are drawn on the map, and the chosen route reaches you. Your machine and
your gateway answer on private addresses nothing can place, so the first
stretch -- from you to the first hop anyone can locate -- is drawn as the
estimate it is, and says how many unplaceable hops it covers.

The trail begins inside your network rather than at the first router that
answered, which is where a traceroute's own output starts. Where more than one
device used the route, the one with the most flows to that destination is
shown, or whichever you are filtering on. A hop that never answered keeps its
place, drawn hollow: the traffic went through it even though nothing replied.

**The map wraps.** It slides east and west without end; pan past the edge and
the land, cables and routes continue rather than stopping at a seam. Distances
are measured the short way round, so a leg between two points either side of
the antimeridian is drawn as the short hop it is instead of a line across the
whole map, and a route from here to Asia runs west across the Pacific, which
is the way the packets went. A key to the marks sits under the map.

**The key is a set of switches.** Click any entry to turn that thing off and
click again to bring it back; the choice is remembered. *Operator known* and
*the route you picked* switch the emphasis rather than hiding anything. *Size
endpoints by traffic* is a mode rather than a layer: off unless you ask, it
grows each endpoint's ring by how much went there over the last day.

**What feeds the map.** The *Data sources* card lists each source and what it
has produced -- positions measured by RIPE IPmap this session and how many are
queued, cables and land routes loaded, any fetch error. The switches
themselves are under *Settings › paths*, grouped as *Tracing*, *Where
things are* and *What the latency proves*.

**A selected route shows what each leg cost** -- the difference in round trip
between one hop and the next -- written along the leg with the hop it arrives
at, as `#4 · 13 ms`, so a label on the map and a step in the route below name
the same thing.

**Your view survives the page's own refresh.** Where you are on the map, what
you have narrowed to and which hop is selected all persist; changing route,
device or filter starts fresh.

**Clicking a hop narrows the map to the routes through it.** Everything else
is taken away rather than dimmed, and a chip above the map says how many
routes remain and through which hop; its &times; puts everything back. The
matching step in the route below is highlighted and scrolled into view, and
hovering a step lights its hop on the map, so the two always agree about which
hop you are looking at.

**Click a hop to go to it, and click it again to come back.** The map opens
showing the world pole to pole; a click travels in to the hop you picked, a
second click on the same hop returns to the whole world, and moving the map by
hand clears that so the next click travels again. *Reset zoom* also returns.

**Filters** on country, latency, distance in hops and device. Choosing one
applies it; there is no Apply to press. *Clear* goes back to everything. Wheel to zoom,
drag to pan, and *Reset zoom* to go back. On a touchscreen or with a pen, one
finger pans and two pinch to zoom; a two-finger drag does both at once. A tap
still opens the hop under your finger rather than being swallowed by the map.

Zooming scales the map, not the marks on it. Coastlines and routes grow, while
line thickness, hop markers and the grid's labels hold their size on screen, so
zooming in separates hops that overlapped rather than merging them into a
larger blob.

The device filter is a list of devices, not a box for typing an address, and
it has one entry per device however many addresses that device holds.
Choosing one covers all of them: a laptop with an IPv4 lease and half a dozen
rotating IPv6 privacy addresses is one thing to filter by, and filtering on
whichever address happened to be handy would show a fraction of where it has
actually been.

**What each hop tells you.** Click any point on the map. The panel to the
right of it gives, in this order and under these headings:

- *Measured* -- the round trip, and where the hop falls in the route. This is
  observation; nothing else on the card is.
- *Resolved* -- the router's own name, from reverse DNS.
- *Endpoint* -- if the hop is one. An endpoint is an address this network was
  talking to; every other hop is a router it crossed on the way. Endpoints
  carry a ring of their own on the map, show how much was received from and
  sent to them over the last day, and clicking one opens the whole journey to
  it.
- *Position, measured* -- where RIPE's IPmap puts the address, worked out by
  measuring it from thousands of probes rather than by looking it up. This is
  the only source here that is measurement rather than paperwork, and it
  outranks the address database. FlowSight asks about twenty addresses a
  minute and keeps each answer for a month.
- *Site, read from the router name* -- carriers write the site into the
  hostname. `po1.owr03.lax31.ntwk.msn.net` says Los Angeles; `ae10.edge1.dal2.
  sp.lumen.tech` says Dallas; `172-11-154-1.lightspeed.tpkaks.sbcglobal.net`
  says Topeka, Kansas. Shortened forms are read too -- `palo-bb4` for Palo
  Alto, `kanc` for Kansas City, `sjo` for San Jose.

  Those shortenings are ambiguous, so nothing is decided on the name alone.
  Every reading is a candidate and the round trip settles them: a name cannot
  place a hop somewhere light could not have reached in the time measured. The
  card gives a confidence and says what decided it. A published code the
  measurement supports scores near 100%; a contraction the measurement merely
  fails to contradict scores lower, and below 70% it is shown but does not
  overrule the address database.
- *Who runs it* -- which network announces the address today, taken from the
  public routing table, plus the registry's record of the allocation: the
  regional registry, the date, the allocation's name, and who it is
  registered to. The registrant's postal address is shown and is marked *head
  office, not this router*, because it is. Every Lumen router in the world is
  registered to one building in Monroe, Louisiana.
- *Buildings this operator occupies in <city>* -- real street addresses, from
  PeeringDB, where operators publish which data centres they are in. This
  appears **only** once the router's name has already given away the city, so
  the list is short and about this hop. When the city is unknown the heading
  changes to say the list is not narrowed, because then it is simply
  everywhere that operator is and proves nothing about the hop in front of
  you. Even narrowed it is a short list, never one answer: an operator
  publishes which buildings it occupies, not which rack answers a traceroute.
- *Placement* -- where the point is drawn and which of the above decided it.

**Corrections are shown, not made quietly.** Where a router's name contradicts
the address database, the name wins and an amber dashed line runs from the
position the database gave to the position now used, with a small ring on the
abandoned one. The card quotes what the database claimed and how far off it
was. This matters more than it sounds: Microsoft answers from a range the
RIPE registry holds, so an address database places its Los Angeles routers in
London, seven thousand miles out, and the latency check cannot catch it
because London is a perfectly plausible distance from Kansas at 134 ms.

Looking anything up over the network is optional -- *Settings > paths > Look
up who runs each hop* and *List buildings the operator occupies*. Reading the
site out of a hostname is free and always on. Results are kept for a month,
because allocations outlive most networks and buildings do not move.

**What the map does not claim.** Land outlines are drawn from Natural Earth's
public-domain 1:110m data, so you can tell Kansas from Kazakhstan. They are
not a claim about precision: coordinates come from an address database that is
dependable for end-user addresses and rough for carrier equipment, and a
router often resolves to wherever its address block was registered rather than
where it sits. That is what the hostname reading above is for. Hops with no coordinates are listed
underneath rather than placed at zero, which would pile a stack of routers
into the Gulf of Guinea. Hops that never answered are counted and not drawn
at all, and they keep their position in the numbering so the path is not
quietly reported as shorter than it is.

**Your location.** The map is drawn from an origin, and that origin is also
the reference for the one check that can prove a placement wrong. Left alone
it is worked out from the gateway's own public address, which is usually the
right town and occasionally the wrong state, because it is where the carrier
registered the block rather than where the wire ends. The page can fill it in
from your browser, which knows precisely and asks your permission first, or
from the public address, or you can type it. It is also *Settings › paths ›
Your location*.

The card shows the gateway's own public addresses, IPv4 and IPv6, beside those
coordinates, and marks which one the coordinates were worked out from. On a
dual-stack line that is always the IPv4 address: the two families geolocate to
different places, and an origin that changed between restarts would quietly
move the line between a placement being ruled out and one standing.

**Hops put between their neighbours.** A router that answers but has no
coordinates anywhere used to be left off the map, so a route appeared to jump
from one country to the next with nothing in between. Those are now placed
between the two hops either side of them, at the point where their round trip
falls between the neighbours' -- drawn hollow and dashed, and saying on the
card what decided the spot. Hops that never answered at all are still left
off: there is no measurement behind them, and spacing them along a line would
be drawing routers out of nothing.

**Placements too fast for any built route.** Every hop is judged against two
numbers. The floor is what light forbids, and it is a proof. Above it a reply
is not disproved -- but it can still be quicker than any route anyone has
built, and the only thing that makes a reply quicker is the place being
nearer. Those are listed separately and marked with a dashed amber ring rather
than a solid red one: doubted, not disproved.

Note the direction. Being *slow* is never suspicious -- congestion, queuing
and indirect routing all make a reply late and all are ordinary. It is being
too fast for where the hop is said to be that means something.

The second number allows for fibre not going straight overland (*Settings ›
paths › Fibre on land runs longer than the crow flies by (%)*, 35% by
default), for a sea crossing being as long as its cable, and for the moment
each router spends receiving a packet before passing it on. Zero turns the
category off.

**Land-route maps.** With *Use published land-route maps* on, FlowSight
downloads open maps of long-haul fibre and measures along them where they
reach rather than estimating the detour, refreshing monthly. These never raise
the impossible threshold: over water a cable is the only way across, so its
length is a real bound, but on land a straight line is merely something nobody
built. Coverage is thin -- AfTerFibre covers Africa under a Creative Commons
licence and is the one substantial open set; the comprehensive maps of North
America, Europe and Asia are sold commercially. Sources are a list of URLs, so
adding one later is a line of configuration. OpenStreetMap's telecom lines
are a second, weaker source: fetched region by region from the Overpass API,
they count at half weight -- the expected time is the average of following
the line and the plain detour -- because they are mostly the visible kind of
line and rarely the buried long-haul a packet rides. Road-traced files are thinned to
the points that change a route's shape by more than a kilometre before use,
so a large one costs a second or two to load rather than a core for a day.

**Clicking a hop opens its route.** Any hop not on the chosen route loads the
route it belongs to, busiest first when there are several, with the hop
selected; the chip above the map then reads *route 1 of N through …* with
*next ›* to step through the others. A hop on the chosen route zooms in, and
again to zoom out.

**Direction and the route table.** Each leg carries an arrow pointing the
way the packets went; *direction of travel* in the key switches them off.
With a route chosen, a table in the map's top-right corner lists every step
from the machine inside the network to the endpoint -- name or address, place,
round trip -- and each row marks its hop on the map, travels to it on click,
and frames the whole route from the endpoint. Both the key and the table fold
to their titles.

**Devices, not addresses.** A device is known by its hardware address; every
IP it has held is grouped under it, IPv4 and IPv6 alike. Which addresses it
holds *now* is remembered for a day (*Settings › identity › Remember a
device's addresses for*), because IPv6 privacy addresses rotate; which device
an address *belonged to* never expires, so traffic sent from an address a
device has since dropped still counts as that device's, and the device list
and route trails name it rather than showing a bare IPv6 address.

**What the database gets wrong is remembered.** The address database places
a block where it was registered, and for a carrier that is a head office. When
a router's own name or a RIPE measurement puts a hop more than 500 km from
there, the map learns two things: that the hop's announced prefix is where the
evidence says -- other addresses of the prefix follow it, drawn as *corrected*
with the router and date on their card -- and, once two routers of one network
have been shown away from the same database coordinate, that the coordinate is
the registrant's and not to be believed. Nothing is learned from a placement the
hop's own round trip could not have reached -- an anycast address is measured
wherever most probes see it -- nor recorded against an aggregate broader than
a /16. A hop the database would put there is
left for the timing to place, with the reason on its card, rather than drawn
at a head office on the wrong continent. The *Data sources* card counts both;
`/api/paths/corrections` lists them and lets any be forgotten. *Remember what
the database gets wrong*, under *Where things are*, turns it off.

**Placements the physics rules out.** This one is geometry rather than a guess
about routing: no path between two points is shorter than the straight line
over the earth's surface, and nothing in fibre beats about 200,000 km per
second. Twice that distance divided by that speed is therefore a bound no
route of any kind can undercut -- not the shortest route FlowSight could find,
but the shortest that could exist. A reply that beats it means the coordinates
are wrong, because the round trip is the one thing here that was measured
directly.

The floor is taken from the nearest point your own origin could honestly be
(*Settings › paths › Your own position could be wrong by*, 100 km by default,
and nothing if you declared your location). A shortfall thinner than that
uncertainty is not counted: calling a placement impossible on a margin
narrower than the error in your own position would be claiming a precision
nobody has.

Between continents that distance is measured along the cables rather than
across the map. Cables follow continental shelves, skirt trenches and come
ashore where there is a station, so the real journey is longer than the
straight line and the floor correspondingly higher. FlowSight takes the
shortest published route joining the two places, counting the run ashore at
each end, and names it in the tables and on the hop card. Under 1,200 km the
straight line stands, because that trip is made on land; a cable route more
than twice the straight line is ignored as a different journey. The bound is
never lowered below the straight line. This needs *Show submarine cables* on.

A leg that crosses an ocean is drawn along that cable rather than straight
across the map, bending where the cable bends. Hovering it names the cable and
gives both distances, the route and the straight line. FlowSight is reading
the evidence, not reporting a fact: a traceroute never names a cable, so this
is the shortest published route that fits the two ends and the latency. A hop that
answers faster than that floor is not where the database says it is, and the
map circles it and lists it with the numbers. On a typical network several
hops fail this: anycast addresses are the usual cause, because the block is
registered in one place and answered from wherever is nearest you.

**Submarine cables.** With *Settings › paths › Show submarine cables* on,
FlowSight fetches TeleGeography's published cable map and draws it behind the
routes. Hovering a leg long enough to have left the continent lists the cables
that could have carried it.

Could, not did. A traceroute gives router addresses and round trips and never
names a cable, so if two places are joined by eight cables then all eight fit
the observation. What can be done is ruling members out, and that part is not
guesswork: light in fibre covers about 200,000 km per second, so a cable
cannot carry a round trip faster than twice its length divided by that. Cables
are long and rarely direct, so this discards a great many candidates outright.
What is left is offered as a list, shortest first, and never as an answer.

The data is fetched by your installation rather than shipped with FlowSight,
and refreshed monthly. TeleGeography publish it as a free public resource but
it is not openly licensed, which is why it is not bundled.

This needs the city-level database, since the country one carries no
coordinates. See *Settings › enrich › How much detail*.

### Devices, zones and IPv6

**A device is one thing, not one address.** A phone has an IPv4 address, one
or more IPv6 addresses, and a MAC that ties them together. Exclusions follow
the device: excluding a range in one address family also exempts the same
devices when they speak the other, because "do not inspect those things over
there" was never meant to apply only to IPv4. On a flat network this matters
more than it sounds, since every device shares one IPv6 prefix and there is
no range to write even if you wanted to.

**Classification rules match on their conditions and nothing else.** A rule's
`when` block is the whole of what it tests, and a condition FlowSight does
not recognise never counts as a match. That last part is deliberate: a rule
that fails open turns one typo into "everything", quietly, and you find out
when every device on the network has been filed under the first rule in the
list.

### Priority (Pro)

The one page that changes traffic rather than describing it. It decides who
waits when the link is full.

**It only works if the bottleneck is here.** When an uplink fills, the queue
that decides what waits belongs to the modem or the carrier, and nothing on
this firewall can reach into it. So shaping starts by sending everything
through a pipe sized a little under what the link really carries, which moves
that queue onto the firewall. That is why the two rates are settings and why
they have to be honest: set them above the real rate and the pipe never
fills, the carrier stays the bottleneck, and every weight below is
decoration. Measure the link, do not copy the figure off the bill.

**Upload matters more than it looks.** A saturated upload delays the
acknowledgements that downloads depend on, so one device pushing hard ruins
streaming in both directions. Downloads can be shaped too, but less crisply:
those packets have already crossed the carrier's bottleneck by the time the
firewall sees them, so the only lever is holding them back until the senders
slow down.

**Rules** are written the way you would say them:

```
192.168.1.178 = low
redgifs.com = high
10.0.5.0/24 = low, 20Mbit
backup.example = 5Mbit
```

The left side is an address, a CIDR or a domain. An address is understood as
a device on this network or as something out on the internet depending on
which side of your local networks it falls, and the rules are written the
right way round either way. A domain matches the addresses this network has
actually been seen using for it, so a name nobody has looked up yet matches
nothing until they do; the page says so per rule rather than leaving you to
wonder.

The three classes are shares, not reservations. A class with twice the weight
gets twice the link when both want it at the same moment, and none of it is
wasted when one does not. A rate on a rule is different: that is a ceiling,
enforced whether anything else wants the link or not.

The page shows the rules, what each one currently matches, the queues and
what they are holding, and the firewall rules the settings would produce, so
you can read them before trusting them.

### Data out (Business)

The one page written in the present tense. Everything else in FlowSight
reports what happened; this reports what is happening, because a transfer
you read about tomorrow is a transfer that finished.

It does not read logs. It reads the firewall's own connection table, which
counts every byte of every open connection and updates as they move, and it
samples that every few seconds. The consequence is that it sees everything:
a session whose certificate is pinned still has a connection, and so does a
spliced session, a QUIC session on UDP 443 that never reaches the proxy, and
a WireGuard tunnel carrying who knows what. None of those can be decrypted.
All of them can be measured.

Each row is one connection: the device, the destination with the name
FlowSight can put to it, what kind of destination it is, how fast it is
sending right now, how much it has sent and received, and how long it has
been open. **Stop** drops the connection at the firewall, which ends the
transfer immediately. The device may open another one; preventing that is a
policy decision and belongs in a policy.

Destinations are grouped coarsely, because the group is what changes what
you would do: cloud storage, file transfer and paste sites, code hosting,
personal mail, messaging, AI assistants, remote access, backup, media,
telemetry, content delivery, encrypted tunnels, and **unnamed**. That last
one is the row most worth reading. It means no DNS answer, no server name in
any handshake and no reverse lookup could put a name to the address the data
is going to.

*Settings › egress* sets which groups raise an event and at what point: a
single transfer above so many megabytes sent, a sustained upload rate held
for so many seconds, a transfer that has sent several times what it
received, the first time a device reaches a kind of destination it never has
before, and anything at all going somewhere unnamed. A quiet-hours window
raises the severity of anything flagged inside it.

What this cannot tell you is what was inside. For the sessions that can be
decrypted, deep inspection reads the request itself. The two are meant to be
read together: this says a device is sending four gigabytes to a cloud
storage provider, and deep inspection says which files.

### Deep inspection (Business)

What a decrypted session carries, not just which server it reached. The
proxy hands each request and response to FlowSight as it passes, using ICAP,
the protocol a proxy speaks to a content adaptation service. FlowSight reads
it and answers "no modification", so nothing is proxied through FlowSight
and nothing is altered on the way.

Each exchange is recorded as the method, the full URL, the response code,
the content type, the size and the timing, plus the request headers when
that is switched on. Cookies and authorization headers are recorded as a
byte count, never as a value. Bodies are read only by the decoders that are
switched on and are never stored.

Today one decoder is shipped: **DNS over HTTPS**. A browser resolving over
HTTPS puts its question in the request body, where a proxy log cannot see
it; deep inspection reads it and files it in the DNS history like any other
lookup, so the name is visible and attributable to the device that asked.

*Settings › mitm* switches it on, sets the loopback port, chooses how much
of each body the proxy sends for decoding, and limits it to particular
clients or names. It only ever sees what a policy already decrypts: a device
without TLS inspection, an excluded host or a pinned name never reaches it.

**Inspect everything that crosses the firewall.** One checkbox decrypts
every intercepted client rather than only those a policy names, appliances
and televisions included. A device that does not trust the FlowSight CA
fails to connect until the pinned-site detector notices the refusal and
starts relaying that name untouched, so an appliance you cannot install a
certificate on ends up relayed rather than broken. Excluded hosts are never
touched. Turn this on deliberately: it is the setting with the widest reach
in the product.

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
country), vendor, zone and last activity. The classification rules decide
each device's zone, and in monitor mode they keep deciding it: edit a rule
and every device it covers moves on the next reconcile (every minute by
default). Choosing a zone from a device's row pins it there, marked
*pinned*, and the rules leave it alone; choosing the empty entry unpins it
and hands it back to the rules. A zone a guest picks on the captive page
pins the device the same way. In enforce mode a device that already has a
zone keeps it, since the zone is an address it holds; only devices without
one are placed. The zone name links to the Zones page, and the zone chips
at the top filter the list. **Mode** (monitor or enforce) is switched here; enforce is
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
