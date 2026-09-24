# Security

What FlowSight exposes, who can change what, how keys are handled, and
what data it keeps. Written for the person who has to sign off on running
it on a gateway.

## Attack surface

- **The daemon listens on loopback only** (`127.0.0.1:8080`) unless `bind`
  is changed in the configuration file, which only root can do. On
  OPNsense it is reached through the GUI, which authenticates the user and
  proxies with the session's CSRF token and a same-origin check; the
  proxied request carries the GUI user's name so the audit log names
  people. Elsewhere, reach it through a reverse proxy you control or bind
  it to a LAN address and rely on the API token.
- **Writes pass one gate.** Every state-changing route requires the header
  `X-Requested-With: Flowsight` (a browser cannot add it cross-site) and,
  from anything other than the OPNsense GUI or loopback, the API token.
  Reads from loopback need nothing.
- **Some keys are locked**: `bind`, `port`, `api_token`, `data_dir`,
  `paths` and every setting that names a binary can only be changed in the
  configuration file. Whoever can change where the daemon listens or what
  it executes is root; the API is not.
- **Content Security Policy** on the UI forbids inline scripts and any
  external resource; the UI ships no third-party code and loads nothing
  from the internet.
- **The block page and captive page** listen on the LAN (ports 8082 and
  8083 by default) and serve static explanations only.
- **The proxy** listens on loopback and, for IPv6, on one LAN address you
  choose; it accepts only redirected (intercepted) connections and one
  plain forward port on loopback for its own internal URLs. It is not an
  open proxy.

## What runs as root and why

`flowsightd` runs as root because it writes the resolver's include files,
manages a squid instance, and loads pf anchors. It drops nothing it does
not need: squid itself runs as the `squid` user in the `proxy` group (the
group that may read `/dev/pf`). The license server (`flowsight-licensed`)
runs as its own unprivileged user.

## Keys and certificates

- **Inspection CA (Pro).** An EC P-256 key pair generated on the firewall
  when you create it, stored under `<etc>/tls/` readable by root and the
  proxy only. It never leaves the box; you download the certificate, not
  the key. Deleting the CA deletes the key. Only devices whose policy has
  inspection on and that trust the certificate are ever bumped; every
  other session is spliced and never decrypted. Bypass lists exempt names
  you must never inspect.
- **Release signing key.** Release binaries carry the ed25519 public key;
  the updater applies only assets whose sha256 is signed by it, and only a
  version newer than the running one. The private key lives with the
  maintainers and is not in the repository.
- **License key.** Release binaries carry a second public key; licenses
  are documents signed by the license server's private key. A build without
  the keys refuses updates and runs Community.
- **API token.** Generated at install on Linux (printed once and stored in
  `flowsight.json` with mode 600); empty on OPNsense where the GUI is the
  door. Rotate by editing the file and restarting.

## Data kept, and what leaves the box

FlowSight keeps, in one SQLite file on the gateway: hosts (addresses,
MACs, names, vendors), flows (who talked to what, how much, which
application), DNS queries and answers, web requests (client, host name,
category, bump mode; never bodies), TLS session metadata and server
certificates, IDS alerts, findings, events, and the audit log. Retention
is configurable and capped by tier; raw rows are pruned daily and rollups
keep aggregates.

Nothing leaves the gateway except:

- category feed downloads (HTTPS GET of public lists; no data sent);
- the release manifest check (HTTPS GET; no data sent);
- online license activation and refresh, when you use it: the activation
  key, the installation id, the hostname, the version and the platform,
  nothing else;
- the country database download when *Country lookup* is on (HTTPS GET
  from DB-IP or the URL you configure, monthly; no data sent), and reverse
  DNS queries through your own resolver when *Reverse DNS names* is on;
  both are off by default;
- Pi-hole query-log pulls, when servers are configured: HTTPS to the
  Pi-holes you list with the app password you give it (read only);
- telemetry export (Business) to the collector you configure;
- notification channels (Pro) to the endpoints you configure.

There is no usage analytics, no crash reporting, no account.

## Decryption, ethically

TLS inspection is a capability with real weight. FlowSight makes it
opt-in per policy, visible (the TLS page shows exactly which sessions were
bumped), bounded by bypass lists, and impossible without installing a
certificate on the device, which is a deliberate act on that device. Use it
on devices you own or administer with the consent their users would
reasonably expect; do not use it on guests. Inspected sessions yield URLs
and certificates for policy and inventory; bodies are not stored.

## Deep inspection, and what it does not keep

The deep inspection module (Business) listens on loopback for ICAP and is
handed each decrypted request and response by the proxy as it passes. It
records what the exchange was: method, URL, status, content type, size,
timing, and request headers when that is switched on. Cookies and
authorization headers are recorded as a length, never a value. Bodies are
read only by the decoders that are switched on, up to a byte limit, and are
discarded immediately; there is no setting that keeps a body, and none will
be added. FlowSight always answers "no modification", so no traffic is
routed through it and nothing it sees is altered. It never receives a
session a policy has not already decrypted, nor an excluded host, nor a
pinned name.

The **inspect everything that crosses the firewall** checkbox widens that
last sentence: with it on, every intercepted client is decrypted rather than
only those a policy names. Nothing else changes, exclusions and pinned names
are still never touched, but it is the widest-reaching setting in the
product and should be turned on deliberately, on a network whose users would
expect it.

The certificate probe opens outbound TLS connections from the firewall to
server names the network has already contacted, in order to read the
certificate served. It sends no request, carries no client identity and
never contacts a name the network has not. It can be switched off in
*Settings › tls*.

## Live egress monitoring

The egress module runs `pfctl -ss -v` on an interval and reads the byte
counters pf already keeps for every open connection. It reads state; it does
not add rules, change the ruleset or touch any traffic. The one action it can
take is **Stop**, which drops a single connection's state and is taken only
when an operator asks for it on the page.

Because it measures rather than decrypts, it sees connections no inspection
can open: pinned sessions, spliced sessions, QUIC on UDP 443 and encrypted
tunnels. It learns nothing about their contents and claims nothing about
them. For a tunnel it says so plainly on the finding: the volume, the far end
and the timing are the whole of what is knowable.

Addresses are named from what FlowSight already holds, the server name in a
handshake and the answer to a DNS query. No external service is consulted to
name a destination.

## Hardening checklist

- Keep the daemon on loopback; reach it through the OPNsense GUI or a
  reverse proxy with authentication.
- Back up `<etc>/tls/` if you use inspection, and treat the backup as the
  secret it is.
- Review the audit log (Events › Audit) after handing the GUI to someone
  else.
- Keep enforcement in monitor for a day when introducing a policy on a
  network you do not fully know.
- Update from the Updates page; the signature check is what makes that
  safe.

## Reporting a vulnerability

Write to <flowsight@grio.co>. Please include the version (System page),
the platform, and steps to reproduce. Fixes ship as signed releases and
the release notes name the issue once a fix is out.

## Fetching operator-supplied URLs

Two settings under *paths* take URLs: the submarine cable map and the
land-route sources. A daemon that fetches whatever URL it is given is a proxy
into the network it sits in -- the router's own administrative interface, a
hypervisor's management port, a printer, the cloud metadata address at
169.254.169.254 -- and the person entering the URL need not be the person who
owns the network.

Those fetches therefore go through a client that:

- accepts only `http` and `https`, with no credentials in the URL;
- resolves the host and **refuses to dial** any address that is loopback,
  private (RFC 1918, ULA), link-local, carrier-grade NAT (100.64/10), the IETF
  protocol range (192.0.0/24), multicast or unspecified;
- applies that check at dial time, after resolution, so a redirect or a name
  that resolves differently on the second lookup cannot lead it somewhere
  private;
- follows at most five redirects, each re-checked;
- ignores proxy environment variables, so the operator's URL is the whole of
  the request;
- reads at most 64 MB and replaces the local copy only once the whole file has
  arrived.

Addresses read from a traceroute are parsed as IP addresses before they are
used as a cache key, a name to resolve, or a path component in a request to a
public service; an AS number must be digits before it is placed in a URL.
The fixed public services asked -- RIPE IPmap, rdap.org, PeeringDB, Team Cymru
over DNS -- are asked at bounded rates and their answers cached for weeks.

## Runtime profiles

`GET /api/system/profile` returns a Go runtime profile -- heap, allocations,
goroutines, or a few seconds of CPU sampling -- for reading with `go tool pprof`. It sits behind the same access
as every other `/api/system` route. A profile is stack traces and byte counts;
it does not contain the flows, names, addresses or keys the daemon holds, and
it can be handed to support without redaction. A heap profile forces a
collection first, at most once every five seconds.

## Proxy configuration

Everything FlowSight hands to squid is generated; nothing operator-typed
reaches the configuration unchecked. Client-address lists are validated as
addresses or CIDRs and written to files one entry a line, domain lists
likewise, so neither a malformed entry nor a long list can leave the proxy
with a configuration it refuses. A rejected configuration is kept beside the
live one as `squid.conf.rejected` for inspection, and the proxy keeps running
on the last one it accepted.

## Operator-supplied route files

Cable and land-route sources are URLs the operator chooses. Each is fetched
through the public-only client, capped at 64 MB on the wire and 256 MB after
inflation, and stitched into networks in memory. A source that stitches to
more than two million edges is refused -- left on disk, reported on the
*Data sources* card, not held -- so a hostile or merely enormous file cannot
push the daemon's heap past what the gateway can carry.
The OpenStreetMap source is a POST to the configured Overpass endpoint through
the same client, carrying only the fixed query for one region; the answer is
capped at 64 MB and converted before it is kept.
