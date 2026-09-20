# How interception works, and what can go wrong

Flowsight owns a squid instance (`flowsight-proxy`) and two pf rules per
interface that send port 80 and 443 from the intercepted networks to it on
loopback. The proxy peeks at the TLS ClientHello for the server name and
splices the connection untouched unless a policy says terminate (denied) or
bump (inspect). Plain HTTP gets a block page for denied names.

## Ordering in pf

pf takes the *first* matching translation rule. NAT reflection, which lets a
client reach an internally hosted service by its public name, is itself an
`rdr`, so the interception rules must come after every port forward or that
traffic is sent to the proxy, which then tries to reach the firewall's own
WAN address and fails. Flowsight's `rdr-anchor "flowsight/*"` is registered
at the tail of the translation rules for exactly this reason. Do not "fix" a
reflection problem with a `no rdr` rule for the WAN address: it excludes the
traffic from reflection too and the failure looks innocent because a `no rdr`
never increments a counter.

## Safety rules the web module enforces

* Redirects are loaded only after squid has parsed its configuration and its
  listeners answer, and withdrawn as soon as they stop answering, so a proxy
  failure cannot take web access down.
* Squid runs with the group that may read `/dev/pf`; without it every
  intercepted connection fails with "NAT lookup failed".
* A domain list is pruned so no entry is a subdomain of another; squid refuses
  such lists.
* A plain forward-proxy port on loopback exists because squid needs one for
  its internal URLs.

## IPv6

Interception of IPv6 needs a listener that is not `::1` (pf cannot redirect
across interfaces to an IPv6 loopback) and a stable address, so the module
expects a unique local address on the LAN when IPv6 interception is enabled.
Until that setting exists, IPv6 web traffic is observed by nDPI and DNS only.

## IPv6

pf cannot redirect LAN traffic to `[::1]`, so IPv6 interception needs an
address the firewall holds on the LAN. Set the web module's
**IPv6 listener address** (`ipv6_listener`) to one, typically a unique local
address (for example a `fd..::1` virtual IP on the LAN). The proxy then also
listens on that address and inet6 redirect rules are generated whose source
is the local-networks table, so clients with global addresses are covered.
Leave it empty and IPv6 web traffic is simply not intercepted (nothing
breaks; it is just not seen).

The local-networks table (`flowsight_local`) lives in the root pf ruleset and
is refreshed by the firewall module every minute; the anchors reference it by
name. Do not define a table of that name inside an anchor: pf would give the
anchor its own empty copy and "to ! <flowsight_local>" would match everything.
