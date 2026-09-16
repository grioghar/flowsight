# Transparent interception

Peek-and-splice interception of client HTTP and HTTPS, so every connection is
recorded with the name it was made to — without decrypting anything.

Squid peeks at the TLS ClientHello to read the SNI, then **splices**: it relays
the original bytes to the original destination and never presents a certificate
of its own. Nothing is decrypted, no client needs to trust a CA, and
certificate pinning is unaffected. What it buys is the hostname on every
session, in `access.log` and therefore on the Hosts, Flows and host-report
pages.

## What it is not

It cannot see inside TLS. It records *that* a client reached
`registry.npmjs.org`, never what was exchanged. Anything requiring content
inspection would need bumping, which means a CA on every device.

## Deploying it

Two pieces, both already present on OPNsense:

1. The proxy plugin with `transparentMode` and `sslbump` enabled, which makes
   squid listen on `127.0.0.1:3128` (HTTP) and `127.0.0.1:3129` (HTTPS) in
   `intercept` mode. Squid must be built `--enable-pf-transparent`
   `--with-nat-devpf` and be able to read `/dev/pf` — it recovers the original
   destination from the NAT state, and without that every intercepted
   connection has nowhere to go.
2. Two NAT port-forward rules on the LAN interface, which the plugin does
   **not** create:

   | | |
   |---|---|
   | source | LAN net |
   | destination | **not** LAN net, port 80 → `127.0.0.1:3128` |
   | destination | **not** LAN net, port 443 → `127.0.0.1:3129` |

## The ordering that matters

**Sequence these rules after every port forward.**

pf takes the *first* matching translation rule, unlike filter rules where the
last match wins. NAT reflection — what lets a client inside reach an internally
hosted service by its public name — is itself an `rdr`. An interception rule
sequenced earlier matches that traffic first and sends it to squid, which then
tries to connect to the firewall's own WAN address, where nothing is listening.

The symptom is stark: one client generated over 900 `TCP_TUNNEL/503` in two
minutes against a single internally hosted host, while ordinary browsing was
fine. Placing interception last leaves reflection to match first and the
failures disappear entirely.

Do **not** try to fix this with a `no rdr` bypass for the WAN address. That
excludes the traffic from translation altogether, which also excludes it from
the reflection that made it work — the connection still fails, and the rule
looks innocent because a matching `no rdr` translates nothing and so never
increments pf's packet counter.

## IPv6

IPv6 is intercepted too, and it needs three things the IPv4 path does not.

**A listener that is not `::1`.** Squid's generated ports bind `[::1]`, and pf
cannot usefully redirect traffic arriving on a LAN interface to an IPv6
loopback address — rules written against `::1` load cleanly and match nothing,
which is the worst kind of failure. The redirect target must be an ordinary
address the firewall owns on that interface.

**A stable one.** The LAN's global address is tracked from the WAN delegation
and carries a one hour lifetime; squid cannot rebind when it changes. So the
listener is a **unique local address** assigned as a virtual IP on the LAN, and
squid binds it via `/usr/local/etc/squid/pre-auth/10-flowsight-v6.conf`. The
proxy plugin owns only its own files in that directory, so this survives a
reconfigure, and the `include` sits at a point where an `http_port` is still
accepted.

**The global prefix in `localnet`.** The generated ACL carries the LAN's IPv4
subnet plus `fc00::/7` and `fe80::/10`, but not the global IPv6 prefix, so
intercepted v6 clients are answered `TCP_DENIED` and nothing says why. Because
the prefix changes, `flowsight-squid-v6acl` derives the current one and
rewrites the ACL only when it differs, reconfiguring squid at that point and
not otherwise. The collector runs it every five minutes, so a re-delegation
does not quietly start denying every IPv6 client days later.

The `pre-auth` include is read after `localnet` is defined and before it is
used, so an extra `acl localnet src <prefix>` line there accumulates into the
existing ACL rather than replacing it.

**QUIC bypasses it.** HTTP/3 runs over UDP 443 and is never redirected, so
browsers that negotiate it leave no record here. Forcing TCP means blocking
UDP 443 outbound, which is a behavioural change with its own consequences and
is not done by default.

## Verifying

Test from a host that genuinely routes through the firewall. On a network where
an ISP router shares the LAN segment, some clients may use it as their gateway
and never traverse OPNsense at all — those cannot be intercepted and their
absence from the log is not a fault.

Check all of: plain HTTP, HTTPS with SNI, HTTPS to a bare IP (no SNI), an
internal service reached by its **public** name, and the same set over IPv6. That last one is the case that
ordering breaks, and it is the one most likely to be missed.

Pick live targets, and for IPv6 pick ones that actually have AAAA records —
`api.github.com` and `httpbin.org` do not, so `curl -6` against them fails with
no proxy involved at all.

Pick live targets. An earlier attempt at this was rolled back on the conclusion
that origin servers were rejecting SNI-less handshakes; the real cause was
retired test addresses that answered nothing, and one chronically flaky test
site. SNI-less interception works.
