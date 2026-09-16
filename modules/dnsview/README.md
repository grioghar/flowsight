# DNS

What this network asked for, who asked, and what came back.

Unbound on OPNsense already records every query it answers into a DuckDB store:
client, domain, type, whether it was passed or blocked and by which list, where
the answer came from, the response code, DNSSEC status and resolution time.
That is a better record than anything reconstructable from syslog, so this
module reads it rather than turning on query logging and parsing text.

Read-only throughout. Nothing here changes resolver behaviour.

## Commands

```
flowsight-dnsview overview --hours 24 --limit 25   # everything the page needs
flowsight-dnsview recent --limit 200 [--client IP] [--domain STR] [--blocked]
flowsight-dnsview resolutions                      # address -> names
flowsight-dnsview lookup 104.200.30.183
```

`overview` returns summary, top domains, most blocked, top clients, and
breakdowns by query type, answer source, response code, DNSSEC status and
blocklist, plus a time series. It is one command rather than several because
importing duckdb costs about a second — the page is served from a single
process start, not one per panel.

## Naming an address

`resolutions` builds an address-to-name map from the resolver's own cache. This
is *forward*-resolution data: the names clients asked for and the addresses they
were given.

That is deliberately not a reverse PTR lookup. Most CDN and cloud addresses
either have no PTR record at all, or carry one naming the hosting provider
rather than the service anyone was actually reaching. The resolver's cache
knows the name the client asked for, which is the one worth showing.

Where several names map to one address, all are kept — that is genuinely what a
shared address means, and collapsing it to one invents precision. A single Plex
address on this network resolves to fourteen names.

## Naming a client

Unbound keeps a client table, but it is sparse — it holds only what the resolver
itself managed to resolve, which on a 100-client network named barely a tenth of
them. So client names are merged from three sources, first hit wins:

1. Unbound's own resolved client table.
2. DHCP leases — what each device called itself.
3. `dhcp-host=` reservations — statically reserved infrastructure never appears
   in the lease file at all, yet is exactly what is worth naming.
4. The enrollment registry, for anything identified there.

## Bounds

Every limit and time window from the UI is clamped before it reaches SQL. The
store holds millions of rows and unbound is writing to it continuously; an
unbounded limit turns a page load into a scan that competes with the resolver's
own writer. Filters are bound as SQL parameters and passed as argv, never as a
shell string.

## Requirements

Unbound reporting must be enabled — without it there is no store and the module
says so rather than failing obscurely.
