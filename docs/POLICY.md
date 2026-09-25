# The policy document

One JSON document, `/usr/local/etc/flowsight/policy.json` on OPNsense and
FreeBSD, `/etc/flowsight/policy.json` on Linux. Edit it in the UI, through
the API, or import YAML. It is validated as a whole; an invalid document is
never partially applied.

```yaml
version: 1
groups:
  kids:
    description: Children's devices
    members: [10.0.1.20, "mac:aa:bb:cc:dd:ee:ff", "device:kids-ipad", "zone:iot"]
    # even_excluded: true                # firewall/DNS rules apply to excluded members too
schedules:
  school-nights:
    windows:
      - { days: [sun, mon, tue, wed, thu], from: "20:00", to: "07:00" }   # overnight
policies:
  - name: kids-evenings
    enabled: true
    action: block            # or monitor: log what would be blocked, enforce nothing
    match: { groups: [kids] }
    schedule: school-nights
    deny:
      apps: [TikTok, Discord, BitTorrent]
      app_categories: [Game]
      categories: [gambling, adult, ads]
      domains: [example.com]
      tlds: [zip, mov]
      countries: [CN, RU]                  # block destinations in these countries
      # countries_except: [US]             # or: block every country but these (home is always allowed)
      ports: [tcp/25, udp/6881-6889]
    allow:
      domains: [classroom.google.com]
    safe_search: true
    youtube: strict
    tls: { inspect: false, bypass: [apple.com, icloud.com] }
exclusions:
  hosts: [10.0.0.5]          # never intercepted, inspected or policed
  domains: [bank.example]    # never intercepted or blocked
options:
  dns_block_mode: nxdomain   # nxdomain | null | refused
  block_page_url: ""         # empty: FlowSight's own page
```

## Members

| Form | Meaning |
|---|---|
| `10.0.1.20`, `2001:db8::5` | one address |
| `10.0.1.0/24` | a network |
| `mac:aa:bb:cc:dd:ee:ff` | the device with that MAC, whatever address it holds |
| `device:<name>` | a device by the name FlowSight knows it under |
| `zone:<id>` | an enrolment zone's subnet |
| `all` (or `match.all: true`) | every local network |

## What each denial compiles to

| Denial | Providers | Where it bites |
|---|---|---|
| `domains`, `categories`, `tlds` | Unbound RPZ zone per policy, tagged to the policy's clients; squid ACLs | the DNS answer, then the TLS ClientHello or HTTP request for anything that slipped past DNS |
| `apps`, `app_categories` | pf table per policy filled by app control from nDPI identifications | the first identified flow is cut and every later connection to that endpoint is dropped |
| `ports`, `internet` | pf rules in `flowsight/policy` | the first packet |
| `countries`, `countries_except` | pf tables built from the local country database | the first packet to an address registered in a denied country |
| `safe_search`, `youtube` | Unbound view with CNAME redirects | the DNS answer |
| `tls.inspect` | squid bumps the client with the FlowSight CA | the handshake; bypassed names are spliced |

A policy whose requirements no installed provider offers is reported as
*unmet* and refused, because a policy that silently enforces nothing is worse
than an error.

## Order and precedence

Policies are evaluated in the order listed; the UI has move buttons. Within a
policy, `allow` beats `deny`. Exclusions beat everything, with one deliberate
exception: a policy with `match.even_excluded: true` (*Apply even to hosts in
the exclusions list* on the Who tab) still gets its firewall and DNS rules
for excluded members. Exclusions are usually there to keep a subnet out of
interception; without the switch that subnet could never be the subject of
a port, internet or country rule. Excluded hosts are never intercepted
whatever the policy says. The plan warns, and the Policies page shows *all
members excluded*, when exclusions leave a policy with nothing to enforce.

## Country-based blocking

Two forms, in the policy's *Countries* tab or in the file:

- `countries: [CN, RU]` denies the listed countries (ISO 3166-1 two-letter
  codes).
- `countries_except: [US]` denies every country other than the listed ones.
  The gateway's own country (the one its public address is registered in) is
  always added to the allowed set, so a policy with an empty list means
  "home only". This is the usual shape for IoT devices.

A policy uses one form or the other, not both.

**What it needs.** The country database, switched on at *Settings › enrich ›
Country lookup*. It is downloaded once and refreshed monthly; nothing else
leaves the gateway to build the tables. Without it the plan fails with a
message naming the setting.

**How it is enforced.** The firewall provider declares one persistent pf
table per denied country, `fs_geo_<cc>`, or one per except-policy,
`fs_geox_<policy>`, in the `flowsight/policy` anchor, and one rule per table
from the policy's members to that table. On apply each table is filled in a
single pass over the database (both address families). The tables follow the
database: an hourly check rebuilds any table filled from an older build, and a
restarted daemon refills them once. `GET /api/firewall/status` lists them
under `geo_tables` with their countries, prefix count, database epoch and
fill time; *Protect › Firewall Analysis Engine (FAE)* shows the same.

**Anycast.** Ranges announced from many sites at once (Cloudflare, the
public resolvers, the root servers, and the forty-odd thousand prefixes the
anycast census lists) are left out of every country table, whichever
country they are registered in: a device reaching one of them is talking to
a nearby site, and a country rule over it would block the wrong thing.
`geo_tables` in the firewall status reports how many ranges were skipped
per table.

**Limits.** Registration is not location: a CDN's unicast range registered
abroad may answer from next door and the reverse, so expect some surprises
and start in monitor mode. Addresses the database does
not know are in no table and are never blocked by a country rule. Tables hold
tens of thousands of prefixes for a large country and a few hundred thousand
for an except-table; pf keeps them in a radix tree, so lookup cost does not
depend on size.

**Precedence.** Like other denials, country rules respect the policy order,
`allow` exceptions for the same members, monitor mode and exclusions.

## Monitor first

Every policy can run with `action: monitor`. Web and DNS denials are then
compiled but not enforced, and application matches are recorded as "would
block" events. Turn on `Enforce policy` in the policy module's settings to
apply anything at all; until then the plan page shows exactly what would be
written where.
