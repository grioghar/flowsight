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
| `safe_search`, `youtube` | Unbound view with CNAME redirects | the DNS answer |
| `tls.inspect` | squid bumps the client with the FlowSight CA | the handshake; bypassed names are spliced |

A policy whose requirements no installed provider offers is reported as
*unmet* and refused, because a policy that silently enforces nothing is worse
than an error.

## Order and precedence

Policies are evaluated in the order listed; the UI has move buttons. Within a
policy, `allow` beats `deny`. Exclusions beat everything.

## Monitor first

Every policy can run with `action: monitor`. Web and DNS denials are then
compiled but not enforced, and application matches are recorded as "would
block" events. Turn on `Enforce policy` in the policy module's settings to
apply anything at all; until then the plan page shows exactly what would be
written where.
