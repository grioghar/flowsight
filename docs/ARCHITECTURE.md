# Architecture

## Principle

Compose, don't reimplement. Every component that touches packets is an existing,
battle-tested open-source project. Flowsight owns only the glue: normalization,
policy, and presentation.

This is deliberate. A new DPI engine would be a decade of work and would be worse
than nDPI. The actual gap in the ecosystem is that these tools do not share a
data model, a policy model, or a UI.

## Data path

A key design decision: **Flowsight does not sit inline by default.**

Zenarmor intercepts traffic with netmap, which makes its packet engine a
mandatory hop. On a virtualized gateway that becomes the throughput ceiling — a
single worker saturating one core, with ring-full drops that are invisible to
`netstat` and only appear in `dmesg`.

Flowsight's default posture is observational:

```
                 ┌───────────────┐
   traffic ──────┤  OS forwarding │────── traffic
                 └───────┬───────┘
                         │ (mirror / flows / eBPF)
                 ┌───────▼────────┐
                 │  ntopng (nDPI) │  flows + L7 app identity
                 │  Suricata      │  IDS alerts (EVE JSON)
                 │  Unbound       │  DNS query + block log
                 └───────┬────────┘
                         │ normalized events
                 ┌───────▼────────┐
                 │   collector    │  one schema, OTLP out
                 └───────┬────────┘
                 ┌───────▼────────┐
                 │  TSDB + Loki   │
                 └───────┬────────┘
                 ┌───────▼────────┐
                 │ Grafana / UI   │
                 └────────────────┘
```

Enforcement is applied by the backends themselves (DNS, firewall, Suricata IPS),
not by a Flowsight packet path. Nothing Flowsight runs can become a bottleneck or
drop packets.

## Modules

Flowsight is a **thin core plus modules**. The core owns nothing domain-specific:
it provides the event schema, the storage abstraction, a module registry, the API
surface and auth. Everything that knows about a particular problem — flows,
intrusion detection, DNS filtering, firewall rule hygiene — is a module that can
be installed, upgraded and removed on its own.

This is not a late refactor target. It is the reason the project can grow past
what Zenarmor does: Zenarmor is one monolithic engine, so every capability has to
be built by one vendor and gated by one licence. A module boundary means anyone
can add a capability without touching the core.

### Module contract

A module declares:

| Element | Purpose |
|---|---|
| `collectors` | ingest sources it normalizes into the core event schema |
| `providers` | enforcement targets it can compile policy onto |
| `panels` | UI surfaces it contributes |
| `capabilities` | what it claims to do, so policy can target it by intent |
| `requires` | backends it needs present (e.g. `suricata >= 7`) |

Policy is expressed against **capabilities**, never against a specific backend.
"block category X" resolves to whichever installed module can enforce it — DNS
filter, firewall, or IDS — so swapping a backend does not rewrite policy.

### Planned modules

| Module | Role |
|---|---|
| `visibility` | ntopng / nDPI flows, app and category identity |
| `ids` | Suricata rules and alerts |
| `dnsfilter` | Unbound / AdGuard blocklists and query logs |
| `policy` | the declarative model and its compiler |
| `rulehygiene` | firewall policy analysis — see below |

### rulehygiene (FireMon-like)

Firewall rulesets decay. Rules get added for a reason nobody records, shadow each
other, stop matching anything, and quietly widen exposure. Commercial tools
(FireMon, Tufin, AlgoSec) solve this and are priced for enterprises.

The module analyses the live ruleset and reports:

- **shadowed rules** — never reachable because an earlier rule already matches
- **redundant rules** — fully covered by another rule
- **unused rules** — zero hits over a window, correlated against real counters
- **overly permissive rules** — `any/any`, wide port ranges, unbounded sources
- **change tracking** — every ruleset diff, who changed it, and what it altered
- **risk scoring** — exposure weighted by what the rule actually reaches

This is a natural fit: Flowsight already ingests the flow data needed to tell a
genuinely unused rule from one that simply has not matched today, which is the
distinction that makes such tools trustworthy.

## Components

### collector/
Reads ntopng flows, Suricata EVE JSON, and DNS logs; normalizes them to one
event schema; exports via OTLP. Stateless, restartable, and safe to kill.

### policy/
The declarative policy model and the compiler that renders it to backend
artifacts. Reconciles continuously so drift is corrected.

### adapters/
Platform integration. `opnsense/` is first: a plugin exposing the UI and wiring
the services. Debian/OpenWrt/container adapters follow the same interface.

### ui/
Single pane: live flows, top talkers, alerts, per-device history, policy editing.

## Where it must beat Zenarmor

1. **No licence gates.** Exclusions, multiple policies, and full reporting are
   core behaviour, not upsells.
2. **No cloud dependency.** Data stays on the user's infrastructure.
3. **No inline bottleneck.** See data path above.
4. **Portable.** Not tied to one firewall distribution.
5. **Dashboards and policy as code.** Reviewable, diffable, restorable.

## Where Zenarmor stays ahead, honestly

Inline L7 *enforcement* mid-stream, TLS inspection, and its curated cloud
category feed are genuinely hard to match. Flowsight should say so rather than
claim parity it does not have. Category data will lean on open feeds and nDPI's
own classification.
