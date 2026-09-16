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
