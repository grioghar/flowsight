# Headgate

An open, self-hosted alternative to Zenarmor for OPNsense and other platforms.

Headgate does not reimplement deep packet inspection. Proven open-source engines
already do that well. What has never existed is the layer above them: one policy
model, one telemetry schema, and one interface across all of them.

That layer is Headgate.

## Why

Zenarmor is the only turnkey L7 visibility and policy stack for OPNsense, and it
is a good product. It is also proprietary, and the free edition gates things that
matter for a home or small network:

- Host and network exclusions from inspection are premium (`ip_nets` and `vlans`
  are rejected outright on the free licence).
- Only the single default policy can be used; any additional policy is premium.
- Reporting data is shared with the vendor under the free licence.
- Its netmap data path becomes a throughput ceiling: a single packet-engine
  worker, pinned to one core, that cannot be scaled by adding workers.

None of the underlying capability requires any of that. nDPI, Suricata and
Unbound are open, and most of the stack is already installed on a typical
OPNsense box.

## What it is

| Layer | Headgate uses | Headgate provides |
|---|---|---|
| L7 identification | nDPI (via ntopng) | normalized app/category schema |
| Intrusion detection | Suricata | unified rule + alert model |
| DNS filtering | Unbound / AdGuard Home | one blocklist + allowlist source of truth |
| Storage | Prometheus-compatible TSDB + Loki | one schema across all sources |
| Reporting | Grafana | dashboards shipped as code |
| Policy | — | **the missing piece: one model, many backends** |

The core idea is the **policy compiler**. You declare intent once:

```yaml
policy:
  - name: kids-devices
    match: { group: kids }
    deny:  { categories: [adult, gambling], apps: [discord] }
    schedule: { school-nights: "20:00-07:00" }
```

Headgate compiles that into the artifacts each backend actually understands —
DNS blocklist entries, Suricata rules, firewall rules — and reconciles them.
No cloud dependency, no per-feature licence gate.

## Status

Early. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and
[docs/ROADMAP.md](docs/ROADMAP.md) for what works today.

## Licence

Apache-2.0.
