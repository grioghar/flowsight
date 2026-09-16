# Roadmap

Phases are ordered so the system is useful early and nothing depends on a
component that does not exist yet.

## Phase 0 — Decommission Zenarmor

Remove `os-sensei`, `os-sensei-updater`, `os-sunnyvalley` (432 MB) and the netmap
ring tuning that exists only to serve it (`rc.d/netmap_ringsize`, the syshook,
and the `loader.conf.local` ring_size entry).

Side effect worth naming: the `netmap_transmit vtnet0 full` drops disappear
entirely rather than being tuned around, because the netmap interception path
goes away with it.

Interim: no L7 inspection. Suricata and DNS filtering carry the load.

## Phase 1 — Visibility

- Install `os-ntopng` (available in the OPNsense repo, 6.6).
- Re-enable Suricata in alert-only mode (it is installed and currently disabled).
- Ship ntopng flows, Suricata EVE and Unbound DNS logs into the existing
  Prometheus-compatible TSDB and Loki.
- Grafana dashboards reproducing Zenarmor's core reports: top talkers, per-device
  activity, app/category breakdown, blocked-domain history.

Exit criteria: every question the Zenarmor dashboard answered can be answered
here.

## Phase 2 — Normalization

The `collector/` service and a stable event schema. Until this exists, each
source has its own field names and the dashboards are bespoke per source.

## Phase 3 — Policy engine

The declarative model and the compiler to DNS blocklists, Suricata rules and
firewall rules, with continuous reconciliation. This is the part that does not
exist anywhere else and is the reason the project is worth building.

## Phase 4 — UI

Single pane over the schema and the policy model.

## Phase 5 — rulehygiene module

Firewall rule analysis: shadowed, redundant, unused and overly permissive rules,
change tracking and risk scoring. The FireMon-shaped capability, built on flow
data the earlier phases already collect.

## Phase 6 — Portability and release

Adapters beyond OPNsense (Debian, OpenWrt, container), packaging, docs, and a
public release.

## Non-goals

- Reimplementing DPI. nDPI is better than anything this project would write.
- Monolithic design. Every capability ships as a module against a thin core;
  nothing domain-specific belongs in the core.
- Inline mid-stream L7 enforcement in v1. Enforcement stays with the backends.
- TLS interception.
