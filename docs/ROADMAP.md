# Roadmap

## Done

- Native daemon: one static Go binary, embedded SQLite store, embedded UI,
  module registry, scheduler, self-describing API.
- Visibility: ntopng flows and applications, hosts with names and vendors,
  web sessions with server names, DNS log, TLS sessions and certificates,
  Suricata alerts, per-host reports, rollups for a year of history.
- Policy: document model with groups, schedules, exclusions; compiler with
  plan, diff, apply and continuous reconciliation; DNS (RPZ), web (SNI and
  HTTP), application (pf tables from nDPI), ports and internet providers;
  safe search and YouTube restriction; monitor mode.
- TLS transparency: generated inspection CA, per-policy inspection with
  bypass lists, certificate inventory and findings.
- Firewall hygiene: live counters, shadowed and permissive rules, change
  tracking with the user who changed it, risk score.
- Enrolment: device identification from DHCP, zones, placement and isolation
  in monitor-first mode, captive self-identification page.
- Operations: reports and CSV export, scheduled email reports, alerting to
  email, webhooks, Discord, Slack and ntfy, audit log, signed in-place
  updates with roll back, OTLP export.
- OPNsense plugin package built with pkg alone; Debian package; installer for
  other systems.

## Next

- Content controls inside inspected sessions: URL-path rules, file-type and
  size limits, keyword lists (squid ACLs on bumped traffic).
- GeoIP: country tables from an open database for `deny.countries` and for
  destination country in reports.
- User identity: RADIUS accounting listener and LDAP/AD group lookup so
  policies can target people, not only devices.
- nftables providers so Linux gateways get web, application and port
  enforcement.
- Quotas: per-device or per-group bandwidth and time budgets, enforced
  through pf tables and schedules.
- Threat intelligence: IP reputation feeds into pf tables (`threat.block`),
  Suricata rule management from the UI.
- Multi-gateway: one UI over several flowsightd instances.
- Licensing and support tiers, built on the module tier field that already
  exists, after the product is stable.

## Non-goals

- Reimplementing DPI. nDPI is better than anything this project would write.
- A packet engine of our own in the forwarding path.
- A cloud dependency of any kind.
