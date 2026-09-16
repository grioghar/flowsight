# flowsight-ui

The single pane over modules, telemetry and policy.

Deliberately **not** a dashboard replacement — Grafana renders timeseries better
than anything here would. This shows what Grafana cannot: which modules are
installed, what each can *observe* versus *enforce*, whether each is healthy,
and what applying the current policy would change.

## Security posture

This is a management surface on a firewall, so the defaults refuse to be
casually dangerous:

- binds to **127.0.0.1**
- **read-only** — it can run `plan`, never `apply`. `POST` returns 405.
  Enforcement stays on the CLI where it is deliberate and auditable.
- ships **no authentication**. Exposing it beyond loopback means putting an
  authenticating reverse proxy in front; it warns loudly on startup if bound
  to anything else.
- no build step and no CDN — an appliance should not need internet access to
  render its own management page.

Reach it over an SSH tunnel:

```bash
ssh -N -L 8080:127.0.0.1:8080 user@firewall
```

## Observe vs enforce

The capability list is split on purpose. Collapsing them makes the UI claim the
system can block when it can only watch — the same false-capability trap
`docs/SCHEMA.md` warns about. Reading Unbound's counters is `dns.observe`;
only the policy provider offers `dns.block`.

## Health comes from the collector, not from config

The collector publishes `/var/run/flowsight-collector.json` each cycle with
per-source health, counts and errors. The UI reads that rather than inferring
from config (which only says what was *asked for*) or from metric presence
(which cannot distinguish a failing source from a quiet one). A state file older
than three minutes is reported as stale, since a collector that died without
clearing it would otherwise look healthy.
