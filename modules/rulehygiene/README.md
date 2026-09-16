# rulehygiene

Firewall ruleset analysis — the FireMon-shaped capability, read-only.

```bash
flowsight-rulehygiene          # human-readable report
flowsight-rulehygiene --json   # machine-readable
```

## Findings are grounded in live counters

Any tool can say "this rule looks broad" from rule text alone. Only `pfctl -vsr`
counters can separate a rule that is genuinely dead from one that is simply
rarely hit — and that distinction is what makes the output worth acting on.

| Finding | Evidence |
|---|---|
| `shadowed` | **zero evaluations** — pf never even considered it, so an earlier quick rule always matches first. This is the one finding counters *prove* rather than infer. |
| `unused` | many evaluations, zero packets — suggestive, not conclusive: a deliberate catch-all safety net looks identical to dead weight |
| `permissive` | unbounded source/destination on a `pass` rule, severity weighted by direction and interface |
| `expected` | broad by necessity (DHCP, DHCPv6, IPv6 ICMP) — reported as info, never as a defect |

## Calibration matters more than coverage

Three deliberate choices, each learned from running it against a real ruleset:

- **Port-qualified rules are not "any to any"** in the sense that matters.
- **Outbound `any → any` is `low`**, not `high` — it is the normal egress
  posture of almost every gateway.
- **DHCP is recognised, not flagged.** A DHCP client cannot constrain the
  server address; it does not know it until it has a lease. Flagging that is
  how a hygiene tool teaches people to ignore it.

Findings below a day of uptime suppress the counter-based checks entirely,
since "never matched since boot" means nothing an hour after a reboot.

## Risk score

A single number for tracking **direction over time**, not an absolute grade.
Zero means no actionable findings.
