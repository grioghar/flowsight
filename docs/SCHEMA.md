# The Flowsight event schema

This is the contract every module normalizes onto. It exists so that the layers
above — dashboards, alerting, and eventually the policy compiler — never need to
know which backend produced a given observation.

That is the whole reason the project exists. Suricata says `src_ip`, Unbound says
`qname`, ntopng says `cli.ip`. Three vocabularies for the same ideas means three
bespoke dashboards and a policy language that has to special-case every backend.

## The core idea

An IDS alert and a blocked DNS lookup are the same *shape* of thing:

> someone (**actor**) tried to reach something (**target**), a **rule** matched,
> and a **verdict** was reached.

Once both are expressed that way, one panel shows both, and a policy can say
"block gambling for the kids' devices" without naming DNS or Suricata.

## Events

| Field | Meaning |
|---|---|
| `timestamp` | UTC epoch nanoseconds |
| `kind` | `alert`, `block`, `flow`, `audit` |
| `source` | module that produced it (`suricata`, `unbound`, `ntopng`) |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `verdict` | `observed`, `blocked`, `allowed` |
| `actor.*` | `ip`, `port`, `mac`, `name` — who initiated |
| `target.*` | `ip`, `port`, `domain`, `name` — what was reached for |
| `network.*` | `proto`, `interface`, `direction` |
| `rule.*` | `id`, `name`, `category` — what matched |
| `message` | human-readable summary |

Empty fields are omitted rather than exported as empty strings, so label
cardinality stays proportional to what a source actually knows.

### Severity

Sources map their own scales onto these five. Suricata's numeric 1–4 becomes
`critical`/`high`/`medium`/`low`; a DNS block is `medium`. Never pass a
backend's native scale through — that is the thing this schema exists to stop.

## Metrics

Names are **domain-based, never source-based**: `flowsight_traffic_bytes_total`,
not `flowsight_ntopng_bytes`. If ntopng were swapped for a NetFlow collector the
metric name must not change, or every dashboard and alert rule breaks.

- prefix `flowsight_`
- unit in the suffix: `_bytes_total`, `_bits_per_second`, `_celsius`, `_seconds`
- cumulative counters end `_total` and are exported as OTLP Sums with a fixed
  start time, so a backend restart reads as a reset rather than a negative spike
- every series carries `source`; add `interface` where it is meaningful

## Capabilities

Each module declares what it can do. Policy targets **capabilities, not
backends** — `dns.block` resolves to whichever installed module provides it.

| Capability | Meaning |
|---|---|
| `traffic.observe` | flow, byte and throughput visibility |
| `threat.detect` | signature or reputation based detection |
| `dns.observe` | resolver query visibility |
| `dns.block` | can refuse a domain |
| `host.inventory` | can enumerate devices on a network |

A module that only observes must not claim a `.block` capability; the compiler
uses these to decide what it can actually enforce, and a false claim produces
policy that silently does nothing.

## Querying it

Loki indexes only `host_name`, `os_type` and `service_name`. **Every schema
field is structured metadata, not an indexed label**, so it must be filtered
after the stream selector:

```logql
{service_name="flowsight-collector"} | source="suricata" | severity="critical"
```

`{source="suricata"}` silently matches nothing — it is not an indexed label.
That returns an empty panel with no error, which is the same class of silent
failure as the dropped future-dated timestamps.
