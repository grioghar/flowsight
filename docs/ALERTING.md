# Alerting

Rules live in `adapters/telemetry/alerting/` and are provisioned into Grafana
from `/opt/telemetry/grafana/provisioning/alerting/` on the **primary telemetry
node only**. Provisioning the same rules on both nodes of the cluster makes
every alert notify twice.

## Set the delivery channel

One line. In `/opt/telemetry/.env`:

```
ALERT_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

then `cd /opt/telemetry && docker compose up -d grafana`.

Until that is set, every rule still evaluates and fires — delivery just fails,
visibly, in the Grafana log. The URL is read from `.env` rather than written
into the provisioning file because a webhook URL *is* a credential: anyone
holding it can post to that channel. Grafana redacts it in its own output.

The contact point is typed `discord`; change `type` in `contact-points.yaml`
for anything else (`webhook`, `email`, `pushover`, …). A generic `webhook`
posts Grafana's own JSON, which Discord rejects — the type has to match.

## What is alerted on, and why

Each rule is a failure that actually happened on this network, not a guess.

| Rule | Condition | Why it exists |
|---|---|---|
| `pve1_swap_filling` | swap >70% for 10m | Swap reached 100% and the host thrashed hard enough to stop answering ARP while still powered on, taking the firewall VM and every container with it. |
| `pve1_memory_high` | memory >92% for 10m | Container limits total more than twice physical memory, so several guests growing at once becomes a thrash. |
| `pve1_disk_saturated` | any disk >95% for 1h | The media drives are USB-attached in BOT mode at queue depth two; one at capacity stalls everything sharing it. |
| `pve1_io_starvation` | >25 processes blocked for 15m | The symptom that precedes unresponsiveness, and it is legible before a load average is. |
| `telemetry_ingest_stopped` | no host metrics for 10m | Ingest silently stopped for *days* because nobody held the telemetry VIP. Silence is the alerting condition. |
| `pve1_nvme_hot` | NVMe >75C for 10m | Observed at 77.8C under sustained I/O; throttling starts in the low 80s. |
| `pve1_cpu_temp_high` | CPU Tctl >80C for 5m | Pre-existing. |

`telemetry_ingest_stopped` uses `noDataState: Alerting` deliberately. Every
other rule treats absent data as `NoData`; this one treats it as the fault,
because a broken ingest path and a healthy quiet host look identical from
inside Grafana.

Alerts are grouped by `alertname` with a 4-hour repeat. A host under I/O
pressure trips several of these together, and four messages describing one
condition is how people learn to ignore alerts.

## Metric names: mind the unit suffix

The OTLP-to-Prometheus translation **appends the unit to the metric name**. A
dimensionless count declared with unit `"1"` arrives as `host_load1_ratio`, not
`host_load1`. Rules written against the intended name then evaluate against
nothing and never fire — they look healthy and are simply blind.

So in `host-sensors-server.py`, counts carry no unit and only genuine ratios use
`"1"`, because their names already end in `_ratio` and the suffix is not
duplicated. Confirm what actually landed before writing a rule against it:

```
curl -s -H "X-Scope-OrgID: anonymous" \
  "http://192.168.1.251:9009/prometheus/api/v1/label/__name__/values"
```

## Verifying

```
# rule states: inactive / pending / firing
curl -s -u admin:$GRAFANA_PASSWORD \
  http://127.0.0.1:3000/api/prometheus/grafana/api/v1/rules

# exercise the delivery path without waiting for a real alert
curl -s -u admin:$GRAFANA_PASSWORD -X POST \
  http://127.0.0.1:3000/api/alertmanager/grafana/config/api/v1/receivers/test ...
```

A `pending` rule is one whose condition is true and whose `for` window has not
elapsed. Three were pending the moment these were installed, which is how it
was confirmed they evaluate against real data rather than merely parse.
