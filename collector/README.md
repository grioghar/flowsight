# flowsight-collector

Reads the backends Flowsight composes, normalizes their output into one event
schema, and exports it over OTLP.

Stdlib Python only — it runs on appliances where installing packages is awkward
and dependencies are a liability.

## Adding a source

Subclass `Source`, implement `collect()` returning `(metrics, log_records)`, and
register it in `SOURCE_TYPES`. Nothing else changes. Sources are enabled and
configured entirely from `collector.json`.

```python
class MySource(Source):
    name = "mysource"

    def collect(self):
        return [("flowsight_my_metric", 1.0, {"source": "mysource"}, False)], []
```

Metrics are `(name, value, attributes, is_counter)`. Counters are exported as
OTLP cumulative Sums with a fixed start timestamp, so a backend restart reads as
a counter reset rather than a huge negative spike.

## Behaviour that matters

- **A failing source never stops the others**, and never kills the loop. A
  collector must not be the reason a firewall has a bad day.
- **eve.json is tailed, not re-read.** It grows without bound between rotations;
  re-parsing each cycle would be quadratic. Rotation is detected by inode change
  rather than size, because a rotated file can briefly exceed the held offset.
- **First run starts at end-of-file.** Replaying history on every restart would
  flood the log backend with alerts already shipped.

## Config

Copy `collector.json.example` to `/usr/local/etc/flowsight/collector.json`, or
point `FLOWSIGHT_CONFIG` at it.
