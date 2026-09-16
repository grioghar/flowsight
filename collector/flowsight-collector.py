#!/usr/bin/env python3
"""Flowsight collector.

Reads the backends Flowsight composes, normalizes what they emit into one event
schema, and exports it over OTLP. Stdlib only - it runs on an appliance where
installing packages is awkward and dependencies are a liability.

Design notes:

  * Every source is a Source subclass. Adding a backend means adding a class and
    listing it in config; nothing else changes. This mirrors the module contract
    in docs/ARCHITECTURE.md.
  * A source that fails is skipped for that cycle and retried on the next one.
    A collector must never be the reason a firewall has a bad day, so no source
    error is allowed to reach the main loop.
  * Counters from the backends are monotonic-since-boot. We export them as OTLP
    Sums with an explicit start timestamp so a backend restart reads as a
    counter reset rather than an enormous negative spike.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.request

CONFIG_PATHS = [
    os.environ.get("FLOWSIGHT_CONFIG", ""),
    "/usr/local/etc/flowsight/collector.json",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "collector.json"),
]

DEFAULT_CONFIG = {
    "otlp_metrics_endpoint": "http://127.0.0.1:4318/v1/metrics",
    "otlp_logs_endpoint": "http://127.0.0.1:4318/v1/logs",
    "host_name": "",
    "interval_seconds": 30,
    "sources": {
        "suricata": {"enabled": True, "eve_path": "/var/log/suricata/eve.json"},
        "unbound": {
            "enabled": True,
            "control": "/usr/local/sbin/unbound-control",
            "config": "/var/unbound/unbound.conf",
        },
    },
}

METRIC_PREFIX = "flowsight"


def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    for path in CONFIG_PATHS:
        if path and os.path.isfile(path):
            try:
                with open(path) as fh:
                    user = json.load(fh)
            except Exception as exc:
                sys.stderr.write("flowsight: bad config %s: %s\n" % (path, exc))
                break
            for key, val in user.items():
                if key == "sources" and isinstance(val, dict):
                    for src, scfg in val.items():
                        cfg["sources"].setdefault(src, {}).update(scfg or {})
                else:
                    cfg[key] = val
            break
    if not cfg.get("host_name"):
        cfg["host_name"] = os.uname()[1]
    return cfg


class Source:
    """One backend Flowsight reads from."""

    name = "source"

    def __init__(self, cfg):
        self.cfg = cfg

    def collect(self):
        """Return (metrics, log_records).

        metrics: list of (name, value, attributes_dict, is_counter)
        log_records: list of (epoch_nanos, severity, body, attributes_dict)
        """
        raise NotImplementedError


class SuricataEve(Source):
    """Suricata alerts from eve.json.

    Tails the file rather than re-reading it: eve.json grows without bound
    between rotations and re-parsing it every cycle would be quadratic.
    Rotation is detected by inode change, not by size, because a rotated file
    can briefly be larger than the offset we held.
    """

    name = "suricata"

    SEVERITY = {1: "ERROR", 2: "WARN", 3: "INFO"}

    def __init__(self, cfg):
        Source.__init__(self, cfg)
        self._offset = None
        self._inode = None
        self._alert_count = 0

    def _reset_if_rotated(self, path):
        try:
            st = os.stat(path)
        except OSError:
            return False
        if self._inode is None:
            # First run: start at the end. Replaying history on every restart
            # would flood Loki with alerts that were already shipped.
            self._inode, self._offset = st.st_ino, st.st_size
            return False
        if st.st_ino != self._inode or st.st_size < self._offset:
            self._inode, self._offset = st.st_ino, 0
        return True

    def collect(self):
        path = self.cfg.get("eve_path")
        metrics, logs = [], []
        if not path or not self._reset_if_rotated(path):
            return metrics, logs

        new_alerts = 0
        by_severity = {}
        with open(path, "r", errors="replace") as fh:
            fh.seek(self._offset)
            for line in fh:
                if not line.endswith("\n"):  # partial trailing write; retry later
                    break
                self._offset += len(line.encode("utf-8", "replace"))
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except ValueError:
                    continue
                if evt.get("event_type") != "alert":
                    continue

                alert = evt.get("alert", {})
                sev = int(alert.get("severity", 3) or 3)
                by_severity[sev] = by_severity.get(sev, 0) + 1
                new_alerts += 1

                attrs = {
                    "signature": str(alert.get("signature", ""))[:200],
                    "category": str(alert.get("category", ""))[:100],
                    "severity": str(sev),
                    "src_ip": str(evt.get("src_ip", "")),
                    "dest_ip": str(evt.get("dest_ip", "")),
                    "dest_port": str(evt.get("dest_port", "")),
                    "proto": str(evt.get("proto", "")),
                    "source": "suricata",
                }
                logs.append((
                    _iso_to_nanos(evt.get("timestamp")),
                    self.SEVERITY.get(sev, "INFO"),
                    "%s [%s]" % (alert.get("signature", "alert"), alert.get("category", "")),
                    attrs,
                ))

        self._alert_count += new_alerts
        metrics.append(("%s_ids_alerts_total" % METRIC_PREFIX, self._alert_count,
                        {"source": "suricata"}, True))
        for sev, count in sorted(by_severity.items()):
            metrics.append(("%s_ids_alerts_by_severity" % METRIC_PREFIX, count,
                            {"source": "suricata", "severity": str(sev)}, False))
        return metrics, logs


class UnboundStats(Source):
    """DNS resolver counters, including blocklist hits."""

    name = "unbound"

    WANTED = {
        "total.num.queries": "dns_queries_total",
        "total.num.cachehits": "dns_cache_hits_total",
        "total.num.cachemiss": "dns_cache_miss_total",
        "num.rrset.bogus": "dns_bogus_total",
    }

    def collect(self):
        cmd = [self.cfg.get("control", "unbound-control"),
               "-c", self.cfg.get("config", ""), "stats_noreset"]
        cmd = [c for c in cmd if c]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if out.returncode != 0:
            raise RuntimeError("unbound-control failed: %s" % out.stderr.strip()[:200])

        metrics = []
        for line in out.stdout.splitlines():
            if "=" not in line:
                continue
            key, _, raw = line.partition("=")
            name = self.WANTED.get(key.strip())
            if not name:
                continue
            try:
                value = float(raw.strip())
            except ValueError:
                continue
            metrics.append(("%s_%s" % (METRIC_PREFIX, name), value,
                            {"source": "unbound"}, True))
        return metrics, []


def _iso_to_nanos(stamp):
    """Suricata timestamps look like 2026-09-16T14:03:30.123456-0500."""
    if not stamp:
        return int(time.time() * 1e9)
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?", str(stamp))
    if not m:
        return int(time.time() * 1e9)
    try:
        base = time.mktime(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return int(time.time() * 1e9)
    frac = float("0." + m.group(2)) if m.group(2) else 0.0
    return int((base + frac) * 1e9)


def _attrs(d):
    return [{"key": k, "value": {"stringValue": str(v)}} for k, v in d.items() if v != ""]


class Exporter:
    def __init__(self, cfg, start_nanos):
        self.cfg = cfg
        self.start = str(start_nanos)

    def _post(self, url, payload):
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).close()

    def _resource(self):
        return {"attributes": _attrs({
            "host.name": self.cfg["host_name"],
            "service.name": "flowsight-collector",
        })}

    def metrics(self, items):
        if not items:
            return
        now = str(int(time.time() * 1e9))
        out = []
        for name, value, attrs, is_counter in items:
            point = {"asDouble": float(value), "timeUnixNano": now,
                     "attributes": _attrs(attrs)}
            if is_counter:
                point["startTimeUnixNano"] = self.start
                out.append({"name": name, "sum": {
                    "dataPoints": [point],
                    "aggregationTemporality": 2,  # cumulative
                    "isMonotonic": True}})
            else:
                out.append({"name": name, "gauge": {"dataPoints": [point]}})
        self._post(self.cfg["otlp_metrics_endpoint"], {"resourceMetrics": [{
            "resource": self._resource(),
            "scopeMetrics": [{"scope": {"name": "flowsight"}, "metrics": out}]}]})

    def logs(self, records):
        if not records:
            return
        out = [{
            "timeUnixNano": str(ts),
            "severityText": sev,
            "body": {"stringValue": body},
            "attributes": _attrs(attrs),
        } for ts, sev, body, attrs in records]
        self._post(self.cfg["otlp_logs_endpoint"], {"resourceLogs": [{
            "resource": self._resource(),
            "scopeLogs": [{"scope": {"name": "flowsight"}, "logRecords": out}]}]})


SOURCE_TYPES = {"suricata": SuricataEve, "unbound": UnboundStats}


def main():
    cfg = load_config()
    start = int(time.time() * 1e9)
    exporter = Exporter(cfg, start)

    sources = []
    for name, scfg in cfg["sources"].items():
        if not scfg.get("enabled"):
            continue
        cls = SOURCE_TYPES.get(name)
        if cls is None:
            sys.stderr.write("flowsight: unknown source '%s', skipping\n" % name)
            continue
        sources.append(cls(scfg))

    if not sources:
        sys.stderr.write("flowsight: no sources enabled\n")
        return 1

    sys.stderr.write("flowsight: collecting from %s every %ss\n"
                     % (", ".join(s.name for s in sources), cfg["interval_seconds"]))

    while True:
        metrics, logs = [], []
        for src in sources:
            try:
                m, l = src.collect()
                metrics.extend(m)
                logs.extend(l)
            except Exception as exc:
                # One broken backend must not stop the others or kill the loop.
                sys.stderr.write("flowsight: source %s failed: %s\n" % (src.name, exc))

        for kind, fn, data in (("metrics", exporter.metrics, metrics),
                               ("logs", exporter.logs, logs)):
            try:
                fn(data)
            except Exception as exc:
                sys.stderr.write("flowsight: export %s failed: %s\n" % (kind, exc))

        time.sleep(cfg["interval_seconds"])


if __name__ == "__main__":
    sys.exit(main())
