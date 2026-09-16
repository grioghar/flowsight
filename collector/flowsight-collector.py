#!/usr/bin/env python3
"""Flowsight collector.

Reads the backends Flowsight composes, normalizes them onto one event schema
(docs/SCHEMA.md), and exports over OTLP. Stdlib only - it runs on appliances
where installing packages is awkward and dependencies are a liability.

  * Every backend is a Source subclass declaring its capabilities. Adding one
    means adding a class and listing it in config; nothing above changes.
  * Sources emit Metric and Event objects, never backend-native field names.
    That normalization is the point of the project: an IDS alert and a blocked
    DNS lookup become the same shape, so one panel and one policy language
    cover both.
  * A failing source is skipped for that cycle. A collector must never be the
    reason a firewall has a bad day.
"""

import calendar
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

CONFIG_PATHS = [
    os.environ.get("FLOWSIGHT_CONFIG", ""),
    "/usr/local/etc/flowsight/collector.json",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "collector.json"),
]

METRIC_PREFIX = "flowsight"

# Beyond this a timestamp is untrustworthy and is replaced with "now" - log
# backends drop far-future entries silently, so a bad clock would otherwise
# make alerts disappear with no error anywhere.
MAX_TIMESTAMP_SKEW_NS = 3600 * 1_000_000_000

# Canonical severities, worst first. Sources map their own scale onto these.
SEVERITIES = ("critical", "high", "medium", "low", "info")

# Canonical capabilities. Policy targets these, never a backend name.
CAP_TRAFFIC_OBSERVE = "traffic.observe"
CAP_THREAT_DETECT = "threat.detect"
CAP_DNS_OBSERVE = "dns.observe"
CAP_DNS_BLOCK = "dns.block"
CAP_HOST_INVENTORY = "host.inventory"

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
        "ntopng": {
            "enabled": True,
            "base_url": "http://127.0.0.1:3000",
            "timeout": 8,
        },
    },
}


def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
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


class Metric:
    """One measurement. Names are domain-based, never source-based."""

    __slots__ = ("name", "value", "labels", "is_counter")

    def __init__(self, name, value, labels=None, is_counter=False):
        self.name = name if name.startswith(METRIC_PREFIX) else \
            "%s_%s" % (METRIC_PREFIX, name)
        self.value = float(value)
        self.labels = labels or {}
        self.is_counter = is_counter


class Event:
    """One normalized observation.

    The shape is deliberately uniform across backends: someone (actor) reached
    for something (target), a rule matched, a verdict was reached.
    """

    __slots__ = ("timestamp", "kind", "source", "severity", "verdict",
                 "actor", "target", "network", "rule", "message")

    def __init__(self, timestamp, kind, source, message,
                 severity="info", verdict="observed",
                 actor=None, target=None, network=None, rule=None):
        if severity not in SEVERITIES:
            severity = "info"
        self.timestamp = int(timestamp)
        self.kind = kind
        self.source = source
        self.severity = severity
        self.verdict = verdict
        self.actor = actor or {}
        self.target = target or {}
        self.network = network or {}
        self.rule = rule or {}
        self.message = message

    # OTLP severity numbers: info=9, low=11, medium=13, high=17, critical=21
    _OTLP_SEVERITY = {"info": 9, "low": 11, "medium": 13, "high": 17,
                      "critical": 21}

    def severity_number(self):
        return self._OTLP_SEVERITY.get(self.severity, 9)

    def attributes(self):
        """Flatten to label form, omitting anything the source did not know.

        Empty values are dropped rather than exported as "", so label
        cardinality stays proportional to what a backend actually provides.
        """
        attrs = {
            "event_kind": self.kind,
            "source": self.source,
            "severity": self.severity,
            "verdict": self.verdict,
        }
        for prefix, group in (("actor", self.actor), ("target", self.target),
                              ("rule", self.rule)):
            for key, val in group.items():
                if val not in (None, ""):
                    attrs["%s_%s" % (prefix, key)] = str(val)
        for key, val in self.network.items():
            if val not in (None, ""):
                attrs[key] = str(val)
        return attrs


class Source:
    """One backend Flowsight reads from."""

    name = "source"
    capabilities = ()

    def __init__(self, cfg):
        self.cfg = cfg

    def collect(self):
        """Return (list[Metric], list[Event])."""
        raise NotImplementedError


class SuricataEve(Source):
    """Suricata alerts from eve.json.

    Tails rather than re-reads: eve.json grows without bound between rotations
    and re-parsing each cycle would be quadratic. Rotation is detected by inode
    change, not size, because a rotated file can briefly exceed the held offset.
    """

    name = "suricata"
    capabilities = (CAP_THREAT_DETECT,)

    # Suricata severity is 1 (worst) .. 4. Never pass that scale through.
    SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low"}

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
            # Start at end of file: replaying history on every restart would
            # flood the log backend with alerts already shipped.
            self._inode, self._offset = st.st_ino, st.st_size
            return False
        if st.st_ino != self._inode or st.st_size < self._offset:
            self._inode, self._offset = st.st_ino, 0
        return True

    def collect(self):
        path = self.cfg.get("eve_path")
        metrics, events = [], []
        if not path or not self._reset_if_rotated(path):
            return metrics, events

        by_severity = {}
        with open(path, "r", errors="replace") as fh:
            fh.seek(self._offset)
            for line in fh:
                if not line.endswith("\n"):  # partial write; pick it up later
                    break
                self._offset += len(line.encode("utf-8", "replace"))
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except ValueError:
                    continue
                if raw.get("event_type") != "alert":
                    continue

                alert = raw.get("alert", {})
                severity = self.SEVERITY_MAP.get(int(alert.get("severity", 3) or 3),
                                                 "medium")
                by_severity[severity] = by_severity.get(severity, 0) + 1
                self._alert_count += 1

                # Suricata "drop" means it was enforced; otherwise it only saw it.
                verdict = "blocked" if alert.get("action") == "blocked" else "observed"

                events.append(Event(
                    timestamp=_iso_to_nanos(raw.get("timestamp")),
                    kind="alert",
                    source=self.name,
                    severity=severity,
                    verdict=verdict,
                    message="%s [%s]" % (alert.get("signature", "alert"),
                                         alert.get("category", "")),
                    actor={"ip": raw.get("src_ip"), "port": raw.get("src_port")},
                    target={"ip": raw.get("dest_ip"), "port": raw.get("dest_port")},
                    network={"proto": raw.get("proto"),
                             "interface": raw.get("in_iface")},
                    rule={"id": alert.get("signature_id"),
                          "name": str(alert.get("signature", ""))[:200],
                          "category": str(alert.get("category", ""))[:100]},
                ))

        metrics.append(Metric("ids_alerts_total", self._alert_count,
                              {"source": self.name}, is_counter=True))
        for severity, count in sorted(by_severity.items()):
            metrics.append(Metric("ids_alerts_by_severity", count,
                                  {"source": self.name, "severity": severity}))
        return metrics, events


class UnboundStats(Source):
    """Resolver counters from unbound-control."""

    name = "unbound"
    capabilities = (CAP_DNS_OBSERVE, CAP_DNS_BLOCK)

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
            raise RuntimeError("unbound-control failed: %s"
                               % out.stderr.strip()[:200])

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
            metrics.append(Metric(name, value, {"source": self.name},
                                  is_counter=True))
        return metrics, []


class NtopngFlows(Source):
    """Flow, host and throughput data from ntopng (nDPI underneath).

    Uses REST v2 over loopback. ntopng must run with `-l=0` (disable login for
    localhost only) so no credentials are needed here, while remote access
    still requires a login.
    """

    name = "ntopng"
    capabilities = (CAP_TRAFFIC_OBSERVE, CAP_HOST_INVENTORY)

    FIELDS = [
        ("bytes", "traffic_bytes_total", True),
        ("packets", "traffic_packets_total", True),
        ("drops", "interface_drops_total", True),
        ("num_flows", "active_flows", False),
        ("num_hosts", "active_hosts", False),
        ("num_devices", "active_devices", False),
        ("throughput_bps", "throughput_bits_per_second", False),
        ("throughput_pps", "throughput_packets_per_second", False),
        ("alerted_flows", "alerted_flows", False),
    ]

    DIRECTIONAL = [("bytes_upload", "up"), ("bytes_download", "down")]

    def _get(self, path):
        url = "%s/lua/rest/v2/get/%s" % (self.cfg.get("base_url", "").rstrip("/"),
                                         path)
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.get("timeout", 8)) as r:
                body = r.read().decode("utf-8", "replace")
                if r.status != 200:
                    raise RuntimeError("ntopng %s returned HTTP %s" % (path, r.status))
        except urllib.error.HTTPError as exc:
            if exc.code in (301, 302, 401, 403):
                # Make the error state its own fix; this is nearly always the
                # login-bypass flag being lost, not a code problem.
                raise RuntimeError(
                    "ntopng requires authentication (HTTP %s). It must run with "
                    "'-l=0' (disable login for localhost). On OPNsense that flag "
                    "lives in /usr/local/etc/ntopng.conf and is STRIPPED whenever "
                    "the ntopng plugin is reconfigured - re-add it and restart "
                    "ntopng." % exc.code)
            raise
        try:
            return json.loads(body)
        except ValueError:
            raise RuntimeError("ntopng %s returned non-JSON (auth redirect?)" % path)

    def collect(self):
        metrics = []
        ifaces = self._get("ntopng/interfaces.lua").get("rsp", [])
        if not ifaces:
            raise RuntimeError("ntopng reported no interfaces")

        for iface in ifaces:
            ifid = iface.get("ifid")
            if ifid is None:
                continue
            ifname = str(iface.get("ifname", ifid))
            data = self._get("interface/data.lua?ifid=%s" % ifid).get("rsp", {})
            base = {"source": self.name, "interface": ifname}

            for field, name, is_counter in self.FIELDS:
                if field not in data:
                    continue
                try:
                    value = float(data[field])
                except (TypeError, ValueError):
                    continue
                metrics.append(Metric(name, value, base, is_counter=is_counter))

            for field, direction in self.DIRECTIONAL:
                if field not in data:
                    continue
                try:
                    value = float(data[field])
                except (TypeError, ValueError):
                    continue
                labels = dict(base)
                labels["direction"] = direction
                metrics.append(Metric("traffic_direction_bytes_total", value,
                                      labels, is_counter=True))
        return metrics, []


def _iso_to_nanos(stamp):
    """Convert a Suricata eve timestamp to UTC epoch nanoseconds.

    The offset is significant: parsing the naive part with mktime() and letting
    the local timezone decide silently skews every record when the host zone and
    the stamp offset disagree - and log backends drop future-dated entries
    without an error, so the symptom is logs that vanish while metrics arrive.
    """
    now_ns = int(time.time() * 1e9)
    if not stamp:
        return now_ns

    m = re.match(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$",
        str(stamp).strip())
    if not m:
        return now_ns

    try:
        tm = time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return now_ns

    epoch = calendar.timegm(tm)  # timegm treats the struct as UTC
    frac = float("0." + m.group(2)) if m.group(2) else 0.0

    tz = m.group(3)
    if tz and tz != "Z":
        tz = tz.replace(":", "")
        sign = -1 if tz[0] == "-" else 1
        epoch -= sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
    elif not tz:
        try:
            epoch = int(time.mktime(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")))
        except (ValueError, OverflowError):
            return now_ns

    ns = int((epoch + frac) * 1e9)
    if abs(ns - now_ns) > MAX_TIMESTAMP_SKEW_NS:
        return now_ns
    return ns


def _attrs(d):
    return [{"key": k, "value": {"stringValue": str(v)}}
            for k, v in d.items() if v not in (None, "")]


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
        for m in items:
            point = {"asDouble": m.value, "timeUnixNano": now,
                     "attributes": _attrs(m.labels)}
            if m.is_counter:
                point["startTimeUnixNano"] = self.start
                out.append({"name": m.name, "sum": {
                    "dataPoints": [point], "aggregationTemporality": 2,
                    "isMonotonic": True}})
            else:
                out.append({"name": m.name, "gauge": {"dataPoints": [point]}})
        self._post(self.cfg["otlp_metrics_endpoint"], {"resourceMetrics": [{
            "resource": self._resource(),
            "scopeMetrics": [{"scope": {"name": "flowsight"}, "metrics": out}]}]})

    def events(self, items):
        if not items:
            return
        out = [{
            "timeUnixNano": str(e.timestamp),
            "severityText": e.severity.upper(),
            "severityNumber": e.severity_number(),
            "body": {"stringValue": e.message},
            "attributes": _attrs(e.attributes()),
        } for e in items]
        self._post(self.cfg["otlp_logs_endpoint"], {"resourceLogs": [{
            "resource": self._resource(),
            "scopeLogs": [{"scope": {"name": "flowsight"}, "logRecords": out}]}]})


SOURCE_TYPES = {
    "suricata": SuricataEve,
    "unbound": UnboundStats,
    "ntopng": NtopngFlows,
}


def main():
    cfg = load_config()
    exporter = Exporter(cfg, int(time.time() * 1e9))

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

    caps = sorted({c for s in sources for c in s.capabilities})
    sys.stderr.write("flowsight: sources=%s capabilities=%s interval=%ss\n" % (
        ",".join(s.name for s in sources), ",".join(caps), cfg["interval_seconds"]))

    while True:
        metrics, events = [], []
        for src in sources:
            try:
                m, e = src.collect()
                metrics.extend(m)
                events.extend(e)
            except Exception as exc:
                sys.stderr.write("flowsight: source %s failed: %s\n" % (src.name, exc))

        for kind, fn, data in (("metrics", exporter.metrics, metrics),
                               ("events", exporter.events, events)):
            try:
                fn(data)
            except Exception as exc:
                sys.stderr.write("flowsight: export %s failed: %s\n" % (kind, exc))

        time.sleep(cfg["interval_seconds"])


if __name__ == "__main__":
    sys.exit(main())
