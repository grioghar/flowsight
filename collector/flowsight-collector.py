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
    "/usr/local/etc/flowsight/collector.json",   # FreeBSD / OPNsense
    "/etc/flowsight/collector.json",             # Debian-family
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
CAP_RULE_ANALYSE = "firewall.analyse"
CAP_TLS_OBSERVE = "tls.observe"

# The collector publishes what it is actually doing here, so the UI and any
# operator can see per-source health without parsing logs or guessing from
# config. Config says what was asked for; this says what is happening.
STATE_PATH = "/var/run/flowsight-collector.json"

def _platform_defaults():
    """Per-platform paths.

    The same backends live in different places on FreeBSD/OPNsense and on
    Debian-family Linux. Detecting once here keeps every call site free of
    platform conditionals, and config still overrides anything.
    """
    if os.path.exists("/usr/local/sbin/opnsense-version") or \
            os.uname()[0] == "FreeBSD":
        return {
            "unbound_control": "/usr/local/sbin/unbound-control",
            "unbound_config": "/var/unbound/unbound.conf",
            "eve_path": "/var/log/suricata/eve.json",
            "rulehygiene_bin": "/usr/local/sbin/flowsight-rulehygiene",
        }
    return {
        "unbound_control": "/usr/sbin/unbound-control",
        # Debian's unbound-control finds its own config; an empty value means
        # "do not pass -c", which is correct there and wrong on FreeBSD.
        "unbound_config": "",
        "eve_path": "/var/log/suricata/eve.json",
        "rulehygiene_bin": "/usr/local/sbin/flowsight-rulehygiene",
    }


_P = _platform_defaults()

DEFAULT_CONFIG = {
    "state_path": STATE_PATH,
    "otlp_metrics_endpoint": "http://127.0.0.1:4318/v1/metrics",
    "otlp_logs_endpoint": "http://127.0.0.1:4318/v1/logs",
    "host_name": "",
    "interval_seconds": 30,
    # Snapshot the resolver cache into the stored address-to-name map on this
    # cadence. CDN answers carry short TTLs and vanish from the cache quickly,
    # so a flow seen a minute later has nothing left to name it unless the map
    # was refreshed while the answer was still live. 0 disables.
    "dns_name_refresh_seconds": 60,
    # Re-derive squid's IPv6 localnet ACL from the current delegated prefix.
    "squid_v6_acl_refresh_seconds": 300,
    "sources": {
        "suricata": {"enabled": True, "eve_path": _P["eve_path"]},
        "unbound": {
            "enabled": True,
            "control": _P["unbound_control"],
            "config": _P["unbound_config"],
        },
        "ntopng": {
            "enabled": True,
            "base_url": "http://127.0.0.1:3000",
            "timeout": 8,
        },
        "squid": {
            "enabled": os.path.exists("/var/log/squid/access.log"),
            "access_log": "/var/log/squid/access.log",
        },
        "rulehygiene": {
            # pf-specific; there is no equivalent on nftables yet.
            "enabled": os.uname()[0] == "FreeBSD",
            "binary": _P["rulehygiene_bin"],
            # Rulesets change on human timescales; re-analysing every cycle
            # would burn CPU on a gateway to re-derive an identical answer.
            "interval_seconds": 900,
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


class SquidProxy(Source):
    """Proxy visibility from squid's access log.

    Configured for peek-and-splice, squid reads the TLS ClientHello to learn the
    destination hostname and then passes the connection through untouched. That
    yields hostname, destination and volume per connection **without decrypting
    anything** - the client still validates the origin server's real
    certificate, so nothing breaks and no CA has to be trusted.

    It is deliberately not tls.decrypt. Claiming that capability when the
    connection is spliced would be exactly the false claim SCHEMA.md warns about.
    """

    name = "squid"
    capabilities = (CAP_TLS_OBSERVE,)

    # <epoch>.<ms> <dur> <client> <code>/<status> <bytes> <method> <url> ...
    LINE = re.compile(
        r"^(\d+)\.(\d+)\s+(\d+)\s+(\S+)\s+(\S+?)/(\d+)\s+(\d+)\s+(\S+)\s+(\S+)")

    def __init__(self, cfg):
        Source.__init__(self, cfg)
        self._offset = None
        self._inode = None
        self._total = 0
        self._bytes = 0

    def _reset_if_rotated(self, path):
        try:
            st = os.stat(path)
        except OSError:
            return False
        if self._inode is None:
            self._inode, self._offset = st.st_ino, st.st_size
            return False
        if st.st_ino != self._inode or st.st_size < self._offset:
            self._inode, self._offset = st.st_ino, 0
        return True

    def collect(self):
        path = self.cfg.get("access_log", "/var/log/squid/access.log")
        metrics, events = [], []
        if not self._reset_if_rotated(path):
            return metrics, events

        by_host = {}
        with open(path, "r", errors="replace") as fh:
            fh.seek(self._offset)
            for line in fh:
                if not line.endswith("\n"):
                    break
                self._offset += len(line.encode("utf-8", "replace"))
                m = self.LINE.match(line.strip())
                if not m:
                    continue
                epoch, _ms, _dur, client, code, status, nbytes, method, url = m.groups()

                # squid logs the CONNECT twice: the tunnel setup and its close.
                # Counting both would double every connection.
                if code.startswith("NONE"):
                    continue

                host = url.split("//")[-1].split("/")[0]
                host = host.rsplit(":", 1)[0] if ":" in host else host
                self._total += 1
                self._bytes += int(nbytes)
                by_host[host] = by_host.get(host, 0) + int(nbytes)

                events.append(Event(
                    timestamp=int(epoch) * 1_000_000_000,
                    kind="flow",
                    source=self.name,
                    severity="info",
                    verdict="observed",
                    message="%s %s" % (method, host),
                    actor={"ip": client},
                    target={"domain": host},
                    network={"proto": "tls" if method == "CONNECT" else "http"},
                    rule={"category": code},
                ))

        metrics.append(Metric("proxy_connections_total", self._total,
                              {"source": self.name}, is_counter=True))
        metrics.append(Metric("proxy_bytes_total", self._bytes,
                              {"source": self.name}, is_counter=True))
        # Top destinations only: one series per hostname would be unbounded
        # cardinality, which is how you take down a metrics backend.
        for host, nbytes in sorted(by_host.items(), key=lambda kv: -kv[1])[:20]:
            metrics.append(Metric("proxy_host_bytes", nbytes,
                                  {"source": self.name, "host": host}))
        return metrics, events


class UnboundStats(Source):
    """Resolver counters from unbound-control."""

    name = "unbound"
    # Observation only. Reading resolver counters does not make this module able
    # to block anything - that is the policy provider's job. SCHEMA.md is
    # explicit that a false capability claim produces policy which silently
    # enforces nothing, and this source claiming dns.block was exactly that.
    capabilities = (CAP_DNS_OBSERVE,)

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


class RuleHygiene(Source):
    """Firewall ruleset analysis, via the rulehygiene module.

    Shells out rather than importing: the analysis is its own module with its
    own release cadence, and the collector should not carry a copy of its
    logic. Results are cached because rulesets change on human timescales.
    """

    name = "rulehygiene"
    capabilities = (CAP_RULE_ANALYSE,)

    def __init__(self, cfg):
        Source.__init__(self, cfg)
        self._last_run = 0.0
        self._cached = []

    def collect(self):
        interval = float(self.cfg.get("interval_seconds", 900))
        now = time.monotonic()
        if self._cached and (now - self._last_run) < interval:
            return self._cached, []

        # Invoke with sys.executable, not the module's own shebang: under
        # daemon(8) the PATH excludes /usr/local/bin, so "#!/usr/bin/env
        # python3" fails with "env: python3: No such file or directory".
        # Using the interpreter already running the collector is portable and
        # cannot drift from it.
        out = subprocess.run([sys.executable, self.cfg.get("binary"), "--json"],
                             capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            raise RuntimeError("rulehygiene failed: %s" % out.stderr.strip()[:200])
        doc = json.loads(out.stdout)

        score = doc.get("score", {})
        metrics = [
            Metric("firewall_risk_score", score.get("score", 0),
                   {"source": self.name}),
            Metric("firewall_rules_analysed", score.get("rules_analysed", 0),
                   {"source": self.name}),
        ]
        by_sev = {}
        for f in doc.get("findings", []):
            sev = f.get("severity", "info")
            by_sev[sev] = by_sev.get(sev, 0) + 1
        # Emit a zero for every severity so a cleared finding visibly drops to
        # zero rather than the series simply disappearing from the graph.
        for sev in SEVERITIES:
            metrics.append(Metric("firewall_findings", by_sev.get(sev, 0),
                                  {"source": self.name, "severity": sev}))

        self._cached = metrics
        self._last_run = now
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


def write_state(path, sources, results, exports):
    """Publish current health atomically. Never fatal - state is a convenience."""
    try:
        doc = {
            "updated": int(time.time()),
            "sources": [{
                "name": s.name,
                "capabilities": list(s.capabilities),
                "ok": results.get(s.name, {}).get("ok", False),
                "metrics": results.get(s.name, {}).get("metrics", 0),
                "events": results.get(s.name, {}).get("events", 0),
                "error": results.get(s.name, {}).get("error", ""),
            } for s in sources],
            "capabilities": sorted({c for s in sources for c in s.capabilities}),
            "exports": exports,
        }
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(doc, fh)
        os.replace(tmp, path)
    except Exception:
        pass


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
    "rulehygiene": RuleHygiene,
    "squid": SquidProxy,
}


DNSVIEW_BIN = "/usr/local/sbin/flowsight-dnsview"
_dns_names_at = [0.0]


def refresh_dns_names(cfg):
    """Fold the resolver cache into the stored address-to-name map.

    Kept here because the collector is the one component already running all
    the time. Names are what make a flow readable, and the cache entry that
    supplies a name may only exist for a few seconds - nobody has the UI open
    for most of them.

    Entirely optional: absent the DNS module, or on a platform without it, this
    does nothing and the collector carries on.
    """
    every = cfg.get("dns_name_refresh_seconds", 0)
    if not every or not os.path.exists(DNSVIEW_BIN):
        return
    now = time.monotonic()
    if _dns_names_at[0] and now - _dns_names_at[0] < every:
        return
    _dns_names_at[0] = now
    try:
        r = subprocess.run([sys.executable, DNSVIEW_BIN, "names"],
                           capture_output=True, text=True, timeout=90)
        if r.returncode != 0:
            sys.stderr.write("flowsight: dns name refresh failed: %s\n"
                             % (r.stderr or "").strip()[:200])
    except Exception as exc:
        sys.stderr.write("flowsight: dns name refresh error: %s\n" % exc)


SQUID_V6ACL_BIN = "/usr/local/sbin/flowsight-squid-v6acl"
_v6acl_at = [0.0]


def refresh_squid_v6_acl(cfg):
    """Keep squid's IPv6 local-network ACL in step with the delegated prefix.

    The prefix is tracked from the WAN delegation and carries a short lifetime,
    so it changes without warning. When it does, intercepted IPv6 clients start
    getting TCP_DENIED and nothing on the firewall explains why. The script is
    cheap and rewrites only on an actual change, so running it on the collector
    loop costs nothing and removes a failure that would otherwise appear days
    later with no obvious cause.
    """
    every = cfg.get("squid_v6_acl_refresh_seconds", 300)
    if not every or not os.path.exists(SQUID_V6ACL_BIN):
        return
    now = time.monotonic()
    if _v6acl_at[0] and now - _v6acl_at[0] < every:
        return
    _v6acl_at[0] = now
    try:
        subprocess.run([SQUID_V6ACL_BIN], capture_output=True, text=True, timeout=60)
    except Exception as exc:
        sys.stderr.write("flowsight: squid v6 acl refresh failed: %s\n" % exc)


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

    state_path = cfg.get("state_path", STATE_PATH)

    while True:
        metrics, events, results = [], [], {}
        for src in sources:
            try:
                m, e = src.collect()
                metrics.extend(m)
                events.extend(e)
                results[src.name] = {"ok": True, "metrics": len(m), "events": len(e)}
            except Exception as exc:
                sys.stderr.write("flowsight: source %s failed: %s\n" % (src.name, exc))
                results[src.name] = {"ok": False, "metrics": 0, "events": 0,
                                     "error": str(exc)[:300]}

        exports = {}
        for kind, fn, data in (("metrics", exporter.metrics, metrics),
                               ("events", exporter.events, events)):
            try:
                fn(data)
                exports[kind] = {"ok": True, "count": len(data)}
            except Exception as exc:
                sys.stderr.write("flowsight: export %s failed: %s\n" % (kind, exc))
                exports[kind] = {"ok": False, "count": len(data), "error": str(exc)[:300]}

        refresh_dns_names(cfg)
        refresh_squid_v6_acl(cfg)
        write_state(state_path, sources, results, exports)
        time.sleep(cfg["interval_seconds"])


if __name__ == "__main__":
    sys.exit(main())
