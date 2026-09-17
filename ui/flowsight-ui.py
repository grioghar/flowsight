#!/usr/bin/env python3
"""Flowsight UI - the single pane over modules, telemetry and policy.

Deliberately NOT a dashboard replacement. Grafana already renders timeseries
better than anything written here would. This shows what Grafana cannot: which
modules are installed, which capabilities they provide, what policy is declared,
and what applying it would change.

Security posture, because this is a management surface on a firewall:

  * binds to 127.0.0.1 by default
  * READ-ONLY - it can run `plan`, never `apply`. Enforcement stays on the CLI
    where it is deliberate and auditable.
  * ships no authentication, so exposing it beyond loopback means putting an
    authenticating reverse proxy in front. The default refuses to be casually
    dangerous.

Stdlib only, no build step and no CDN: an appliance should not need internet
access to render its own management page.
"""

import ipaddress
import json
import os
import re
import shutil
import subprocess
import time
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_PATHS = [
    os.environ.get("FLOWSIGHT_UI_CONFIG", ""),
    "/usr/local/etc/flowsight/ui.json",   # FreeBSD / OPNsense
    "/etc/flowsight/ui.json",             # Debian-family
]

DEFAULT_CONFIG = {
    "bind": "127.0.0.1",
    "port": 8080,
    "metrics_url": "http://127.0.0.1:9009/prometheus",
    "metrics_tenant": "anonymous",
    "logs_url": "http://127.0.0.1:3100",
    "policy_file": "/usr/local/etc/flowsight/policy.yaml",
    "policy_bin": "/usr/local/sbin/flowsight-policy",
    "collector_service": "flowsight_collector",
    "collector_state": "/var/run/flowsight-collector.json",
    "ntopng_url": "http://127.0.0.1:3000",
    "hostmap_url": "http://192.168.1.252:9099/hostmap.json",
    "dhcp_leases": "/var/db/dnsmasq.leases",
    "collector_config": "/usr/local/etc/flowsight/collector.json",
    # Writes are off unless explicitly enabled. The UI has no authentication of
    # its own; only enable this where something in front of it authenticates,
    # such as the OPNsense GUI proxy.
    "allow_write": False,
}

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")

# Query string of the request being served, for handlers that take parameters.
FLOWSIGHT_VERSION = "0.4.0"

_QUERY = {}


def py_cmd(script, *args):
    """Run one of our own scripts with the interpreter already running us.

    daemon(8) starts services with a minimal PATH that excludes
    /usr/local/bin, so a portable "#!/usr/bin/env python3" shebang fails with
    "env: python3: No such file or directory". Relying on the shebang has now
    broken four separate call sites; routing every internal invocation through
    here is the fix that stays fixed.
    """
    return [sys.executable, script] + list(args)


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    for path in CONFIG_PATHS:
        if path and os.path.isfile(path):
            try:
                with open(path) as fh:
                    cfg.update(json.load(fh))
            except Exception as exc:
                sys.stderr.write("flowsight-ui: bad config %s: %s\n" % (path, exc))
            break
    return cfg


CFG = load_config()


def _promql(query):
    url = "%s/api/v1/query?%s" % (CFG["metrics_url"].rstrip("/"),
                                  urllib.parse.urlencode({"query": query}))
    req = urllib.request.Request(url, headers={"X-Scope-OrgID": CFG["metrics_tenant"]})
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _logql(query, limit=25):
    url = "%s/loki/api/v1/query_range?%s" % (
        CFG["logs_url"].rstrip("/"),
        urllib.parse.urlencode({"query": query, "limit": limit,
                                "direction": "backward"}))
    req = urllib.request.Request(url, headers={"X-Scope-OrgID": CFG["metrics_tenant"]})
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def api_status():
    """Module and capability inventory, plus collector health.

    Capabilities are split by what they actually mean. Observation and
    enforcement are different things, and collapsing them into one list makes
    the UI claim the system can block when it can only watch.
    """
    out = {"collector": "unknown", "sources": [],
           "observe_capabilities": [], "enforce_capabilities": [],
           "stale": False, "errors": []}

    svc = CFG["collector_service"]
    if SAFE_NAME.match(svc):
        try:
            r = subprocess.run(["/usr/sbin/service", svc, "status"],
                               capture_output=True, text=True, timeout=10)
            out["collector"] = "running" if r.returncode == 0 else "stopped"
        except Exception as exc:
            out["errors"].append("service check: %s" % exc)

    # The collector publishes what it is actually doing. Preferred over config,
    # which only says what was asked for, and over metrics, which cannot show a
    # source that is failing rather than merely quiet.
    state = {}
    try:
        with open(CFG["collector_state"]) as fh:
            state = json.load(fh)
    except Exception:
        pass

    if state:
        age = max(0, int(__import__("time").time()) - int(state.get("updated", 0)))
        # A stale state file means the collector died without clearing it.
        out["stale"] = age > 180
        out["state_age_seconds"] = age
        out["observe_capabilities"] = state.get("capabilities", [])
        by_name = {s["name"]: s for s in state.get("sources", [])}
    else:
        by_name = {}
        out["errors"].append("collector has not published state yet")

    series = {}
    try:
        res = _promql('count by (source) ({__name__=~"flowsight_.*"})')
        for row in res.get("data", {}).get("result", []):
            series[row["metric"].get("source", "?")] = int(float(row["value"][1]))
    except Exception as exc:
        out["errors"].append("metrics: %s" % exc)

    for name in sorted(set(list(by_name) + list(series))):
        s = by_name.get(name, {})
        out["sources"].append({
            "name": name,
            "ok": s.get("ok", None),
            "capabilities": s.get("capabilities", []),
            "error": s.get("error", ""),
            "series": series.get(name, 0),
        })

    try:
        policy_out = subprocess.run(
            py_cmd(CFG["policy_bin"], "status", "-f", CFG["policy_file"]),
            capture_output=True, text=True, timeout=20)
        caps = []
        for line in policy_out.stdout.splitlines():
            m = re.search(r"capabilities=(\S+)", line)
            if m:
                caps.extend(m.group(1).split(","))
        out["enforce_capabilities"] = sorted(set(caps))
    except Exception as exc:
        out["errors"].append("policy status: %s" % exc)

    return out


def api_summary():
    wanted = {
        "throughput_bits_per_second": "Throughput (bps)",
        "active_flows": "Active flows",
        "active_hosts": "Active hosts",
        "active_devices": "Devices",
        "dns_queries_total": "DNS queries",
        "ids_alerts_total": "IDS alerts",
    }
    out = []
    for metric, label in wanted.items():
        try:
            res = _promql("flowsight_%s" % metric)
            rows = res.get("data", {}).get("result", [])
            value = sum(float(r["value"][1]) for r in rows) if rows else None
        except Exception:
            value = None
        out.append({"label": label, "value": value})
    return out


def api_alerts():
    try:
        res = _logql('{service_name="flowsight-collector"} | source="suricata"')
        rows = []
        for stream in res.get("data", {}).get("result", []):
            lbl = stream.get("stream", {})
            for ts, body in stream.get("values", []):
                rows.append({
                    "ts": int(ts) // 1_000_000_000,
                    "severity": lbl.get("severity", "info"),
                    "actor": lbl.get("actor_ip", ""),
                    "target": lbl.get("target_ip", ""),
                    "verdict": lbl.get("verdict", ""),
                    "message": body,
                })
        rows.sort(key=lambda r: r["ts"], reverse=True)
        return {"alerts": rows[:25]}
    except Exception as exc:
        return {"alerts": [], "error": str(exc)}


def _ntopng(path):
    url = "%s/lua/rest/v2/get/%s" % (CFG["ntopng_url"].rstrip("/"), path)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def _lease_names():
    """Address -> local device name, from DHCP and static reservations."""
    out = {}
    try:
        with open("/var/db/dnsmasq.leases") as fh:
            for line in fh:
                p = line.split()
                if len(p) >= 4 and p[3] != "*":
                    out[p[2]] = p[3]
    except Exception:
        pass
    try:
        import glob as _glob
        for conf in ["/usr/local/etc/dnsmasq.conf"] + sorted(
                _glob.glob("/usr/local/etc/dnsmasq.conf.d/*.conf")):
            try:
                with open(conf) as fh:
                    for line in fh:
                        if not line.startswith("dhcp-host="):
                            continue
                        parts = line.strip().split("=", 1)[1].split(",")
                        ip = next((x for x in parts if x.count(".") == 3), "")
                        label = parts[-1]
                        if ip and label and "." not in label and ":" not in label:
                            out.setdefault(ip, label)
            except OSError:
                continue
    except Exception:
        pass
    return out


_DNS_NAMES = {"data": {}, "at": 0.0}


def _dns_names():
    """Address -> name, cached.

    Refreshing means re-reading the resolver cache and merging it into the
    stored map, which costs about a second; the pages that use it re-render
    every fifteen. A failure keeps the previous map rather than blanking every
    name on the page.
    """
    now = time.time()
    if _DNS_NAMES["data"] and now - _DNS_NAMES["at"] < 120:
        return _DNS_NAMES["data"]
    out = _dnsview("names")
    names = out.get("names") if isinstance(out, dict) else None
    if names:
        _DNS_NAMES["data"] = names
        _DNS_NAMES["at"] = now
    return _DNS_NAMES["data"]


def api_hosts():
    """Per-device report: who is on the network and what they are doing."""
    try:
        rsp = _ntopng("host/active.lua?ifid=0&perPage=100").get("rsp", {})
        names = _dns_names()
        local = _lease_names()
        rows = []
        for h in rsp.get("data", []):
            b = h.get("bytes", {}) or {}
            ip = h.get("ip", "")
            rows.append({
                "ip": ip,
                "name": (h.get("name") or "") if h.get("name") != h.get("ip") else "",
                # A local address is best named by what the device calls itself;
                # a remote one by the name it was resolved from. Consulting DHCP
                # first means our own hosts stop showing as bare addresses.
                "dns_name": local.get(ip, "") or names.get(ip, ""),
                "mac": h.get("mac", ""),
                "country": h.get("country", ""),
                "sent": b.get("sent", 0),
                "recvd": b.get("recvd", 0),
                "total": b.get("total", 0),
                # ntopng returns num_flows as {total, as_client, as_server}
                "flows": (h.get("num_flows") or {}).get("total", 0)
                         if isinstance(h.get("num_flows"), dict)
                         else h.get("num_flows", 0),
                "alerts": h.get("num_alerts", 0),
                "blacklisted": bool(h.get("is_blacklisted")),
                "local": bool(h.get("is_localhost")),
                "last_seen": h.get("last_seen", 0),
            })
        rows.sort(key=lambda r: r["total"], reverse=True)
        return {"hosts": rows}
    except Exception as exc:
        return {"hosts": [], "error": str(exc)}


def api_flows():
    """Live sessions, with the nDPI-identified application per flow."""
    try:
        rsp = _ntopng("flow/active.lua?ifid=0&perPage=100").get("rsp", {})
        raw = rsp.get("data", rsp) if isinstance(rsp, dict) else rsp
        names = _dns_names()
        local = _lease_names()
        rows = []
        for f in raw or []:
            cli = f.get("client", {}) or {}
            srv = f.get("server", {}) or {}
            proto = f.get("protocol", {}) or {}
            b = f.get("bytes", {}) or {}
            cip = cli.get("ip") or cli.get("name", "")
            sip = srv.get("ip") or srv.get("name", "")
            rows.append({
                "client": cip,
                "server": sip,
                # The client is usually ours, so a device name fits it; the
                # server is usually not, and the name it was resolved from is
                # the only thing that says what it actually is.
                "client_name": local.get(cip, "") or names.get(cip, ""),
                "server_name": names.get(sip, "") or local.get(sip, ""),
                "app": proto.get("l7") or proto.get("l7_proto") or
                       proto.get("l4") or "",
                "l4": proto.get("l4", ""),
                "bytes": b.get("total", b.get("sent", 0)) if isinstance(b, dict) else b,
                "duration": f.get("duration", 0),
            })
        rows.sort(key=lambda r: r["bytes"] or 0, reverse=True)
        return {"flows": rows}
    except Exception as exc:
        return {"flows": [], "error": str(exc)}


RANGES = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}

# Metrics worth plotting over time, with the query used for each.
SERIES = [
    ("throughput", "Throughput (bps)",
     'sum(flowsight_throughput_bits_per_second)'),
    ("flows", "Active flows", 'sum(flowsight_active_flows)'),
    ("hosts", "Active hosts", 'sum(flowsight_active_hosts)'),
    ("dns", "DNS queries/s", 'sum(rate(flowsight_dns_queries_total[5m]))'),
    ("traffic", "Traffic (bytes/s)",
     'sum(rate(flowsight_traffic_direction_bytes_total[5m]))'),
    ("alerts", "IDS alerts/h",
     'sum(increase(flowsight_ids_alerts_total[1h]))'),
]


def _reachable(url, timeout=4):
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status < 500
    except urllib.error.HTTPError:
        return True          # answered, which is all we are testing
    except Exception:
        return False


def api_setup():
    """Guided setup: what is required, what is present, and how to fix the rest.

    Every failing check carries the exact command that fixes it. A setup screen
    that only says "not configured" makes the operator go hunting, which is the
    part of deployment that actually costs time.
    """
    checks = []

    def add(name, ok, detail, fix=""):
        checks.append({"name": name, "ok": bool(ok), "detail": detail, "fix": fix})

    # --- collector ---------------------------------------------------------
    state, age = {}, None
    try:
        with open(CFG["collector_state"]) as fh:
            state = json.load(fh)
        age = int(time.time()) - int(state.get("updated", 0))
    except Exception:
        pass
    add("Collector running", bool(state) and age is not None and age < 180,
        ("last published %ss ago" % age) if age is not None
        else "no state file at %s" % CFG["collector_state"],
        "service flowsight_collector start")

    # --- each source -------------------------------------------------------
    for src in state.get("sources", []):
        add("Source: %s" % src["name"], src.get("ok"),
            (src.get("error") or "%s metrics, %s events"
             % (src.get("metrics", 0), src.get("events", 0)))[:200],
            "check the backend, then: service flowsight_collector restart")

    # --- telemetry backends ------------------------------------------------
    add("Metrics backend", _reachable(CFG["metrics_url"].rstrip("/") + "/api/v1/query?query=1"),
        CFG["metrics_url"], "point metrics_url at a Prometheus-compatible endpoint")
    add("Logs backend", _reachable(CFG["logs_url"].rstrip("/") + "/ready"),
        CFG["logs_url"], "point logs_url at a Loki endpoint")
    add("ntopng", _reachable(CFG["ntopng_url"].rstrip("/") +
                             "/lua/rest/v2/get/ntopng/interfaces.lua"),
        CFG["ntopng_url"] + " (needs -l=0 for loopback access)",
        "add '-l=0' to ntopng.conf and restart ntopng")

    # --- policy ------------------------------------------------------------
    add("Policy file", os.path.isfile(CFG["policy_file"]), CFG["policy_file"],
        "create it in the Policy tab, or copy policy.example.yaml")

    cats = []
    try:
        cdir = "/usr/local/share/flowsight/categories"
        cats = sorted(f[:-5] for f in os.listdir(cdir) if f.endswith(".list"))
    except Exception:
        pass
    add("Category feeds", bool(cats),
        (", ".join(cats) if cats else "none cached"),
        "flowsight-categories update")

    add("Writes enabled", bool(CFG.get("allow_write")),
        "editing from this UI is %s" % ("on" if CFG.get("allow_write") else "off"),
        "set allow_write in ui.json - only behind an authenticating proxy")

    done = sum(1 for c in checks if c["ok"])
    return {"checks": checks, "passed": done, "total": len(checks)}


def api_timeseries():
    """Historical series for the reports view.

    Uses Mimir's query_range rather than repeated instant queries: one request
    per series instead of hundreds, and the server picks sane step alignment.
    """
    rng = (_QUERY.get("range") or ["24h"])[0]
    seconds = RANGES.get(rng, 86400)
    now = int(time.time())
    # ~120 points regardless of window, so the payload stays small and the
    # chart stays legible at every range.
    step = max(15, seconds // 120)

    out = {"range": rng, "step": step, "series": []}
    for key, label, query in SERIES:
        try:
            url = "%s/api/v1/query_range?%s" % (
                CFG["metrics_url"].rstrip("/"),
                urllib.parse.urlencode({"query": query, "start": now - seconds,
                                        "end": now, "step": step}))
            req = urllib.request.Request(
                url, headers={"X-Scope-OrgID": CFG["metrics_tenant"]})
            with urllib.request.urlopen(req, timeout=20) as resp:
                doc = json.loads(resp.read().decode("utf-8", "replace"))
            result = doc.get("data", {}).get("result", [])
            points = [[int(float(t)), float(v)]
                      for t, v in (result[0].get("values", []) if result else [])]
            out["series"].append({"key": key, "label": label, "points": points})
        except Exception as exc:
            out["series"].append({"key": key, "label": label, "points": [],
                                  "error": str(exc)[:160]})
    return out


def api_apps():
    """Application breakdown from nDPI, with ntopng's breed classification."""
    try:
        rows = _ntopng("interface/l7/data.lua?ifid=0").get("rsp", []) or []
        out = []
        for a in rows:
            app = (a.get("application") or {})
            b = (a.get("bytes") or {})
            out.append({
                "app": app.get("name", "?"),
                "breed": a.get("breed", ""),
                "flows": a.get("tot_num_flows", 0),
                "bytes": b.get("total", 0),
                "sent": b.get("sent", 0),
                "rcvd": b.get("rcvd", 0),
            })
        out.sort(key=lambda r: r["bytes"], reverse=True)
        return {"apps": out}
    except Exception as exc:
        return {"apps": [], "error": str(exc)}


_HOSTMAP = {"at": 0.0, "data": {}}


def _hostmap():
    """MAC -> hypervisor guest identity, cached.

    Every virtual NIC shares one OUI, so vendor lookup calls all 41 guests
    "Proxmox Server Solutions GmbH". The hypervisor knows which MAC is which
    guest; this is that answer. Cached, and a fetch failure keeps the old map
    rather than blanking every name.
    """
    now = time.time()
    if _HOSTMAP["data"] and now - _HOSTMAP["at"] < 600:
        return _HOSTMAP["data"]
    try:
        req = urllib.request.Request(CFG["hostmap_url"])
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        if isinstance(data, dict) and data:
            _HOSTMAP["data"] = {k.upper(): v for k, v in data.items()}
            _HOSTMAP["at"] = now
    except Exception:
        pass
    return _HOSTMAP["data"]


def _leases():
    """MAC -> DHCP-assigned hostname, for devices the hypervisor knows nothing
    about (phones, IoT, TVs)."""
    out = {}
    try:
        with open(CFG["dhcp_leases"]) as fh:
            for line in fh:
                parts = line.split()
                # dnsmasq: <expiry> <mac> <ip> <hostname> <client-id>
                if len(parts) >= 4 and ":" in parts[1]:
                    name = parts[3]
                    if name and name != "*":
                        out[parts[1].upper()] = {"name": name, "ip": parts[2]}
    except Exception:
        pass
    return out


BROADCAST = "FF:FF:FF:FF:FF:FF"


def _l2_pseudo(mac):
    """Name the addresses that are not devices at all.

    ntopng lists broadcast and multicast destinations alongside real hosts, and
    with no OUI to look up they land in the inventory as "Unknown" - which reads
    like a device we failed to identify rather than one that never existed.
    IPv4 multicast is 01:00:5E:.., IPv6 is 33:33:.., and the low bit of the
    first octet marks any other multicast group.
    """
    if not mac:
        return ""
    if mac == BROADCAST:
        return "broadcast"
    if mac.startswith(("01:00:5E", "33:33")):
        return "multicast"
    try:
        if int(mac.split(":")[0], 16) & 1:
            return "multicast"
    except ValueError:
        pass
    return ""


def api_devices():
    """Layer-2 device inventory: manufacturer and device type per MAC.

    This is the closest thing available to OS/device identification - ntopng
    derives it from the OUI and traffic fingerprint. It is a separate view from
    Hosts because one MAC can carry several IPs.
    """
    try:
        rsp = _ntopng("mac/macs_list.lua?ifid=0&perPage=250").get("rsp", {})
        rows = rsp.get("data", rsp) if isinstance(rsp, dict) else rsp
        hostmap, leases = _hostmap(), _leases()
        out = []
        for m in rows or []:
            mac = (m.get("mac") or "").upper()
            name = m.get("name") or {}
            label = name.get("host_label", "") if isinstance(name, dict) else str(name)
            guest = hostmap.get(mac) or {}
            lease = leases.get(mac) or {}

            # Identity, best source first: the hypervisor knows its own guests,
            # DHCP knows what a device called itself, ntopng's label is a last
            # resort and is often just the IP.
            pseudo = _l2_pseudo(mac)
            identity = guest.get("name") or lease.get("name") or label
            if guest:
                gk = guest.get("kind", "")
                kind = "hypervisor" if gk == "node" else \
                    "%s %s" % (gk.upper(), guest.get("id", ""))
            elif lease:
                kind = "dhcp"
            elif pseudo:
                kind = pseudo
            else:
                kind = (m.get("device_type") or {}).get("device_type_label", "")

            out.append({
                "mac": mac,
                "identity": identity,
                "kind": kind,
                "status": guest.get("status", ""),
                "label": label,
                "manufacturer": m.get("manufacturer", "") or "",
                "device_type": (m.get("device_type") or {}).get("device_type_label", ""),
                "hosts": m.get("hosts", 0),
                "sent": m.get("bytes_sent", 0),
                "rcvd": m.get("bytes_rcvd", 0),
                "traffic": m.get("traffic", 0),
                "seen_since": m.get("seen_since", 0),
            })
        out.sort(key=lambda r: r["traffic"], reverse=True)
        # Broadcast and multicast groups are destinations, not devices. They are
        # kept, because their traffic is real and worth seeing, but they are not
        # mixed into the inventory - two dozen of them buried the seventy hosts
        # this page exists to show.
        real = [r for r in out if r["kind"] not in ("multicast", "broadcast")]
        pseudo = [r for r in out if r["kind"] in ("multicast", "broadcast")]
        named = sum(1 for r in real if r["identity"] and r["identity"] != r["mac"])
        return {"devices": real, "pseudo": pseudo, "named": named,
                "total": len(real), "pseudo_count": len(pseudo),
                "hostmap_entries": len(hostmap), "lease_entries": len(leases)}
    except Exception as exc:
        return {"devices": [], "error": str(exc)}


def api_policy():
    """Declared policy and what applying it would change. Never applies."""
    out = {"exists": os.path.isfile(CFG["policy_file"]),
           "path": CFG["policy_file"], "status": "", "plan": "", "error": ""}
    if not out["exists"]:
        out["error"] = "No policy file at %s" % CFG["policy_file"]
        return out
    for key, cmd in (("status", "status"), ("plan", "plan")):
        try:
            r = subprocess.run(py_cmd(CFG["policy_bin"], cmd, "-f", CFG["policy_file"]),
                               capture_output=True, text=True, timeout=30)
            out[key] = r.stdout or r.stderr
        except Exception as exc:
            out["error"] = str(exc)
    return out


def api_policy_source():
    """The raw policy document, for editing."""
    path = CFG["policy_file"]
    try:
        with open(path) as fh:
            return {"path": path, "text": fh.read(), "exists": True,
                    "writable": bool(CFG.get("allow_write"))}
    except (OSError, IOError):
        return {"path": path, "exists": False,
                "writable": bool(CFG.get("allow_write")),
                "text": "version: 1\n\ngroups: {}\n\npolicies: []\n"}


def api_config():
    """Collector configuration, for editing."""
    path = CFG["collector_config"]
    try:
        with open(path) as fh:
            return {"path": path, "text": fh.read(), "exists": True,
                    "writable": bool(CFG.get("allow_write"))}
    except (OSError, IOError) as exc:
        return {"path": path, "exists": False, "text": "",
                "writable": bool(CFG.get("allow_write")), "error": str(exc)}


def save_policy(text):
    """Validate, then write. Never the other way round.

    The policy file is compiled into DNS enforcement, so a document that does
    not compile must never reach disk - it would either break the next apply or,
    worse, look saved while enforcing nothing.
    """
    path = CFG["policy_file"]
    tmp = path + ".candidate"
    with open(tmp, "w") as fh:
        fh.write(text)
    try:
        check = subprocess.run(py_cmd(CFG["policy_bin"], "plan", "-f", tmp),
                               capture_output=True, text=True, timeout=40)
        if check.returncode != 0:
            return {"ok": False,
                    "error": (check.stderr or check.stdout).strip()[:600]}
        if os.path.exists(path):
            shutil.copy2(path, "%s.bak-%s" % (path, time.strftime("%Y%m%d%H%M%S")))
        os.replace(tmp, path)
        return {"ok": True, "plan": check.stdout}
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def apply_policy():
    r = subprocess.run(py_cmd(CFG["policy_bin"], "apply", "-f", CFG["policy_file"]),
                       capture_output=True, text=True, timeout=90)
    return {"ok": r.returncode == 0, "output": (r.stdout or r.stderr).strip()[:2000]}


def save_config(text):
    """Validate JSON, back up, write, then restart the collector."""
    try:
        json.loads(text)
    except ValueError as exc:
        return {"ok": False, "error": "not valid JSON: %s" % exc}
    path = CFG["collector_config"]
    if os.path.exists(path):
        shutil.copy2(path, "%s.bak-%s" % (path, time.strftime("%Y%m%d%H%M%S")))
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)
    svc = CFG["collector_service"]
    out = ""
    if SAFE_NAME.match(svc):
        r = subprocess.run(["/usr/sbin/service", svc, "restart"],
                           capture_output=True, text=True, timeout=60)
        out = (r.stdout or r.stderr).strip()[:400]
    return {"ok": True, "output": out}


ENROLL_BIN = "/usr/local/sbin/flowsight-enroll"
ENROLL_STATE = "/var/db/flowsight"
ZONES_FILE = "/usr/local/etc/flowsight/zones.json"
ENROLL_RULES_FILE = "/usr/local/etc/flowsight/enroll-rules.json"


def _json_file(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return default


def api_enroll():
    """Enrollment state: what each device was identified as, and by which rule.

    Reads the registry the enrolment engine writes rather than invoking it, so
    that rendering a page never waits on ntopng or the hypervisor.
    """
    zones = _json_file(ZONES_FILE, {"zones": [], "mode": "monitor"})
    reg = _json_file(os.path.join(ENROLL_STATE, "enroll-registry.json"),
                     {"devices": {}})
    devices = list(reg.get("devices", {}).values())
    claims = []
    try:
        with open(os.path.join(ENROLL_STATE, "enroll-claims.jsonl")) as fh:
            for line in fh.readlines()[-100:]:
                try:
                    claims.append(json.loads(line))
                except ValueError:
                    continue
    except Exception:
        pass
    counts = {}
    for d in devices:
        counts[d.get("zone") or "?"] = counts.get(d.get("zone") or "?", 0) + 1
    devices.sort(key=lambda d: (d.get("zone") or "", d.get("hostname") or ""))
    return {
        "mode": zones.get("mode", "monitor"),
        "captive_policy": zones.get("captive_policy", "self_service"),
        "zones": zones.get("zones", []),
        "counts": counts,
        "devices": devices,
        "claims": list(reversed(claims)),
        "unidentified": sum(1 for d in devices
                            if d.get("state") == "unidentified"),
        "pinned": sum(1 for d in devices if d.get("state") == "pinned"),
        "total": len(devices),
    }


def api_enroll_zones():
    return _json_file(ZONES_FILE, {"zones": []})


def api_enroll_rules():
    return _json_file(ENROLL_RULES_FILE, {"rules": []})


def _enroll_run(*args):
    try:
        r = subprocess.run(py_cmd(ENROLL_BIN, *args), capture_output=True,
                           text=True, timeout=180)
        return {"ok": r.returncode == 0, "out": r.stdout, "err": r.stderr}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _save_enroll_json(path, body, key):
    """Replace a configuration document after checking it parses and is shaped.

    A malformed zone or rule file does not fail loudly - it makes the engine
    fall back to its empty default, which would quarantine the whole network on
    the next apply. So nothing is written until it parses and carries the list
    it is supposed to carry.
    """
    text = body.get("text")
    if text is None:
        return {"ok": False, "error": "no text supplied"}
    try:
        doc = json.loads(text)
    except ValueError as exc:
        return {"ok": False, "error": "not valid JSON: %s" % exc}
    if not isinstance(doc.get(key), list):
        return {"ok": False, "error": 'expected a "%s" list' % key}
    if key == "rules":
        for r in doc["rules"]:
            for cond in _walk_conds(r.get("when", {})):
                for ck, cv in cond.items():
                    if ck.endswith("_re"):
                        try:
                            re.compile(cv)
                        except re.error as exc:
                            return {"ok": False,
                                    "error": "rule %r: bad regex %r: %s"
                                             % (r.get("id"), cv, exc)}
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "saved": path, "count": len(doc[key])}


def _walk_conds(cond):
    yield cond
    for sub in cond.get("any", []) or []:
        for c in _walk_conds(sub):
            yield c


def enroll_assign(body):
    mac = (body.get("mac") or "").strip().upper()
    zone = (body.get("zone") or "").strip()
    if not re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$", mac):
        return {"ok": False, "error": "not a MAC address"}
    zones = {z["id"] for z in _json_file(ZONES_FILE, {"zones": []})["zones"]}
    if zone not in zones:
        return {"ok": False, "error": "unknown zone %r" % zone}
    return _enroll_run("assign", mac, zone)


DNSVIEW_BIN = "/usr/local/sbin/flowsight-dnsview"


def _qint(name, default, low, high):
    """A bounded integer from the query string.

    Bounded rather than merely parsed: these become row limits and time windows
    on a store holding millions of queries, and an unbounded value turns a page
    load into a scan that blocks the resolver's own writer.
    """
    try:
        v = int((_QUERY.get(name) or [default])[0])
    except (TypeError, ValueError):
        return default
    return max(low, min(high, v))


def _qstr(name, maxlen=253):
    return (_QUERY.get(name) or [""])[0][:maxlen]


def _dnsview(*args):
    """Run the DNS module and return its JSON.

    Arguments are passed as a list, never a shell string, and the module itself
    binds them as SQL parameters - a client filter is a value, never fragments
    of a query.
    """
    try:
        r = subprocess.run(py_cmd(DNSVIEW_BIN, *args), capture_output=True,
                           text=True, timeout=180)
    except Exception as exc:
        return {"error": str(exc)}
    if r.stdout.strip():
        try:
            return json.loads(r.stdout)
        except ValueError:
            pass
    return {"error": (r.stderr or "no output from flowsight-dnsview").strip()[:400]}


def api_dns():
    return _dnsview("overview",
                    "--hours", str(_qint("hours", 24, 1, 720)),
                    "--limit", str(_qint("limit", 25, 1, 200)),
                    "--interval", str(_qint("interval", 10, 1, 10)))


def api_dns_recent():
    args = ["recent", "--limit", str(_qint("limit", 200, 1, 1000))]
    client, domain = _qstr("client", 64), _qstr("domain")
    if client:
        args += ["--client", client]
    if domain:
        args += ["--domain", domain]
    if _qstr("blocked", 8) in ("1", "true", "yes"):
        args.append("--blocked")
    return _dnsview(*args)


def api_dns_resolutions():
    return _dnsview("resolutions")


def api_dns_lookup():
    addr = _qstr("address", 64)
    if not addr:
        return {"error": "no address given"}
    return _dnsview("lookup", addr)


# ---------------------------------------------------------------------------
# Configuration registry
#
# Every file Flowsight reads is registered here, so one set of operations
# covers all of them and a new document needs a descriptor rather than another
# pair of endpoints. Documents come in four shapes:
#
#   settings    a JSON object of keys, edited key by key (collector, ui)
#   collection  a list of identified items, created and deleted one at a time
#               (enrollment zones, classification rules)
#   map         name to value (category feeds)
#   text        validated as a whole, not decomposable (the policy document)
#
# Every write validates first, keeps a timestamped backup, replaces the file
# atomically, and then triggers whatever needs to notice. In that order: a
# document that fails validation must never reach disk, because most of these
# fail soft - a malformed rules file does not raise, it makes the engine fall
# back to an empty default and quarantine the network on the next apply.

CONFIG_DOCS = {
    "collector": {
        "title": "Collector",
        "why": "Which sources are polled, how often, and where telemetry is sent.",
        "kind": "settings",
        "path_key": "collector_config",
        "reload": "collector",
    },
    "ui": {
        "title": "Interface",
        "why": "Bind address, backend URLs and whether this interface may write.",
        "kind": "settings",
        "path": "/usr/local/etc/flowsight/ui.json",
        "reload": "ui",
    },
    "zones": {
        "title": "Enrollment zones",
        "why": "The network each class of device is placed in, and what it may reach.",
        "kind": "collection",
        "path": "/usr/local/etc/flowsight/zones.json",
        "collection": "zones",
        "id_field": "id",
        "settings_too": True,
        "reload": "enroll",
    },
    "enroll-rules": {
        "title": "Classification rules",
        "why": "How a device is identified from its DHCP request. Order is policy: the first match wins.",
        "kind": "collection",
        "path": "/usr/local/etc/flowsight/enroll-rules.json",
        "collection": "rules",
        "id_field": "id",
        "ordered": True,
        "reload": "enroll",
    },
    "categories": {
        "title": "Category feeds",
        "why": "Domain feeds backing category policy, as name to URL.",
        "kind": "map",
        "path": "/usr/local/etc/flowsight/categories.json",
    },
    "policy": {
        "title": "Policy",
        "why": "The declarative policy document compiled into DNS enforcement.",
        "kind": "text",
        "path_key": "policy_file",
        "validator": "policy",
    },
}


class ConfigError(Exception):
    pass


def _doc(name):
    spec = CONFIG_DOCS.get(name)
    if not spec:
        raise ConfigError("unknown document %r" % name)
    return spec


def _doc_path(spec):
    return spec.get("path") or CFG[spec["path_key"]]


def _writable():
    return bool(CFG.get("allow_write"))


def _cfg_read(name):
    """Parse a document, or return its empty shape if it does not exist yet."""
    spec = _doc(name)
    path = _doc_path(spec)
    try:
        with open(path) as fh:
            raw = fh.read()
    except OSError:
        empty = {"collection": {spec.get("collection", "items"): []},
                 "settings": {}, "map": {}, "text": ""}
        return spec, path, empty[spec["kind"]], ""
    if spec["kind"] == "text":
        return spec, path, raw, raw
    try:
        return spec, path, json.loads(raw), raw
    except ValueError as exc:
        raise ConfigError("%s on disk is not valid JSON: %s" % (name, exc))


def _validate(name, spec, doc):
    kind = spec["kind"]
    if kind == "settings" and not isinstance(doc, dict):
        raise ConfigError("expected an object of settings")
    if kind == "map":
        if not isinstance(doc, dict):
            raise ConfigError("expected an object of name to value")
        for k, v in doc.items():
            if not isinstance(v, str):
                raise ConfigError("%r must be a string" % k)
    if kind == "collection":
        key = spec["collection"]
        items = doc.get(key)
        if not isinstance(items, list):
            raise ConfigError('expected a "%s" list' % key)
        seen = set()
        for it in items:
            if not isinstance(it, dict):
                raise ConfigError("every entry must be an object")
            ident = it.get(spec["id_field"], "")
            if not ident:
                raise ConfigError("every entry needs a non-empty %r"
                                  % spec["id_field"])
            if ident in seen:
                raise ConfigError("duplicate id %r" % ident)
            seen.add(ident)
    if name == "enroll-rules":
        for r in doc.get("rules", []):
            for cond in _walk_conds(r.get("when", {})):
                for ck, cv in cond.items():
                    if ck.endswith("_re"):
                        try:
                            re.compile(cv)
                        except re.error as exc:
                            raise ConfigError("rule %r: bad regex %r: %s"
                                              % (r.get("id"), cv, exc))
            if r.get("zone"):
                zones = _cfg_read("zones")[2].get("zones", [])
                ids = {z.get("id") for z in zones}
                if ids and r["zone"] not in ids:
                    raise ConfigError("rule %r targets unknown zone %r"
                                      % (r.get("id"), r["zone"]))
    if name == "zones":
        for z in doc.get("zones", []):
            for field in ("subnet", "range"):
                if field not in z:
                    raise ConfigError("zone %r has no %s" % (z.get("id"), field))
            try:
                net = ipaddress.ip_network(z["subnet"], strict=False)
            except ValueError as exc:
                raise ConfigError("zone %r: %s" % (z.get("id"), exc))
            rng = z.get("range") or []
            if len(rng) != 2:
                raise ConfigError("zone %r: range must be two addresses"
                                  % z.get("id"))
            for addr in rng:
                try:
                    if ipaddress.ip_address(addr) not in net:
                        raise ConfigError("zone %r: %s is outside %s"
                                          % (z.get("id"), addr, z["subnet"]))
                except ValueError as exc:
                    raise ConfigError("zone %r: %s" % (z.get("id"), exc))


def _reload(spec):
    """Tell whatever consumes this document that it changed."""
    what = spec.get("reload")
    if what == "collector":
        # Detached, not waited on. A restart can outlast any timeout worth
        # holding an HTTP request for - the collector shuts down through its
        # poll interval - and a reload that runs long is not a failed write.
        # Reporting it as one sent the caller looking for a problem in a file
        # that had already been written correctly.
        try:
            subprocess.Popen(["/usr/sbin/service", CFG["collector_service"],
                              "restart"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
            return "saved; collector restarting"
        except Exception as exc:
            return "saved, but the collector restart could not be started: %s" % exc
    if what == "enroll":
        try:
            r = subprocess.run(py_cmd(ENROLL_BIN, "reconcile"),
                               capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            return "saved; re-evaluation is still running"
        return "enrollment re-evaluated" if r.returncode == 0 else \
            "saved, but re-evaluation reported: %s" % (r.stderr or "").strip()[:160]
    if what == "ui":
        # Deliberately not automatic: this process is serving the request that
        # changed the file, and restarting it here would drop the response and
        # leave the caller unable to tell whether the write succeeded.
        return "saved - restart flowsight_ui for it to take effect"
    return ""


def _cfg_write(name, doc, note=""):
    spec = _doc(name)
    if not _writable():
        raise ConfigError("this interface is configured read-only")
    path = _doc_path(spec)

    if spec.get("validator") == "policy":
        result = save_policy(doc if isinstance(doc, str) else str(doc))
        if not result.get("ok"):
            raise ConfigError(result.get("error", "policy did not validate"))
        return {"ok": True, "path": path, "note": "policy validated and saved"}

    _validate(name, spec, doc)
    body = doc if spec["kind"] == "text" else json.dumps(doc, indent=2,
                                                         sort_keys=False)
    try:
        if os.path.exists(path):
            shutil.copy2(path, "%s.bak-%s" % (path, time.strftime("%Y%m%d%H%M%S")))
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(body if body.endswith("\n") else body + "\n")
        os.replace(tmp, path)
    except OSError as exc:
        raise ConfigError("could not write %s: %s" % (path, exc))
    return {"ok": True, "path": path, "note": note or _reload(spec)}


def _items(spec, doc):
    return doc.setdefault(spec["collection"], [])


# --- read -----------------------------------------------------------------


def _registry_by_ip(ip):
    reg = _json_file(os.path.join(ENROLL_STATE, "enroll-registry.json"),
                     {"devices": {}})
    for d in reg.get("devices", {}).values():
        if d.get("ip") == ip or d.get("ip6") == ip:
            return d
    return {}


def api_host():
    """Everything known about one host, from every source at once.

    The value of this page is the join: ntopng knows the traffic, the
    hypervisor knows whether it is a guest, DHCP knows what it called itself,
    enrollment knows what it was identified as and why, and the resolver knows
    what it asked for. Each is unremarkable alone.
    """
    ip = _qstr("ip", 64)
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"error": "not an IP address"}

    out = {"ip": ip}
    lease = _lease_names().get(ip, "")
    dns_name = _dns_names().get(ip, "")
    reg = _registry_by_ip(ip)
    mac = (reg.get("mac") or "").upper()
    guest = _hostmap().get(mac, {}) if mac else {}

    out["identity"] = {
        "name": lease or reg.get("hostname") or guest.get("name") or dns_name,
        "dhcp_name": lease,
        "resolved_name": dns_name,
        "mac": mac,
        "vendor": reg.get("vendor", ""),
        "randomized_mac": bool(reg.get("randomized_mac")),
        "device_type": reg.get("device_type", ""),
        "guest": ("%s %s on the hypervisor" % (guest.get("kind", "").upper(),
                                               guest.get("id", ""))
                  if guest else ""),
        "guest_status": guest.get("status", ""),
    }
    out["enrollment"] = {
        "zone": reg.get("zone", ""), "suggested_zone": reg.get("suggested_zone", ""),
        "state": reg.get("state", ""), "rule": reg.get("rule", ""),
        "why": reg.get("why", ""), "confidence": reg.get("confidence", ""),
        "source": reg.get("zone_source", ""),
        "first_seen": reg.get("first_seen", 0), "last_seen": reg.get("last_seen", 0),
        "vendor_class": reg.get("vendor_class", ""),
        "dhcp_fingerprint": reg.get("fingerprint", ""),
    } if reg else {}

    q = urllib.parse.urlencode({"ifid": 0, "host": ip})
    data = _ntopng("host/data.lua?" + q).get("rsp", {}) or {}
    if isinstance(data, dict) and data:
        out["traffic"] = {
            "sent": data.get("bytes.sent", 0), "rcvd": data.get("bytes.rcvd", 0),
            "packets_sent": data.get("packets.sent", 0),
            "packets_rcvd": data.get("packets.rcvd", 0),
            "flows_as_client": data.get("flows.as_client", 0),
            "flows_as_server": data.get("flows.as_server", 0),
            "active_flows": (data.get("active_flows.as_client", 0) +
                             data.get("active_flows.as_server", 0)),
            "contacts_as_client": data.get("contacts.as_client", 0),
            "contacts_as_server": data.get("contacts.as_server", 0),
            "duration": data.get("duration", 0),
            "num_alerts": data.get("num_alerts", 0),
            "country": data.get("country", ""), "city": data.get("city", ""),
            "asn": data.get("asn", 0), "asname": data.get("asname", ""),
            "is_blacklisted": bool(data.get("is_blacklisted")),
            "dhcp_host": bool(data.get("dhcpHost")),
            "devtype": data.get("devtype", 0),
            "os": data.get("os_detail") or data.get("os") or "",
            "fingerprint": data.get("fingerprint", "") or "",
        }
        dns = data.get("dns") or {}
        if dns:
            out["traffic"]["dns_counters"] = dns

    ports = _ntopng("host/open_ports.lua?" + q).get("rsp", []) or []
    out["open_ports"] = sorted({str(p.get("key")) for p in ports
                                if isinstance(p, dict) and p.get("key")},
                               key=lambda x: int(x) if x.isdigit() else 0)

    apps = _ntopng("host/l7/stats.lua?" + q).get("rsp", []) or []
    out["applications"] = [{"app": a.get("label", ""), "bytes": a.get("value", 0),
                            "duration": a.get("duration", 0)}
                           for a in apps if isinstance(a, dict)]

    # This endpoint answers with {"records": [...], "stats": {...}} rather than
    # the "data" key the other list endpoints use. Falling back to the envelope
    # itself iterated the dict's keys as though they were alerts.
    alerts = _ntopng("host/alert/list.lua?" + q + "&perPage=25").get("rsp", {})
    if isinstance(alerts, dict):
        rows = alerts.get("records") or alerts.get("data") or []
    else:
        rows = alerts or []
    out["alerts"] = [{"time": a.get("tstamp", 0),
                      "name": a.get("alert_name") or a.get("msg", ""),
                      "severity": (a.get("severity") or {}).get("label", "")
                                  if isinstance(a.get("severity"), dict)
                                  else a.get("severity", "")}
                     for a in rows if isinstance(a, dict)][:25]

    out["dns"] = _dnsview("client", ip, "--hours", str(_qint("hours", 168, 1, 720)))

    flows = api_flows().get("flows", [])
    out["flows"] = [f for f in flows
                    if f.get("client") == ip or f.get("server") == ip][:40]
    return out


# ---------------------------------------------------------------------------
# API description
#
# The document is generated from the route tables rather than maintained
# alongside them, so it cannot describe an endpoint that no longer exists or
# quietly omit one that was added. Anything in the tables without an entry here
# still appears, marked undocumented, because a silent gap in an API reference
# is worse than a visible one.

_Q = lambda n, d, t="string", **kw: dict(name=n, desc=d, type=t, **kw)

API_INFO = {
    "System": "Service health and what this installation can see and do.",
    "Traffic": "Hosts, flows and applications, as observed.",
    "DNS": "Resolver activity and address naming.",
    "Enrollment": "Device identification and zone placement.",
    "Configuration": "CRUD over every configuration document.",
    "Policy": "The declarative policy document and its compilation.",
}

API_META = {
    "GET /api/status": ("System", "Service and source health.", []),
    "GET /api/summary": ("System", "Headline counters for the overview.", []),
    "GET /api/setup": ("System", "Installation checks and what each one means.", []),
    "GET /api/alerts": ("System", "Recent IDS alerts.", []),
    "GET /api/timeseries": ("System", "Metric series for the reports page.", [
        _Q("range", "Window: 1h, 6h, 24h or 7d.", enum=["1h", "6h", "24h", "7d"])]),

    "GET /api/hosts": ("Traffic", "Active hosts with traffic and resolved names.", []),
    "GET /api/flows": ("Traffic", "Active sessions with the nDPI application and "
                                  "both ends named where possible.", []),
    "GET /api/apps": ("Traffic", "Traffic grouped by nDPI application.", []),
    "GET /api/devices": ("Traffic", "Layer-2 inventory by MAC, with identity from "
                                    "the hypervisor, DHCP and OUI.", []),
    "GET /api/host": ("Traffic", "Everything known about one host, joined from "
                                 "every source.", [
        _Q("ip", "The host to report on.", required=True),
        _Q("hours", "DNS window in hours (1-720).", "integer")]),

    "GET /api/dns": ("DNS", "Resolver overview: volume, blocks, clients and "
                            "breakdowns.", [
        _Q("hours", "Window in hours (1-720).", "integer"),
        _Q("limit", "Rows per table (1-200).", "integer"),
        _Q("interval", "Series bucket in minutes: 1, 5 or 10.", "integer")]),
    "GET /api/dns/recent": ("DNS", "The query log, newest first.", [
        _Q("limit", "Rows (1-1000).", "integer"),
        _Q("client", "Only this client address."),
        _Q("domain", "Only domains containing this string."),
        _Q("blocked", "Set to 1 for blocked queries only.")]),
    "GET /api/dns/resolutions": ("DNS", "The whole address-to-name map.", []),
    "GET /api/dns/lookup": ("DNS", "Names an address resolved to.", [
        _Q("address", "The address to name.", required=True)]),

    "GET /api/enroll": ("Enrollment", "Registry state: what each device was "
                                      "identified as, and by which rule.", []),
    "GET /api/enroll/zones": ("Enrollment", "Zone definitions.", []),
    "GET /api/enroll/rules": ("Enrollment", "Classification rules, in order.", []),
    "GET /api/enroll/plan": ("Enrollment", "What enforcing would write. Writes "
                                           "nothing.", []),
    "POST /api/enroll/assign": ("Enrollment", "Place one device in a zone by hand.",
                                {"mac": "MAC address", "zone": "Zone id"}),
    "POST /api/enroll/reconcile": ("Enrollment", "Re-evaluate every device against "
                                                 "the current rules.", {}),
    "POST /api/enroll/apply": ("Enrollment", "Write DHCP and firewall placement. "
                                             "Refused unless mode is enforce.", {}),
    "POST /api/enroll/zones": ("Enrollment", "Replace the zone document.",
                               {"text": "The whole document as JSON text"}),
    "POST /api/enroll/rules": ("Enrollment", "Replace the rules document.",
                               {"text": "The whole document as JSON text"}),

    "GET /api/config/docs": ("Configuration", "Every editable document, with its "
                                              "shape and entry count.", []),
    "GET /api/config/doc": ("Configuration", "One whole document.", [
        _Q("name", "Document name.", required=True)]),
    "GET /api/config/items": ("Configuration", "Entries in a document.", [
        _Q("doc", "Document name.", required=True)]),
    "GET /api/config/item": ("Configuration", "One entry.", [
        _Q("doc", "Document name.", required=True),
        _Q("id", "Entry id, or key for settings and map documents.",
           required=True)]),
    "POST /api/config/doc": ("Configuration", "Replace a whole document. "
                                              "Also accepts PUT.",
                             {"name": "Document name",
                              "text": "The document as text",
                              "document": "or the parsed document"}),
    "POST /api/config/item/create": ("Configuration", "Add an entry. Also reachable "
                                                      "as POST /api/config/item.",
                                     {"doc": "Document name",
                                      "item": "The entry, for collections",
                                      "key": "Key, for settings and map documents",
                                      "value": "Value, for settings and map documents",
                                      "position": "Index, for ordered documents"}),
    "POST /api/config/item/update": ("Configuration", "Change an entry. Merges by "
                                                      "default. Also PUT "
                                                      "/api/config/item.",
                                     {"doc": "Document name", "id": "Entry id",
                                      "item": "Fields to change",
                                      "replace": "true to replace rather than merge",
                                      "key": "Key, for settings and map documents",
                                      "value": "Value, for settings and map documents"}),
    "POST /api/config/item/delete": ("Configuration", "Remove an entry. Also DELETE "
                                                      "/api/config/item.",
                                     {"doc": "Document name",
                                      "id": "Entry id or key"}),
    "POST /api/config/reorder": ("Configuration", "Reorder an ordered document. The "
                                                  "id list must name every entry "
                                                  "exactly once.",
                                 {"doc": "Document name",
                                  "ids": "Every entry id, in the order wanted"}),
    "GET /api/config": ("Configuration", "Collector configuration as text. Superseded "
                                         "by /api/config/doc?name=collector.", []),
    "POST /api/config": ("Configuration", "Replace the collector configuration.",
                         {"text": "The document as JSON text"}),

    "GET /api/openapi.json": ("System", "This document, generated from the route "
                                       "tables.", []),

    "GET /api/policy": ("Policy", "Policy status and what applying it would change.",
                        []),
    "GET /api/policy_source": ("Policy", "The raw policy document.", []),
    "POST /api/policy_source": ("Policy", "Validate and save the policy document. "
                                          "A document that does not compile is "
                                          "never written.",
                                {"text": "The policy document"}),
    "POST /api/policy_apply": ("Policy", "Compile and apply the policy.", {}),
}


def _openapi():
    paths = {}
    undocumented = []
    for verb, table in (("GET", ROUTES), ("POST", WRITE_ROUTES)):
        for route in table:
            key = "%s %s" % (verb, route)
            meta = API_META.get(key)
            if meta is None:
                undocumented.append(key)
                tag, summary, extra = "Undocumented", "No description yet.", []
            else:
                tag, summary, extra = meta
            op = {
                "tags": [tag],
                "summary": summary,
                "operationId": "%s_%s" % (
                    verb.lower(), route[len("/api/"):].replace("/", "_") or "root"),
                "responses": {
                    "200": {"description": "Success",
                            "content": {"application/json": {
                                "schema": {"type": "object"}}}},
                    "400": {"description": "Rejected - the response carries an "
                                           "error field saying why"},
                    "404": {"description": "No such endpoint or entry"},
                },
            }
            if verb == "GET":
                op["parameters"] = [{
                    "name": q["name"], "in": "query",
                    "required": bool(q.get("required")),
                    "description": q["desc"],
                    "schema": dict({"type": q.get("type", "string")},
                                   **({"enum": q["enum"]} if q.get("enum") else {})),
                } for q in (extra or [])]
            elif extra:
                op["requestBody"] = {
                    "required": True,
                    "content": {"application/json": {"schema": {
                        "type": "object",
                        "properties": {k: {"description": v}
                                       for k, v in extra.items()},
                    }}},
                }
            paths.setdefault(route, {})[verb.lower()] = op

    # The aliases exist so the API reads as CRUD; they belong in the document.
    for route, verb, target in (("/api/config/item", "put", "update"),
                                ("/api/config/item", "post", "create"),
                                ("/api/config/item", "delete", "delete"),
                                ("/api/config/doc", "put", "replace")):
        src = paths.get("/api/config/item/%s" % target, {}).get("post") \
            if target != "replace" else paths.get("/api/config/doc", {}).get("post")
        if not src:
            continue
        alias = dict(src)
        alias["operationId"] = src["operationId"] + "_" + verb
        alias["summary"] = src["summary"]
        if verb == "delete":
            alias["parameters"] = [
                {"name": "doc", "in": "query", "required": True,
                 "schema": {"type": "string"},
                 "description": "Document name"},
                {"name": "id", "in": "query", "required": True,
                 "schema": {"type": "string"},
                 "description": "Entry id or key"}]
            alias.pop("requestBody", None)
        paths.setdefault(route, {})[verb] = alias

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Flowsight API",
            "version": FLOWSIGHT_VERSION,
            "description":
                "Flowsight observes; the backends enforce. Reads are always "
                "available. Writes require allow_write, and inside OPNsense "
                "they arrive through the authenticated GUI page rather than "
                "directly, because this service ships no authentication of its "
                "own and binds to loopback.\n\n"
                "PUT and DELETE are accepted where noted, but every operation "
                "is also reachable by POST: the OPNsense page forwards only GET "
                "and POST, so a PUT-only operation would work for direct "
                "callers and fail behind the GUI.",
        },
        "servers": [{"url": "/api", "description": "Direct, on loopback"},
                    {"url": "/flowsight.php?api=",
                     "description": "Through the authenticated OPNsense GUI"}],
        "tags": [{"name": k, "description": v} for k, v in API_INFO.items()],
        "paths": paths,
        "x-undocumented": undocumented,
    }


def api_openapi():
    return _openapi()


SWAGGER_CDN = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5"

# Swagger UI is loaded from a CDN, so this page - and only this page - relaxes
# the service's default-src 'none' policy far enough to fetch it. A firewall
# with no outbound access is an ordinary case rather than an error, so the page
# renders the same document itself when the script does not arrive.
DOCS_CSP = ("default-src 'none'; style-src 'unsafe-inline' "
            "https://cdn.jsdelivr.net; script-src 'unsafe-inline' "
            "https://cdn.jsdelivr.net; img-src 'self' data:; "
            "font-src https://cdn.jsdelivr.net; connect-src 'self'")

DOCS_PAGE = """<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Flowsight API</title>
<link rel="stylesheet" href="__CDN__/swagger-ui.css">
<style>
/* Light only, to match the GUI this is reached from. */
:root{color-scheme:light}
body{margin:0;font:14px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;
  background:#f5f5f5;color:#373736}
#fallback{max-width:960px;margin:0 auto;padding:22px 18px}
#fallback h1{font-size:21px;margin:0 0 4px}
#fallback .sub{opacity:.7;font-size:13px;margin-bottom:18px}
#fallback h2{font-size:12px;text-transform:uppercase;letter-spacing:.06em;
  opacity:.6;margin:22px 0 8px}
.op{background:#fff;border:1px solid #ddd;border-radius:8px;padding:10px 13px;margin-bottom:7px}
.verb{display:inline-block;min-width:58px;padding:1px 8px;border-radius:5px;
  font:600 11px/1.6 ui-monospace,Menlo,monospace;color:#fff;text-align:center;
  margin-right:9px}
.get{background:#C03E14}.post{background:#2f7d4f}
.put{background:#b8791b}.delete{background:#b3352e}
code{font:12px/1.5 ui-monospace,Menlo,monospace}
.pp{margin:8px 0 0 67px;font-size:12.5px;opacity:.85}
.pp b{font-family:ui-monospace,Menlo,monospace;font-weight:600}
.req{color:#b3352e;font-size:11px}
</style>
<div id="swagger"></div>
<div id="fallback" hidden></div>
<script src="__CDN__/swagger-ui-bundle.js" onerror="window.__noswagger=1"></script>
<script>
(function(){
  function manual(){
    fetch('/api/openapi.json').then(function(r){return r.json();}).then(function(d){
      var esc=function(t){return String(t==null?'':t).replace(/[&<>"]/g,
        function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});};
      var byTag={};
      Object.keys(d.paths).forEach(function(route){
        Object.keys(d.paths[route]).forEach(function(verb){
          var op=d.paths[route][verb];
          var tag=(op.tags&&op.tags[0])||'Other';
          (byTag[tag]=byTag[tag]||[]).push({route:route,verb:verb,op:op});
        });
      });
      var html='<h1>'+esc(d.info.title)+' <span style="opacity:.5">'+
        esc(d.info.version)+'</span></h1><div class="sub">'+
        esc(d.info.description)+'</div><div class="sub">Swagger UI could not be '+
        'loaded, so this is rendered locally. The document itself is at '+
        '<code>/api/openapi.json</code> and can be imported anywhere.</div>';
      (d.tags||[]).concat([{name:'Other'},{name:'Undocumented'}]).forEach(function(t){
        var ops=byTag[t.name]; if(!ops) return;
        html+='<h2>'+esc(t.name)+(t.description?' &mdash; '+esc(t.description):'')+'</h2>';
        ops.sort(function(a,b){return a.route.localeCompare(b.route);});
        ops.forEach(function(x){
          html+='<div class="op"><span class="verb '+x.verb+'">'+
            x.verb.toUpperCase()+'</span><code>'+esc(x.route)+'</code><div class="pp">'+
            esc(x.op.summary||'')+'</div>';
          (x.op.parameters||[]).forEach(function(pm){
            html+='<div class="pp"><b>'+esc(pm.name)+'</b> '+esc(pm.description||'')+
              (pm.required?' <span class="req">required</span>':'')+'</div>';
          });
          var rb=x.op.requestBody&&x.op.requestBody.content&&
                 x.op.requestBody.content['application/json'];
          if(rb&&rb.schema&&rb.schema.properties){
            Object.keys(rb.schema.properties).forEach(function(k){
              html+='<div class="pp"><b>'+esc(k)+'</b> '+
                esc(rb.schema.properties[k].description||'')+'</div>';
            });
          }
          html+='</div>';
        });
      });
      var f=document.getElementById('fallback');
      f.innerHTML=html; f.hidden=false;
      document.getElementById('swagger').hidden=true;
    });
  }
  // ?local=1 forces the built-in renderer, so the no-internet path can be
  // exercised deliberately rather than only discovered on an appliance
  // that cannot reach the CDN.
  var forced=location.search.indexOf('local')>=0;
  if(forced||window.__noswagger||typeof SwaggerUIBundle==='undefined'){
    manual(); return; }
  try{
    SwaggerUIBundle({url:'/api/openapi.json',dom_id:'#swagger',
      docExpansion:'list',defaultModelsExpandDepth:-1,tryItOutEnabled:true});
  }catch(e){ manual(); }
})();
</script>
""".replace("__CDN__", SWAGGER_CDN)


def api_config_docs():
    """Every document that can be edited, with its shape and size."""
    out = []
    for name, spec in sorted(CONFIG_DOCS.items()):
        entry = {"name": name, "title": spec["title"], "why": spec["why"],
                 "kind": spec["kind"], "ordered": bool(spec.get("ordered")),
                 "writable": _writable()}
        try:
            _s, path, doc, _raw = _cfg_read(name)
            entry["path"] = path
            entry["exists"] = os.path.exists(path)
            if spec["kind"] == "collection":
                entry["count"] = len(doc.get(spec["collection"], []))
                entry["collection"] = spec["collection"]
                entry["id_field"] = spec["id_field"]
            elif spec["kind"] in ("settings", "map"):
                entry["count"] = len(doc)
        except ConfigError as exc:
            entry["error"] = str(exc)
        out.append(entry)
    return {"documents": out, "writable": _writable()}


def api_config_doc():
    name = _qstr("name", 64)
    try:
        spec, path, doc, raw = _cfg_read(name)
    except ConfigError as exc:
        return {"error": str(exc)}
    return {"name": name, "path": path, "kind": spec["kind"],
            "exists": os.path.exists(path), "writable": _writable(),
            "document": doc,
            "text": raw or (doc if spec["kind"] == "text"
                            else json.dumps(doc, indent=2))}


def api_config_items():
    name = _qstr("doc", 64)
    try:
        spec, _path, doc, _raw = _cfg_read(name)
    except ConfigError as exc:
        return {"error": str(exc)}
    if spec["kind"] == "collection":
        out = {"doc": name, "id_field": spec["id_field"],
               "items": _items(spec, doc)}
        if spec.get("settings_too"):
            out["settings"] = {k: v for k, v in doc.items()
                               if k != spec["collection"]}
        return out
    if spec["kind"] in ("settings", "map"):
        return {"doc": name, "id_field": "key",
                "items": [{"key": k, "value": v} for k, v in doc.items()]}
    return {"doc": name, "items": [], "text": doc}


def api_config_item():
    name, ident = _qstr("doc", 64), _qstr("id", 128)
    try:
        spec, _p, doc, _r = _cfg_read(name)
    except ConfigError as exc:
        return {"error": str(exc)}
    if spec["kind"] == "collection":
        for it in _items(spec, doc):
            if it.get(spec["id_field"]) == ident:
                return {"doc": name, "item": it}
        return {"error": "no item %r in %s" % (ident, name)}
    if spec["kind"] in ("settings", "map"):
        if ident in doc:
            return {"doc": name, "item": {"key": ident, "value": doc[ident]}}
        return {"error": "no key %r in %s" % (ident, name)}
    return {"error": "%s is not a collection" % name}


# --- write ----------------------------------------------------------------


def _as_error(fn, body):
    try:
        return fn(body)
    except ConfigError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:                      # noqa: BLE001 - reported, not raised
        return {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}


def cfg_doc_save(body):
    def run(b):
        name = b.get("name") or b.get("doc") or ""
        spec = _doc(name)
        if "text" in b and spec["kind"] != "text":
            try:
                doc = json.loads(b["text"])
            except ValueError as exc:
                raise ConfigError("not valid JSON: %s" % exc)
        elif "text" in b:
            doc = b["text"]
        elif "document" in b:
            doc = b["document"]
        else:
            raise ConfigError("supply text or document")
        return _cfg_write(name, doc)
    return _as_error(run, body)


def cfg_item_create(body):
    def run(b):
        name = b.get("doc", "")
        spec = _doc(name)
        _s, _p, doc, _r = _cfg_read(name)
        if spec["kind"] == "collection":
            item = b.get("item") or {}
            ident = item.get(spec["id_field"], "")
            if not ident:
                raise ConfigError("item needs a %r" % spec["id_field"])
            items = _items(spec, doc)
            if any(i.get(spec["id_field"]) == ident for i in items):
                raise ConfigError("%r already exists - update it instead" % ident)
            pos = b.get("position")
            if spec.get("ordered") and isinstance(pos, int) and 0 <= pos <= len(items):
                items.insert(pos, item)
            else:
                items.append(item)
        elif spec["kind"] in ("settings", "map"):
            key = b.get("key", "")
            if not key:
                raise ConfigError("supply a key")
            if key in doc:
                raise ConfigError("%r already exists - update it instead" % key)
            doc[key] = b.get("value")
        else:
            raise ConfigError("%s has no items" % name)
        return _cfg_write(name, doc)
    return _as_error(run, body)


def cfg_item_update(body):
    def run(b):
        name = b.get("doc", "")
        spec = _doc(name)
        _s, _p, doc, _r = _cfg_read(name)
        ident = b.get("id", "")
        if spec["kind"] == "collection" and spec.get("settings_too") and \
                b.get("key") and "item" not in b:
            # A collection document can also carry document-level settings -
            # zones.json holds "mode" and "captive_policy" beside its list. A
            # caller supplying "key" rather than "item" means one of those.
            # The descriptor advertised this and the code did not implement it,
            # so the setting could only be changed by rewriting the whole file.
            key = b["key"]
            if key == spec["collection"]:
                raise ConfigError("use the item operations to change %r" % key)
            if key not in doc and not b.get("create"):
                raise ConfigError("no setting %r in %s" % (key, name))
            doc[key] = b.get("value")
            return _cfg_write(name, doc)
        if spec["kind"] == "collection":
            items = _items(spec, doc)
            for idx, it in enumerate(items):
                if it.get(spec["id_field"]) == ident:
                    new = b.get("item") or {}
                    # A merge by default: a caller editing one field should not
                    # have to resend the whole item and risk dropping the rest.
                    items[idx] = new if b.get("replace") else {**it, **new}
                    items[idx][spec["id_field"]] = new.get(
                        spec["id_field"], ident)
                    break
            else:
                raise ConfigError("no item %r in %s" % (ident, name))
        elif spec["kind"] in ("settings", "map"):
            key = b.get("key", ident)
            if key not in doc and not b.get("create"):
                raise ConfigError("no key %r in %s" % (key, name))
            doc[key] = b.get("value")
        else:
            raise ConfigError("%s has no items" % name)
        return _cfg_write(name, doc)
    return _as_error(run, body)


def cfg_item_delete(body):
    def run(b):
        name = b.get("doc", "")
        spec = _doc(name)
        _s, _p, doc, _r = _cfg_read(name)
        ident = b.get("id", "") or b.get("key", "")
        if spec["kind"] == "collection":
            items = _items(spec, doc)
            keep = [i for i in items if i.get(spec["id_field"]) != ident]
            if len(keep) == len(items):
                raise ConfigError("no item %r in %s" % (ident, name))
            doc[spec["collection"]] = keep
        elif spec["kind"] in ("settings", "map"):
            if ident not in doc:
                raise ConfigError("no key %r in %s" % (ident, name))
            del doc[ident]
        else:
            raise ConfigError("%s has no items" % name)
        return _cfg_write(name, doc)
    return _as_error(run, body)


def cfg_reorder(body):
    def run(b):
        name = b.get("doc", "")
        spec = _doc(name)
        if not spec.get("ordered"):
            raise ConfigError("%s is not an ordered document" % name)
        _s, _p, doc, _r = _cfg_read(name)
        items = _items(spec, doc)
        want = b.get("ids") or []
        have = [i.get(spec["id_field"]) for i in items]
        if sorted(want) != sorted(have):
            raise ConfigError("the id list must name every entry exactly once")
        index = {i.get(spec["id_field"]): i for i in items}
        doc[spec["collection"]] = [index[i] for i in want]
        return _cfg_write(name, doc)
    return _as_error(run, body)


WRITE_ROUTES = {
    "/api/policy_source": lambda body: save_policy(body.get("text", "")),
    "/api/policy_apply": lambda body: apply_policy(),
    "/api/config": lambda body: save_config(body.get("text", "")),
    "/api/config/doc": cfg_doc_save,
    "/api/config/item/create": cfg_item_create,
    "/api/config/item/update": cfg_item_update,
    "/api/config/item/delete": cfg_item_delete,
    "/api/config/reorder": cfg_reorder,
    "/api/enroll/assign": enroll_assign,
    "/api/enroll/reconcile": lambda body: _enroll_run("reconcile"),
    "/api/enroll/apply": lambda body: _enroll_run("apply"),
    "/api/enroll/zones": lambda body: _save_enroll_json(ZONES_FILE, body, "zones"),
    "/api/enroll/rules": lambda body: _save_enroll_json(
        ENROLL_RULES_FILE, body, "rules"),
}


ROUTES = {
    "/api/status": api_status,
    "/api/summary": api_summary,
    "/api/alerts": api_alerts,
    "/api/policy": api_policy,
    "/api/hosts": api_hosts,
    "/api/flows": api_flows,
    "/api/apps": api_apps,
    "/api/timeseries": api_timeseries,
    "/api/setup": api_setup,
    "/api/devices": api_devices,
    "/api/policy_source": lambda: api_policy_source(),
    "/api/config": lambda: api_config(),
    "/api/host": api_host,
    "/api/openapi.json": api_openapi,
    "/api/config/docs": api_config_docs,
    "/api/config/doc": api_config_doc,
    "/api/config/items": api_config_items,
    "/api/config/item": api_config_item,
    "/api/dns": api_dns,
    "/api/dns/recent": api_dns_recent,
    "/api/dns/resolutions": api_dns_resolutions,
    "/api/dns/lookup": api_dns_lookup,
    "/api/enroll": api_enroll,
    "/api/enroll/zones": api_enroll_zones,
    "/api/enroll/rules": api_enroll_rules,
    "/api/enroll/plan": lambda: _enroll_run("plan"),
}

PAGE = """<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Flowsight</title>
<style>
/* Matches the OPNsense "opnsense" theme this page is embedded in: #f5f5f5
   behind white content boxes, #373736 text, and #C03E14 as the accent. There is
   deliberately no prefers-color-scheme rule - the surrounding GUI is light
   whatever the operating system is set to, and a page that went dark inside it
   was unreadable against the white chrome around it. */
:root{color-scheme:light;
      --bg:#f5f5f5;--fg:#373736;--mut:#777772;--card:#fff;--line:#ddd;
      --ok:#4b8b3b;--warn:#b8791b;--crit:#d9534f;--accent:#C03E14}
*{box-sizing:border-box}
.fs{color:var(--fg);background:var(--bg);
    font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
.fs h1{font-size:19px;margin:0 0 2px}
.fs h3{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);margin:0 0 6px;font-weight:600}
.big{font-size:26px;font-weight:600;font-variant-numeric:tabular-nums}
.row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.row>.card{flex:1;min-width:160px}
a.hl{color:var(--accent);text-decoration:none}
a.hl:hover{text-decoration:underline}
.fs .sub{color:var(--mut);font-size:12px;margin-bottom:14px}
.fslayout{display:flex;gap:20px;align-items:flex-start}
.fsnav{flex:0 0 172px;display:flex;flex-direction:column;gap:1px;
       position:sticky;top:12px;border-right:1px solid var(--line);
       padding-right:12px;margin-bottom:16px}
.fsmain{flex:1;min-width:0}
.tab{padding:7px 11px;cursor:pointer;border:0;background:none;color:var(--mut);
     font:600 12px/1.4 inherit;text-transform:uppercase;letter-spacing:.05em;
     text-align:left;border-radius:6px;border-left:2px solid transparent}
.tab:hover{color:var(--fg);background:color-mix(in srgb,var(--fg) 6%,transparent)}
.tab.on{color:var(--accent);border-left-color:var(--accent);
        background:color-mix(in srgb,var(--accent) 12%,transparent)}
/* Inside the OPNsense GUI the navigation lives in that page's own left menu,
   so carrying a second copy here would just duplicate it. */
.fs.embedded .fsnav{display:none}
.fs.embedded .fslayout{display:block}
/* Time-range selectors sit inside the content, not the navigation, so they
   keep a horizontal pill styling rather than the sidebar's list styling. */
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.tabs .tab{border-left:0;border:1px solid var(--line);text-transform:none;
           letter-spacing:0;padding:5px 12px;background:var(--card)}
.tabs .tab.on{border-color:var(--accent);color:var(--accent)}
@media(max-width:820px){
  .fslayout{display:block}
  .fsnav{flex-direction:row;flex-wrap:wrap;position:static;border-right:0;
         border-bottom:1px solid var(--line);padding-right:0;padding-bottom:6px}
}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));margin-bottom:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .k{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em}
.card .v{font-size:22px;font-weight:600;margin-top:4px;font-variant-numeric:tabular-nums}
.fs h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);
   margin:20px 0 8px;font-weight:600}
.fs table{width:100%;border-collapse:collapse;background:var(--card);
      border:1px solid var(--line);border-radius:8px;overflow:hidden}
.fs th,.fs td{text-align:left;padding:7px 11px;border-bottom:1px solid var(--line);font-size:13px}
.fs th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;cursor:pointer;white-space:nowrap}
.fs th:hover{color:var(--fg)}
.fs tr:last-child td{border-bottom:0}
.num{text-align:right;font-variant-numeric:tabular-nums}
.fs pre{background:var(--card);border:1px solid var(--line);border-radius:8px;
    padding:12px;overflow-x:auto;font-size:12px;white-space:pre-wrap}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:600}
.ok{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}
.bad{background:color-mix(in srgb,var(--crit) 18%,transparent);color:var(--crit)}
.warn{background:color-mix(in srgb,var(--warn) 18%,transparent);color:var(--warn)}
.cap{display:inline-block;background:color-mix(in srgb,var(--accent) 15%,transparent);
     color:var(--accent);padding:2px 9px;border-radius:5px;font-size:12px;margin:0 6px 6px 0}
.note{color:var(--mut);font-size:12px;margin-top:6px}
.err{color:var(--crit);font-size:12px}
.scroll{max-height:560px;overflow-y:auto;border-radius:8px}
.btn{background:var(--accent);color:#fff;border:0;border-radius:6px;padding:7px 14px;
     font:600 12px/1 inherit;cursor:pointer;margin-right:6px}
.btn:hover{filter:brightness(1.1)}
.editor{width:100%;height:280px;font:12px/1.5 ui-monospace,Menlo,monospace;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:10px;margin-top:6px}
</style>
<div class="fs" id="fsroot">
  <div class="fslayout">
    <nav class="fsnav" id="tabs"></nav>
    <main class="fsmain">
      <h1>Flowsight</h1>
      <div class="sub" id="sub">read-only &middot; policy is applied from the CLI, never here</div>
      <div id="view"></div>
    </main>
  </div>
</div>
<script>
(function(){
const $=id=>document.getElementById(id);
// The OPNsense page proxies this UI and rewrites the literal '/api/ to
// 'flowsight.php?api=, which already carries a query string. Appending
// parameters with a bare "?" produced a second one and every parameterised
// call 404'd behind the GUI while working perfectly when reached directly.
// Building URLs here keeps both forms correct.
const API='/api/';
function apiUrl(name, params){
  let u=API+name;
  const qs=params?new URLSearchParams(params).toString():'';
  if(!qs) return u;
  return u+(u.indexOf('?')>=0?'&':'?')+qs;
}
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const num=v=>v==null?'&mdash;':(v>=1e9?(v/1e9).toFixed(1)+'G':v>=1e6?(v/1e6).toFixed(1)+'M':
  v>=1e3?(v/1e3).toFixed(1)+'k':(Number.isInteger(v)?v:(+v).toFixed(1)));
const bytes=v=>v==null?'&mdash;':(v>=1073741824?(v/1073741824).toFixed(2)+' GB':
  v>=1048576?(v/1048576).toFixed(1)+' MB':v>=1024?(v/1024).toFixed(1)+' KB':v+' B');
const dur=s=>s==null?'':(s>=3600?Math.floor(s/3600)+'h':s>=60?Math.floor(s/60)+'m':s+'s');
// Returns an object always. Callers read .error straight off the result, and a
// null here - which happens whenever the UI service is restarting - turned a
// transient fetch failure into a TypeError that blanked the whole page.
async function get(p){
  try{
    const r=await fetch(p);
    const j=await r.json();
    return (j&&typeof j==='object')?j:{error:'unexpected response'};
  }catch(e){return {error:String(e&&e.message||e)};}
}
function shortName(n){
  // Hosting and CDN answers carry long per-session or per-shard prefixes. The
  // tail is the part that identifies the service, and the full name is on the
  // element's title for anyone who needs it.
  if(!n) return '';
  if(n.length<=34) return n;
  const p=n.split('.');
  return p.length>3 ? '\u2026'+p.slice(-3).join('.') : n.slice(0,33)+'\u2026';
}
function chart(pts){
  if(!pts||!pts.length) return '<div class="note">no data in this window</div>';
  const W=320,H=90,P=4;
  const xs=pts.map(p=>p[0]), ys=pts.map(p=>p[1]);
  const x0=Math.min(...xs), x1=Math.max(...xs);
  let y0=Math.min(...ys), y1=Math.max(...ys);
  if(y1===y0){y1=y0+1;}                    // flat series still needs a baseline
  const sx=v=>P+((v-x0)/(x1-x0||1))*(W-2*P);
  const sy=v=>H-P-((v-y0)/(y1-y0||1))*(H-2*P);
  const line=pts.map((p,i)=>(i?'L':'M')+sx(p[0]).toFixed(1)+' '+sy(p[1]).toFixed(1)).join(' ');
  const area=line+` L ${sx(x1).toFixed(1)} ${H-P} L ${sx(x0).toFixed(1)} ${H-P} Z`;
  const last=ys[ys.length-1];
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:90px;display:block;margin-top:6px">`+
    `<path d="${area}" fill="var(--accent)" opacity="0.13"/>`+
    `<path d="${line}" fill="none" stroke="var(--accent)" stroke-width="1.5" vector-effect="non-scaling-stroke"/>`+
    `</svg><div class="v" style="font-size:17px">${num(last)}</div>`+
    `<div class="note" style="margin:0">peak ${num(y1)}</div>`;
}
async function post(p,b){try{const r=await fetch(p,{method:'POST',
  headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});return await r.json()}catch(e){return {ok:false,error:String(e)}}}

const TABS=[['overview','Overview'],['reports','Reports'],['devices','Devices'],
            ['enroll','Enrollment'],['dns','DNS'],['hosts','Hosts'],
            ['apps','Applications'],['flows','Live flows'],['alerts','Alerts'],
            ['policy','Policy'],['config','Configuration'],['setup','Setup']];
let range=localStorage.getItem('fs_range')||'24h';
let cur=location.hash.replace('#','')||'overview';
let sortKey={}, sortDir={};

function tabs(){
  // A host page is reached from Hosts and belongs to it, so that entry stays
  // lit rather than leaving the navigation showing nothing as current.
  const active=cur.indexOf('host/')===0?'hosts':cur;
  $('tabs').innerHTML=TABS.map(([k,l])=>
    `<button class="tab ${k===active?'on':''}" data-t="${k}">${l}</button>`).join('');
  [...document.querySelectorAll('.tab')].forEach(b=>b.onclick=()=>{
    cur=b.dataset.t; location.hash=cur; tabs(); render();});
}

function table(id, cols, rows, empty){
  if(!rows.length) return `<div class="note">${empty}</div>`;
  const k=sortKey[id], d=sortDir[id]||-1;
  if(k) rows=[...rows].sort((a,b)=>{const x=a[k],y=b[k];
    return (typeof x==='number'&&typeof y==='number')?(x-y)*d:String(x).localeCompare(String(y))*d;});
  return `<div class="scroll"><table><tr>`+
    cols.map(c=>`<th data-s="${id}:${c.k}" class="${c.n?'num':''}">${c.t}${k===c.k?(d<0?' \u2193':' \u2191'):''}</th>`).join('')+
    `</tr>`+rows.map(r=>`<tr>`+cols.map(c=>
      `<td class="${c.n?'num':''}">${c.f?c.f(r):esc(r[c.k])}</td>`).join('')+`</tr>`).join('')+
    `</table></div>`;
}
function wireSort(){[...document.querySelectorAll('th[data-s]')].forEach(th=>th.onclick=()=>{
  const [id,k]=th.dataset.s.split(':');
  sortDir[id]=(sortKey[id]===k)?-(sortDir[id]||-1):-1; sortKey[id]=k; render();});}

function zoneBadge(z){const c={infra:'#6b7f9e',personal:'#2f6fed',media:'#8b5cf6',
  iot:'#14915c',quarantine:'#c2410c'}[z]||'#777';
  return `<span style="background:${c};color:#fff;padding:1px 7px;border-radius:9px;
    font-size:11px;white-space:nowrap">${esc(z||'-')}</span>`;}

async function renderEnroll(v){
  const d=await get('/api/enroll');
  if(d.error){v.innerHTML=`<div class="note">${esc(d.error)}</div>`;return;}
  const zoneIds=(d.zones||[]).map(z=>z.id);
  const modeNote = d.mode==='enforce'
    ? `<div class="note">Enforcing. New devices are placed by rule; DHCP and
       firewall policy are written from this page's decisions.</div>`
    : `<div class="note"><b>Monitor mode.</b> Devices are identified and shown
       here, but nothing is enforced - no addressing or firewall change is
       written. The Suggested column is what enforcing would do.</div>`;

  const counts=Object.entries(d.counts||{}).sort((a,b)=>b[1]-a[1])
    .map(([z,n])=>`${zoneBadge(z)} ${n}`).join(' &nbsp; ');

  const cols=[
    {k:'hostname',t:'Name',f:r=>esc(r.hostname||'(unnamed)')},
    {k:'mac',t:'MAC'},
    {k:'ip',t:'Address',f:r=>r.ip?hostLink(r.ip,r.ip):esc(r.ip6||'')},
    {k:'zone',t:'Zone',f:r=>zoneBadge(r.zone==='__existing__'?'pinned':r.zone)},
    {k:'suggested_zone',t:'Suggested',f:r=>zoneBadge(r.suggested_zone)},
    {k:'confidence',t:'Confidence'},
    {k:'vendor',t:'Vendor',f:r=>esc(r.vendor|| (r.randomized_mac?'(randomized MAC)':''))},
    {k:'rule',t:'Matched rule',f:r=>`<span title="${esc(r.why||'')}">${esc(r.rule||'-')}</span>`},
    {k:'mac',t:'',f:r=>`<select data-mac="${esc(r.mac)}" class="zsel">
        <option value="">move to...</option>`+
        zoneIds.map(z=>`<option value="${esc(z)}">${esc(z)}</option>`).join('')+
      `</select>`}];

  v.innerHTML = modeNote +
    `<div class="row"><div class="card"><h3>Zones</h3><div>${counts}</div></div>
     <div class="card"><h3>Unidentified</h3><div class="big">${d.unidentified}</div>
       <div class="sub">held for identification</div></div>
     <div class="card"><h3>Pinned</h3><div class="big">${d.pinned}</div>
       <div class="sub">present before enrollment; never moved automatically</div></div></div>` +
    (d.claims&&d.claims.length?`<h3>Recent self-identifications</h3>`+
      table('claims',[{k:'at',t:'When',f:r=>new Date(r.at*1000).toLocaleString()},
        {k:'mac',t:'MAC'},{k:'ip',t:'Address'},
        {k:'zone',t:'Claimed',f:r=>zoneBadge(r.zone)},
        {k:'user_agent',t:'User agent'}],d.claims,'None'):'') +
    `<h3>Devices (${d.total})</h3>` +
    table('enroll',cols,d.devices,'No devices yet.') +
    `<div class="row" style="margin-top:12px">
       <button id="ereconcile">Re-identify now</button>
       <button id="eapply">Apply placement</button></div>
     <h3>Zones and rules</h3>
     <p class="sub">Both are plain JSON and are validated before they are saved.
        A rule with a bad regex is rejected rather than stored.</p>
     <div id="ecfg"></div>`;
  wireSort();

  [...document.querySelectorAll('.zsel')].forEach(sel=>sel.onchange=async()=>{
    if(!sel.value)return;
    const r=await post('/api/enroll/assign',{mac:sel.dataset.mac,zone:sel.value});
    if(!r.ok) alert(r.error||'assign failed');
    render();});

  $('ereconcile').onclick=async()=>{await post('/api/enroll/reconcile',{});render();};
  $('eapply').onclick=async()=>{
    if(!confirm('Write DHCP and firewall placement for every classified device?'))return;
    const r=await post('/api/enroll/apply',{});
    alert((r.out||'')+(r.err||'')||JSON.stringify(r)); render();};

  for(const [name,path,key] of [['Zones','/api/enroll/zones','zones'],
                                 ['Rules','/api/enroll/rules','rules']]){
    const doc=await get(path);
    const box=document.createElement('div');
    box.innerHTML=`<h4>${name}</h4>
      <textarea id="ta_${key}" rows="14" style="width:100%;font-family:ui-monospace,
        Menlo,monospace;font-size:12px">${esc(JSON.stringify(doc,null,2))}</textarea>
      <div><button id="sv_${key}">Save ${name.toLowerCase()}</button>
      <span id="msg_${key}" class="sub"></span></div>`;
    $('ecfg').appendChild(box);
    $('sv_'+key).onclick=async()=>{
      const r=await post(path,{text:$('ta_'+key).value});
      $('msg_'+key).textContent=r.ok?`saved (${r.count} entries)`:('error: '+(r.error||''));};
  }
}

let dnsHours=parseInt(localStorage.getItem('fs_dns_hours')||'24',10);
let dnsFilter={client:'',domain:'',blocked:false};

function pctBar(rows,total){
  return rows.map(r=>{const w=total?(100*r.queries/total):0;
    return `<div style="display:flex;align-items:center;gap:8px;margin:2px 0">
      <div style="flex:0 0 118px;font-size:12px">${esc(r.label)}</div>
      <div style="flex:1;background:var(--line);height:9px;border-radius:5px;overflow:hidden">
        <div style="width:${w.toFixed(1)}%;background:var(--accent);height:100%"></div></div>
      <div style="flex:0 0 74px;text-align:right;font-size:12px">${num(r.queries)}</div>
    </div>`;}).join('');
}

async function renderDns(v){
  const d=await get(apiUrl('dns',{hours:dnsHours,limit:25}));
  if(d.error){v.innerHTML=`<div class="note">${esc(d.error)}</div>
    <div class="note">DNS reporting is an Unbound setting - it must be on for
    this page to have anything to read.</div>`;return;}
  const s=d.summary, ts=(d.timeseries||[]).map(p=>[p.t,p.total]);
  const tot=s.total||0;

  const win=[1,6,24,72,168].map(h=>
    `<button class="tab ${h===dnsHours?'on':''}" data-h="${h}">${h<24?h+'h':(h/24)+'d'}</button>`).join('');

  v.innerHTML=
    `<div class="tabs">${win}</div>
     <div class="row">
       <div class="card"><h3>Queries</h3><div class="big">${num(tot)}</div>
         ${chart(ts)}</div>
       <div class="card"><h3>Blocked</h3><div class="big">${num(s.blocked)}</div>
         <div class="sub">${s.blocked_pct}% of queries${s.dropped?(', '+num(s.dropped)+' dropped'):''}</div></div>
       <div class="card"><h3>Answered from cache</h3><div class="big">${s.cache_pct}%</div>
         <div class="sub">${num(s.recursed)} needed recursion, ${s.avg_resolve_ms} ms average</div></div>
       <div class="card"><h3>Asking</h3><div class="big">${num(s.clients)}</div>
         <div class="sub">clients, ${num(s.domains)} distinct domains</div></div>
       <div class="card"><h3>Failures</h3><div class="big">${num(s.nxdomain)}</div>
         <div class="sub">NXDOMAIN, ${num(s.servfail)} SERVFAIL</div></div>
     </div>

     <div class="row">
       <div class="card" style="flex:1"><h3>Query type</h3>${pctBar(d.types,tot)}</div>
       <div class="card" style="flex:1"><h3>Answer source</h3>${pctBar(d.sources,tot)}</div>
       <div class="card" style="flex:1"><h3>Response code</h3>${pctBar(d.rcodes,tot)}</div>
       <div class="card" style="flex:1"><h3>DNSSEC</h3>${pctBar(d.dnssec,tot)}</div>
     </div>

     <h3>Top domains</h3>
     ${table('dnsdom',[{k:'domain',t:'Domain',f:r=>
         `<a href="#" class="dq" data-d="${esc(r.domain)}">${esc(r.domain)}</a>`},
       {k:'queries',t:'Queries',n:1,f:r=>num(r.queries)},
       {k:'clients',t:'Clients',n:1}],d.top_domains,'No queries in this window.')}

     <h3>Most blocked</h3>
     ${table('dnsblk',[{k:'domain',t:'Domain',f:r=>
         `<a href="#" class="dq" data-d="${esc(r.domain)}">${esc(r.domain)}</a>`},
       {k:'queries',t:'Blocked',n:1,f:r=>num(r.queries)},
       {k:'clients',t:'Clients',n:1},{k:'blocklist',t:'List'}],
       d.top_blocked,'Nothing blocked in this window.')}

     <h3>Who is asking</h3>
     ${table('dnscli',[
       {k:'hostname',t:'Device',f:r=>esc(r.hostname||'(unnamed)')},
       {k:'client',t:'Address',f:r=>
         `<a href="#" class="cq" data-c="${esc(r.client)}">filter</a> `+
         hostLink(r.client,r.client)},
       {k:'queries',t:'Queries',n:1,f:r=>num(r.queries)},
       {k:'blocked',t:'Blocked',n:1,f:r=>r.blocked?
         `<b style="color:#c2410c">${num(r.blocked)}</b>`:'0'},
       {k:'domains',t:'Domains',n:1}],d.top_clients,'No clients.')}

     ${d.blocklists&&d.blocklists.length?`<h3>By blocklist</h3>`+
       table('dnsbl',[{k:'blocklist',t:'List'},
         {k:'queries',t:'Blocked',n:1,f:r=>num(r.queries)}],d.blocklists,''):''}

     <h3>Query log</h3>
     <div class="row" style="gap:6px;margin-bottom:6px">
       <input id="fcli" placeholder="client address" value="${esc(dnsFilter.client)}"
         style="padding:6px;min-width:150px">
       <input id="fdom" placeholder="domain contains" value="${esc(dnsFilter.domain)}"
         style="padding:6px;min-width:180px">
       <label style="font-size:13px"><input type="checkbox" id="fblk"
         ${dnsFilter.blocked?'checked':''}> blocked only</label>
       <button id="fgo">Filter</button><button id="fclr">Clear</button>
     </div>
     <div id="qlog" class="note">loading...</div>

     <h3>Name an address</h3>
     <p class="sub">Answered from the resolver's cache - the names clients were
       actually given. A reverse PTR lookup often has no record, or names the
       hosting provider instead of the service.</p>
     <div class="row" style="gap:6px">
       <input id="raddr" placeholder="e.g. 104.200.30.183" style="padding:6px;min-width:190px">
       <button id="rgo">Look up</button><span id="rout" class="sub"></span>
     </div>`;
  wireSort();

  [...document.querySelectorAll('[data-h]')].forEach(b=>b.onclick=()=>{
    dnsHours=parseInt(b.dataset.h,10);
    localStorage.setItem('fs_dns_hours',dnsHours); render();});
  [...document.querySelectorAll('.dq')].forEach(a=>a.onclick=e=>{
    e.preventDefault(); dnsFilter={client:'',domain:a.dataset.d,blocked:false};
    render();});
  [...document.querySelectorAll('.cq')].forEach(a=>a.onclick=e=>{
    e.preventDefault(); dnsFilter={client:a.dataset.c,domain:'',blocked:false};
    render();});

  async function loadLog(){
    const q={limit:'200'};
    if(dnsFilter.client)q.client=dnsFilter.client;
    if(dnsFilter.domain)q.domain=dnsFilter.domain;
    if(dnsFilter.blocked)q.blocked='1';
    const r=await get(apiUrl('dns/recent',q));
    // The tab may have changed while this was in flight, in which case the
    // element it was going to fill no longer exists.
    const box=$('qlog'); if(!box) return;
    box.innerHTML=r.error?`<div class="note">${esc(r.error)}</div>`:
      table('dnslog',[
        {k:'time',t:'Time',f:x=>new Date(x.time*1000).toLocaleTimeString()},
        {k:'hostname',t:'Device',f:x=>esc(x.hostname||x.client)},
        {k:'domain',t:'Domain'},{k:'type',t:'Type'},
        {k:'action',t:'Action',f:x=>x.action==='Pass'?'Pass':
          `<b style="color:#c2410c">${esc(x.action)}</b>`},
        {k:'source',t:'From'},
        {k:'rcode',t:'Result',f:x=>x.rcode==='NOERROR'?x.rcode:
          `<span style="color:#b45309">${esc(x.rcode)}</span>`},
        {k:'resolve_ms',t:'ms',n:1},{k:'dnssec',t:'DNSSEC'},
        {k:'blocklist',t:'List'}],r.queries||[],'No matching queries.');
    wireSort();
  }
  loadLog();
  $('fgo').onclick=()=>{dnsFilter={client:$('fcli').value.trim(),
    domain:$('fdom').value.trim(),blocked:$('fblk').checked}; loadLog();};
  $('fclr').onclick=()=>{dnsFilter={client:'',domain:'',blocked:false}; render();};
  $('rgo').onclick=async()=>{
    const a=$('raddr').value.trim(); if(!a)return;
    $('rout').textContent='...';
    const r=await get(apiUrl('dns/lookup',{address:a}));
    $('rout').textContent=r.error?r.error:
      (r.names&&r.names.length?r.names.join(', '):'no name in the resolver cache');
  };
}

let cfgDoc=localStorage.getItem('fs_cfg_doc')||'collector';
let cfgRaw=false;

function fieldEditor(id,value){
  const t=(typeof value==='object'&&value!==null)?JSON.stringify(value,null,1):
          (value===undefined?'':String(value));
  // String.fromCharCode, not an escape: the whole page is a non-raw Python
  // triple-quoted string, so a backslash-n here is consumed by Python and
  // arrives in the browser as a real line break inside a string literal.
  const multi=t.length>60||t.indexOf(String.fromCharCode(10))>=0;
  return multi?`<textarea id="${id}" rows="6" style="width:100%;font-family:ui-monospace,
    Menlo,monospace;font-size:12px">${esc(t)}</textarea>`
   :`<input id="${id}" value="${esc(t)}" style="width:100%;padding:6px;
     font-family:ui-monospace,Menlo,monospace;font-size:12px">`;
}
// Values arrive as text. Anything that parses as JSON is stored as JSON so
// numbers, booleans, lists and nested objects survive a round trip; anything
// else is kept as the string it plainly is.
function parseValue(t){
  const v=t.trim();
  if(v==='') return '';
  try{ return JSON.parse(v); }catch(e){ return t; }
}

async function renderConfig(v){
  const list=await get('/api/config/docs');
  if(list.error){v.innerHTML=`<div class="err">${esc(list.error)}</div>`;return;}
  const docs=list.documents||[];
  const spec=docs.find(d=>d.name===cfgDoc)||docs[0];
  if(!spec){v.innerHTML='<div class="note">Nothing is registered.</div>';return;}
  cfgDoc=spec.name;

  const picker=docs.map(d=>`<button class="tab ${d.name===cfgDoc?'on':''}"
      data-d="${esc(d.name)}">${esc(d.title)}${d.count!==undefined?
      ` <span style="opacity:.6">${d.count}</span>`:''}</button>`).join('');

  let bodyHtml='';
  if(cfgRaw||spec.kind==='text'){
    const doc=await get(apiUrl('config/doc',{name:cfgDoc}));
    bodyHtml=`<textarea id="rawsrc" spellcheck="false" class="editor">${esc(doc.text||'')}</textarea>
      <div style="margin:8px 0"><button id="rawsave" class="btn">Save document</button>
      <span id="rawmsg" class="note"></span></div>`;
  }else{
    const got=await get(apiUrl('config/items',{doc:cfgDoc}));
    if(got.error){bodyHtml=`<div class="err">${esc(got.error)}</div>`;}
    else{
      const idf=got.id_field, items=got.items||[];
      const isColl=spec.kind==='collection';
      const rows=items.map((it,i)=>{
        const ident=it[idf];
        const summary=isColl
          ? Object.keys(it).filter(k=>k!==idf).map(k=>
              `${k}=${typeof it[k]==='object'?JSON.stringify(it[k]):it[k]}`).join('  ').slice(0,120)
          : (typeof it.value==='object'?JSON.stringify(it.value):String(it.value)).slice(0,120);
        return `<tr>
          <td style="white-space:nowrap"><b>${esc(String(ident))}</b></td>
          <td style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${esc(summary)}</td>
          <td style="white-space:nowrap">
            ${spec.ordered?`<button class="btn mv" data-i="${i}" data-dir="-1"
                 ${i===0?'disabled':''} style="padding:3px 7px">&uarr;</button>
               <button class="btn mv" data-i="${i}" data-dir="1"
                 ${i===items.length-1?'disabled':''} style="padding:3px 7px">&darr;</button>`:''}
            <button class="btn ed" data-id="${esc(String(ident))}" style="padding:3px 9px">Edit</button>
            <button class="btn del" data-id="${esc(String(ident))}"
              style="padding:3px 9px;background:var(--crit)">Delete</button>
          </td></tr>`;}).join('');
      bodyHtml=`<div class="scroll"><table>
        <tr><th>${esc(idf)}</th><th>Value</th><th></th></tr>${rows}</table></div>
        <div style="margin-top:10px"><button id="addnew" class="btn">Add ${isColl?'entry':'key'}</button></div>
        <div id="editbox"></div>`;
    }
  }

  v.innerHTML=`<h2>Configuration</h2>
    <div class="tabs">${picker}</div>
    <div class="card" style="margin-bottom:12px">
      <b>${esc(spec.title)}</b>
      <div class="note" style="margin-top:2px">${esc(spec.why)}</div>
      <div class="note"><code>${esc(spec.path||'')}</code>${spec.exists?'':' &mdash; not created yet'}</div>
    </div>
    ${spec.writable?'':'<div class="note">Editing is disabled (allow_write is off).</div>'}
    <div class="tabs"><button class="tab ${cfgRaw?'on':''}" id="rawtoggle">Raw document</button></div>
    ${bodyHtml}
    <div class="note">Every save validates first, keeps a timestamped backup and
      replaces the file atomically. A document that does not validate is never written.</div>`;

  [...document.querySelectorAll('[data-d]')].forEach(b=>b.onclick=()=>{
    cfgDoc=b.dataset.d; localStorage.setItem('fs_cfg_doc',cfgDoc);
    cfgRaw=false; render();});
  $('rawtoggle').onclick=()=>{cfgRaw=!cfgRaw; render();};

  if($('rawsave')) $('rawsave').onclick=async()=>{
    const m=$('rawmsg'); m.textContent='saving...';
    const r=await post('/api/config/doc',{name:cfgDoc,text:$('rawsrc').value});
    m.innerHTML=r.ok?`<span class="pill ok">saved</span> ${esc(r.note||'')}`
      :`<span class="pill bad">rejected</span> <span class="err">${esc(r.error||'')}</span>`;
    if(r.ok) setTimeout(render,700);
  };

  const isColl=spec.kind==='collection';
  function openEditor(existing){
    const box=$('editbox'); if(!box) return;
    const idf=isColl?(spec.id_field||'id'):'key';
    const ident=existing?(isColl?existing[idf]:existing.key):'';
    const value=existing?(isColl?existing:existing.value):(isColl?{}:'');
    const shown=isColl?Object.assign({},value):value;
    if(isColl) delete shown[idf];
    box.innerHTML=`<div class="card" style="margin-top:10px">
      <b>${existing?'Edit':'New'} ${isColl?'entry':'key'}</b>
      <div style="margin:8px 0"><div class="note">${esc(idf)}</div>
        <input id="edid" value="${esc(String(ident))}" ${existing?'readonly':''}
          style="width:100%;padding:6px;font-family:ui-monospace,Menlo,monospace"></div>
      <div class="note">${isColl?'Remaining fields, as JSON':'Value (JSON or plain text)'}</div>
      ${fieldEditor('edval',shown)}
      <div style="margin-top:8px"><button id="edsave" class="btn">Save</button>
      <button id="edcancel" class="btn" style="background:var(--mut)">Cancel</button>
      <span id="edmsg" class="note"></span></div></div>`;
    $('edcancel').onclick=()=>{box.innerHTML='';};
    $('edsave').onclick=async()=>{
      const m=$('edmsg'); m.textContent='saving...';
      const id=$('edid').value.trim();
      const parsed=parseValue($('edval').value);
      let payload;
      if(isColl){
        if(typeof parsed!=='object'||parsed===null||Array.isArray(parsed)){
          m.innerHTML='<span class="err">an entry must be a JSON object</span>';return;}
        payload={doc:cfgDoc,id:id,item:Object.assign({},parsed,{[spec.id_field||'id']:id}),replace:true};
      }else{
        payload={doc:cfgDoc,key:id,id:id,value:parsed,create:!existing};
      }
      const r=await post(existing?'/api/config/item/update':'/api/config/item/create',payload);
      m.innerHTML=r.ok?`<span class="pill ok">saved</span> ${esc(r.note||'')}`
        :`<span class="pill bad">rejected</span> <span class="err">${esc(r.error||'')}</span>`;
      if(r.ok) setTimeout(render,700);
    };
  }

  if($('addnew')) $('addnew').onclick=()=>openEditor(null);
  [...document.querySelectorAll('.ed')].forEach(b=>b.onclick=async()=>{
    const r=await get(apiUrl('config/item',{doc:cfgDoc,id:b.dataset.id}));
    if(r.error){alert(r.error);return;} openEditor(r.item);});
  [...document.querySelectorAll('.del')].forEach(b=>b.onclick=async()=>{
    if(!confirm('Delete '+b.dataset.id+' from '+cfgDoc+'?'))return;
    const r=await post('/api/config/item/delete',{doc:cfgDoc,id:b.dataset.id,key:b.dataset.id});
    if(!r.ok) alert(r.error||'delete failed');
    render();});
  [...document.querySelectorAll('.mv')].forEach(b=>b.onclick=async()=>{
    const got=await get(apiUrl('config/items',{doc:cfgDoc}));
    const ids=(got.items||[]).map(i=>i[spec.id_field||'id']);
    const i=parseInt(b.dataset.i,10), j=i+parseInt(b.dataset.dir,10);
    if(j<0||j>=ids.length) return;
    [ids[i],ids[j]]=[ids[j],ids[i]];
    const r=await post('/api/config/reorder',{doc:cfgDoc,ids:ids});
    if(!r.ok) alert(r.error||'reorder failed');
    render();});
  wireSort();
}

function hostLink(ip,label){
  if(!ip) return esc(label||'');
  return `<a href="#host/${encodeURIComponent(ip)}" class="hl">${esc(label||ip)}</a>`;
}
function kv(rows){
  const live=rows.filter(r=>r[1]!==''&&r[1]!==undefined&&r[1]!==null);
  if(!live.length) return '<div class="note">nothing recorded</div>';
  return `<table>`+live.map(r=>
    `<tr><td style="color:var(--mut);white-space:nowrap">${esc(r[0])}</td>
     <td>${r[2]?r[1]:esc(String(r[1]))}</td></tr>`).join('')+`</table>`;
}

async function renderHost(v,ip){
  v.innerHTML=`<div class="note">loading ${esc(ip)}...</div>`;
  const d=await get(apiUrl('host',{ip:ip,hours:168}));
  if(d.error){v.innerHTML=`<div class="err">${esc(d.error)}</div>
    <p><a href="#hosts">Back to hosts</a></p>`;return;}
  const i=d.identity||{}, e=d.enrollment||{}, t=d.traffic||{}, dn=d.dns||{};
  const when=x=>x?new Date(x*1000).toLocaleString():'';

  v.innerHTML=
    `<div class="note"><a href="#hosts">&larr; Hosts</a></div>
     <h1 style="margin:2px 0 0">${esc(i.name||ip)}</h1>
     <div class="sub">${esc(ip)}${i.name&&i.name!==ip?'':''}
       ${t.is_blacklisted?' <span class="pill bad">flagged</span>':''}
       ${i.randomized_mac?' <span class="pill warn">randomized MAC</span>':''}</div>

     <div class="row">
       <div class="card" style="flex:1;min-width:250px"><h3>Identity</h3>
         ${kv([['Name',i.name],['From DHCP',i.dhcp_name],
               ['Resolved name',i.resolved_name],['MAC',i.mac],
               ['Vendor',i.vendor],['Device type',i.device_type],
               ['Hypervisor',i.guest],['Guest state',i.guest_status]])}</div>
       <div class="card" style="flex:1;min-width:250px"><h3>Classification</h3>
         ${e.state?kv([['Zone',e.zone==='__existing__'?'pinned where it was':e.zone],
               ['Suggested',e.suggested_zone],['Matched rule',e.rule],
               ['Confidence',e.confidence],['Assigned by',e.source],
               ['Reasoning',e.why],['DHCP vendor class',e.vendor_class],
               ['DHCP fingerprint',e.dhcp_fingerprint],
               ['First seen',when(e.first_seen)],['Last seen',when(e.last_seen)]])
            :'<div class="note">not enrolled</div>'}</div>
       <div class="card" style="flex:1;min-width:250px"><h3>Traffic</h3>
         ${kv([['Sent',bytes(t.sent||0)],['Received',bytes(t.rcvd||0)],
               ['Active flows',t.active_flows],
               ['Flows as client',t.flows_as_client],
               ['Flows as server',t.flows_as_server],
               ['Peers contacted',t.contacts_as_client],
               ['Alerts',t.num_alerts],
               ['Country',[t.city,t.country].filter(Boolean).join(', ')],
               ['Network',t.asname?(t.asname+' (AS'+t.asn+')'):''],
               ['Seen for',t.duration?dur(t.duration):''],
               ['OS',t.os],['DHCP client',t.dhcp_host?'yes':'']])}</div>
     </div>

     ${(d.open_ports||[]).length?`<h2>Listening ports</h2>
       <div>${d.open_ports.map(p=>`<span class="cap">${esc(p)}</span>`).join('')}</div>
       <div class="note">Ports ntopng observed this host accepting connections on.</div>`:''}

     <h2>Applications</h2>
     ${table('happ',[{k:'app',t:'Application'},
       {k:'bytes',t:'Bytes',n:1,f:r=>bytes(r.bytes)},
       {k:'duration',t:'Time',n:1,f:r=>dur(r.duration||0)}],
       d.applications||[],'No application breakdown yet.')}

     <h2>DNS</h2>
     ${dn.error?`<div class="note">${esc(dn.error)}</div>`:
      `<div class="row">
        <div class="card"><h3>Queries</h3><div class="big">${num(dn.total||0)}</div>
          <div class="sub">over ${dn.hours||168}h, ${num(dn.domains||0)} domains</div></div>
        <div class="card"><h3>Blocked</h3><div class="big">${num(dn.blocked||0)}</div>
          <div class="sub">${dn.total?((100*dn.blocked/dn.total).toFixed(1)):0}% of its queries</div></div>
        <div class="card"><h3>NXDOMAIN</h3><div class="big">${num(dn.nxdomain||0)}</div>
          <div class="sub">${num(dn.cached||0)} answered from cache</div></div>
      </div>
      <h3>Most requested</h3>
      ${table('hdns',[{k:'domain',t:'Domain'},
        {k:'queries',t:'Queries',n:1,f:r=>num(r.queries)},
        {k:'blocked',t:'Blocked',n:1,f:r=>r.blocked?
          `<b style="color:#c2410c">${num(r.blocked)}</b>`:'0'}],
        dn.top_domains||[],'No DNS activity recorded.')}
      ${(dn.top_blocked||[]).length?`<h3>Blocked</h3>`+
        table('hblk',[{k:'domain',t:'Domain'},
          {k:'queries',t:'Times',n:1,f:r=>num(r.queries)},
          {k:'blocklist',t:'List'}],dn.top_blocked,''):''}`}

     <h2>Live flows</h2>
     ${table('hflow',[
       {k:'client',t:'Client',f:r=>r.client===ip?esc(r.client_name||r.client):
          hostLink(r.client,r.client_name||r.client)},
       {k:'server',t:'Server',f:r=>r.server===ip?esc(r.server_name||r.server):
          hostLink(r.server,shortName(r.server_name)||r.server)},
       {k:'app',t:'Application'},{k:'l4',t:'Proto'},
       {k:'bytes',t:'Bytes',n:1,f:r=>bytes(r.bytes)}],
       d.flows||[],'No active flows involving this host.')}

     ${(d.alerts||[]).length?`<h2>Alerts</h2>`+
       table('halrt',[{k:'time',t:'When',f:r=>when(r.time)},
         {k:'name',t:'Alert'},{k:'severity',t:'Severity'}],d.alerts,''):''}`;
  wireSort();
}

async function render(){
  const v=$('view');
  if(cur.indexOf('host/')===0){
    return renderHost(v, decodeURIComponent(cur.slice(5)));
  }
  if(cur==='dns'){return renderDns(v);}
  if(cur==='enroll'){return renderEnroll(v);}
  if(cur==='overview'){
    const s=await get('/api/summary')||[];
    const st=await get('/api/status');
    v.innerHTML=`<div class="grid">`+s.map(m=>
      `<div class="card"><div class="k">${esc(m.label)}</div><div class="v">${num(m.value)}</div></div>`).join('')+
      `</div><h2>Modules</h2><div id="mod"></div><h2>Capabilities</h2><div id="caps"></div>`;
    if(st){
      const cls=st.collector==='running'?'ok':'bad';
      $('sub').innerHTML=`read-only &middot; policy is applied from the CLI, never here &middot; collector <span class="pill ${cls}">${esc(st.collector)}</span>`;
      $('mod').innerHTML=table('mod',[
        {k:'name',t:'Source'},
        {k:'ok',t:'Health',f:r=>r.ok===true?'<span class="pill ok">ok</span>':
           r.ok===false?`<span class="pill bad">failing</span> <span class="err">${esc(r.error)}</span>`:
           '<span class="pill warn">unknown</span>'},
        {k:'series',t:'Series',n:1},
        {k:'capabilities',t:'Provides',f:r=>esc((r.capabilities||[]).join(', '))}],
        st.sources,'No sources reporting.');
      const row=(t,l)=>`<div style="margin-bottom:6px"><span style="color:var(--mut);font-size:11px;text-transform:uppercase">${t}</span><br>`+
        (l.length?l.map(c=>`<span class="cap">${esc(c)}</span>`).join(''):'<span class="note">none</span>')+`</div>`;
      $('caps').innerHTML=row('Observe',st.observe_capabilities||[])+row('Enforce',st.enforce_capabilities||[])+
        `<div class="note">Observation is what Flowsight can see. Enforcement is what it can actually change.</div>`+
        (st.stale?`<div class="err">Collector state is ${st.state_age_seconds}s old.</div>`:'');
    }
  }
  else if(cur==='hosts'){
    const d=await get('/api/hosts')||{hosts:[]};
    v.innerHTML=`<h2>Devices seen on the network</h2>`+table('hosts',[
      {k:'ip',t:'Address',f:r=>hostLink(r.ip,r.ip)},
      {k:'local',t:'Scope',f:r=>r.local?'<span class="pill ok">local</span>':'<span class="pill warn">remote</span>'},
      {k:'name',t:'Name'},
      {k:'dns_name',t:'Resolved name',f:r=>r.dns_name?
        `<span title="${esc(r.dns_name)}">${esc(shortName(r.dns_name))}</span>`:''},
      {k:'mac',t:'MAC'},{k:'country',t:'CC'},
      {k:'total',t:'Total',n:1,f:r=>bytes(r.total)},
      {k:'sent',t:'Sent',n:1,f:r=>bytes(r.sent)},
      {k:'recvd',t:'Received',n:1,f:r=>bytes(r.recvd)},
      {k:'flows',t:'Flows',n:1},
      {k:'alerts',t:'Alerts',n:1,f:r=>r.alerts>0?`<span class="pill bad">${r.alerts}</span>`:'0'},
      {k:'blacklisted',t:'Flagged',f:r=>r.blacklisted?'<span class="pill bad">yes</span>':''}],
      d.hosts,'No devices reported. Is ntopng running?')+
      (d.error?`<div class="err">${esc(d.error)}</div>`:'')+
      `<div class="note">From ntopng. Includes remote peers as well as local devices &mdash; the Scope column distinguishes them. Resolved name comes from the names the resolver handed out, so a remote address is shown as what a device asked for rather than as a number. Sorted by traffic; click a column to re-sort.</div>`;
  }
  else if(cur==='flows'){
    const d=await get('/api/flows')||{flows:[]};
    v.innerHTML=`<h2>Active sessions</h2>`+table('flows',[
      {k:'client',t:'Client',f:r=>hostLink(r.client,r.client_name||r.client)},
      {k:'server',t:'Server',f:r=>hostLink(r.server,
        r.server_name?shortName(r.server_name):r.server)},
      {k:'app',t:'Application'},{k:'l4',t:'Proto'},
      {k:'bytes',t:'Bytes',n:1,f:r=>bytes(r.bytes)},
      {k:'duration',t:'Duration',n:1,f:r=>dur(r.duration)}],
      d.flows,'No active flows reported.')+
      (d.error?`<div class="err">${esc(d.error)}</div>`:'')+
      `<div class="note">Application is identified by nDPI, the same engine ntopng uses for L7 classification. Where a name is shown instead of an address, hover to see the address it stands for.</div>`;
  }
  else if(cur==='alerts'){
    const d=await get('/api/alerts')||{alerts:[]};
    v.innerHTML=`<h2>Recent alerts</h2>`+table('alerts',[
      {k:'ts',t:'When',f:r=>esc(new Date(r.ts*1000).toLocaleString())},
      {k:'severity',t:'Severity',f:r=>{const p=(r.severity==='critical'||r.severity==='high')?'bad':
        (r.severity==='medium'?'warn':'ok');return `<span class="pill ${p}">${esc(r.severity)}</span>`}},
      {k:'actor',t:'Actor'},{k:'target',t:'Target'},
      {k:'verdict',t:'Verdict'},{k:'message',t:'Signature'}],
      d.alerts,'No alerts in the query window. On a quiet WAN that is expected, not a fault.');
  }
  else if(cur==='reports'){
    const d=await get(apiUrl('timeseries',{range:range}));
    const btns=['1h','6h','24h','7d'].map(r=>
      `<button class="tab ${r===range?'on':''}" data-r="${r}">${r}</button>`).join('');
    v.innerHTML=`<div class="tabs" style="border:0;margin-bottom:10px">${btns}</div>`+
      `<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(330px,1fr))">`+
      ((d&&d.series)||[]).map(s=>`<div class="card"><div class="k">${esc(s.label)}</div>`+
        (s.error?`<div class="err">${esc(s.error)}</div>`:chart(s.points))+`</div>`).join('')+
      `</div><div class="note">Range queries against the metrics backend, ~120 points per window. A flat line at zero means the metric exists and is genuinely zero; an empty chart means no data was returned for that window.</div>`;
    [...document.querySelectorAll('[data-r]')].forEach(b=>b.onclick=()=>{
      range=b.dataset.r; localStorage.setItem('fs_range',range); render();});
  }
  else if(cur==='devices'){
    const d=await get('/api/devices')||{devices:[]};
    v.innerHTML=`<h2>Device inventory &mdash; ${d.named||0}/${d.total||0} identified</h2>`+table('devices',[
      {k:'identity',t:'Identity',f:r=>r.identity?`<b>${esc(r.identity)}</b>`:'<span class="note">unidentified</span>'},
      {k:'kind',t:'Kind'},
      {k:'status',t:'State',f:r=>r.status?`<span class="pill ${r.status==='running'?'ok':'warn'}">${esc(r.status)}</span>`:''},
      {k:'mac',t:'MAC'},
      {k:'manufacturer',t:'Manufacturer'},
      {k:'hosts',t:'IPs',n:1},
      {k:'traffic',t:'Traffic',n:1,f:r=>bytes(r.traffic)},
      {k:'sent',t:'Sent',n:1,f:r=>bytes(r.sent)},
      {k:'rcvd',t:'Received',n:1,f:r=>bytes(r.rcvd)},
      {k:'seen_since',t:'First seen',f:r=>r.seen_since?esc(new Date(r.seen_since*1000).toLocaleString()):''}],
      d.devices,'No devices reported.')+
      (d.error?`<div class="err">${esc(d.error)}</div>`:'')+
      `<div class="note">Identity resolves in order: hypervisor guest name (${d.hostmap_entries||0} known), then DHCP hostname (${d.lease_entries||0} leases), then ntopng's label. Every virtual NIC shares one OUI, so Manufacturer alone reports "Proxmox" for every guest and tells you nothing &mdash; Identity is what actually names them.</div>`;
  }
  else if(cur==='apps'){
    const d=await get('/api/apps')||{apps:[]};
    v.innerHTML=`<h2>Applications seen (nDPI)</h2>`+table('apps',[
      {k:'app',t:'Application'},
      {k:'breed',t:'Breed',f:r=>{const b=String(r.breed||'').toLowerCase();
        const p=(b.indexOf('unsafe')>=0||b.indexOf('danger')>=0)?'bad':(b.indexOf('fun')>=0?'warn':'ok');
        return r.breed?`<span class="pill ${p}">${esc(r.breed)}</span>`:''}},
      {k:'flows',t:'Flows',n:1},
      {k:'bytes',t:'Bytes',n:1,f:r=>bytes(r.bytes)},
      {k:'sent',t:'Sent',n:1,f:r=>bytes(r.sent)},
      {k:'rcvd',t:'Received',n:1,f:r=>bytes(r.rcvd)}],
      d.apps,'No application data. Is ntopng running?')+
      (d.error?`<div class="err">${esc(d.error)}</div>`:'')+
      `<div class="note">Breed is ntopng's own safety classification of the protocol.</div>`;
  }
  else if(cur==='policy'){
    const p=await get('/api/policy');
    const src=await get('/api/policy_source');
    v.innerHTML=`<h2>Policy</h2>`+
      (src&&src.writable
        ? `<textarea id="polsrc" spellcheck="false" class="editor">${esc(src.text)}</textarea>
           <div style="margin:8px 0"><button id="polsave" class="btn">Validate &amp; save</button>
           <button id="polapply" class="btn">Apply</button>
           <span id="polmsg" class="note"></span></div>`
        : `<pre>${esc((src&&src.text)||'')}</pre><div class="note">Editing is disabled (allow_write is off).</div>`)+
      `<h2>Current plan</h2>`+
      (p&&p.exists?`<pre>${esc(p.status)}${esc(p.plan)}</pre>`
        :`<div class="note">${esc((p&&p.error)||'No policy declared yet.')}</div>`)+
      `<div class="note">Save validates by compiling the policy, and only writes it if it compiles. Apply is a separate, deliberate step.</div>`;
    const msg=$('polmsg');
    if($('polsave')) $('polsave').onclick=async()=>{
      msg.textContent='validating...';
      const r=await post('/api/policy_source',{text:$('polsrc').value});
      msg.innerHTML=(r&&r.ok)?'<span class="pill ok">saved</span>':
        `<span class="pill bad">rejected</span> <span class="err">${esc((r&&r.error)||'failed')}</span>`;
      if(r&&r.ok) setTimeout(render,600);
    };
    if($('polapply')) $('polapply').onclick=async()=>{
      msg.textContent='applying...';
      const r=await post('/api/policy_apply',{});
      msg.innerHTML=(r&&r.ok)?'<span class="pill ok">applied</span>':
        `<span class="pill bad">failed</span> <span class="err">${esc((r&&(r.output||r.error))||'')}</span>`;
      setTimeout(render,800);
    };
  }
  else if(cur==='setup'){
    const d=await get('/api/setup')||{checks:[]};
    v.innerHTML=`<h2>Deployment checklist &mdash; ${d.passed}/${d.total} passing</h2>`+
      table('setup',[
        {k:'ok',t:'',f:r=>r.ok?'<span class="pill ok">ok</span>':'<span class="pill bad">needs attention</span>'},
        {k:'name',t:'Check'},
        {k:'detail',t:'Detail'},
        {k:'fix',t:'How to fix',f:r=>r.ok?'':`<code>${esc(r.fix)}</code>`}],
        d.checks,'No checks returned.')+
      `<div class="note">Every failing check carries the command that fixes it. Nothing here changes anything &mdash; it reports state.</div>`;
  }
  else if(cur==='config'){ return renderConfig(v); }
  wireSort();
}
// Tabs that hold an editor are never re-rendered on a timer: a periodic
// render replaces the DOM, and doing that to a half-written policy or rule set
// discards whatever was typed. The focus check covers the rest - a refresh
// landing mid-keystroke on a filter field is the same loss, briefly.
const NOAUTO=new Set(['policy','config','enroll','setup']);
function autoRefresh(){
  if(NOAUTO.has(cur)) return;
  const el=document.activeElement, t=el&&el.tagName;
  if(t==='INPUT'||t==='TEXTAREA'||t==='SELECT') return;
  render();
}
if(window.FS_EMBEDDED){
  document.getElementById('fsroot').classList.add('embedded');
}else{
  // Reached directly rather than through the GUI: nothing else paints the
  // page, so without this the browser canvas shows through around the app -
  // dark grey under dark text if the operating system asks for dark.
  document.documentElement.style.background='#f5f5f5';
  document.body.style.background='#f5f5f5';
  document.body.style.margin='0';
  document.getElementById('fsroot').style.minHeight='100vh';
  document.getElementById('fsroot').style.padding='14px 16px';
}
tabs(); render(); setInterval(autoRefresh, 15000);
// The OPNsense menu navigates by changing the fragment on the same page, so
// the view has to follow the hash rather than only the in-page buttons.
window.addEventListener('hashchange',()=>{
  const h=location.hash.replace('#','');
  if(h&&h!==cur){cur=h; tabs(); render();}
});
})();
</script>
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "flowsight-ui"

    def _send(self, code, body, ctype="application/json", csp=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        # This page renders only its own data; no third-party anything.
        self.send_header("Content-Security-Policy", csp or
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; connect-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        global _QUERY
        _QUERY = urllib.parse.parse_qs(parsed.query)
        if path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if path in ("/docs", "/docs/", "/api/docs"):
            return self._send(200, DOCS_PAGE, "text/html; charset=utf-8",
                              csp=DOCS_CSP)
        fn = ROUTES.get(path)
        if fn is None:
            return self._send(404, json.dumps({"error": "not found"}))
        try:
            return self._send(200, json.dumps(fn()))
        except Exception as exc:
            return self._send(500, json.dumps({"error": str(exc)}))

    # PUT and DELETE are provided so the API reads as CRUD to anything speaking
    # REST. They are aliases: the OPNsense page that fronts this UI forwards
    # only GET and POST, so every operation must also be reachable by POST or
    # it would work for direct callers and fail behind the GUI.
    VERB_ALIAS = {
        ("PUT", "/api/config/item"): "/api/config/item/update",
        ("POST", "/api/config/item"): "/api/config/item/create",
        ("DELETE", "/api/config/item"): "/api/config/item/delete",
        ("PUT", "/api/config/doc"): "/api/config/doc",
    }

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        if length > 4 * 1024 * 1024:
            raise ValueError("payload too large")
        try:
            return json.loads(self.rfile.read(length).decode("utf-8", "replace"))
        except ValueError:
            raise ValueError("body is not valid JSON")

    def _write_call(self, verb):
        parsed = urllib.parse.urlparse(self.path)
        global _QUERY
        _QUERY = urllib.parse.parse_qs(parsed.query)
        path = self.VERB_ALIAS.get((verb, parsed.path), parsed.path)
        fn = WRITE_ROUTES.get(path)
        if fn is None:
            return self._send(404, json.dumps({"error": "not found"}))
        try:
            body = self._body()
        except ValueError as exc:
            return self._send(400, json.dumps({"error": str(exc)}))
        # Query parameters stand in for a body on DELETE, where senders often
        # omit one entirely.
        for key in ("doc", "id", "key", "name"):
            if key not in body and _QUERY.get(key):
                body[key] = _QUERY[key][0]
        try:
            result = fn(body)
        except Exception as exc:                  # noqa: BLE001
            return self._send(500, json.dumps({"error": str(exc)}))
        code = 200 if (not isinstance(result, dict) or
                       result.get("ok", True)) else 400
        return self._send(code, json.dumps(result))

    def do_PUT(self):
        return self._write_call("PUT")

    def do_DELETE(self):
        return self._write_call("DELETE")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        fn = WRITE_ROUTES.get(path)
        if fn is None:
            return self._send(404, json.dumps({"error": "not found"}))
        if not CFG.get("allow_write"):
            return self._send(403, json.dumps({
                "error": "writes are disabled. Set allow_write in the UI config, "
                         "and only where something in front authenticates."}))
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 1_000_000:
                return self._send(413, json.dumps({"error": "payload too large"}))
            raw = self.rfile.read(length).decode("utf-8", "replace") if length else "{}"
            body = json.loads(raw) if raw.strip() else {}
        except Exception as exc:
            return self._send(400, json.dumps({"error": "bad request: %s" % exc}))
        try:
            return self._send(200, json.dumps(fn(body)))
        except Exception as exc:
            return self._send(500, json.dumps({"error": str(exc)}))

    def log_message(self, *args):
        pass


def main():
    bind, port = CFG["bind"], int(CFG["port"])
    if bind not in ("127.0.0.1", "::1", "localhost"):
        sys.stderr.write(
            "flowsight-ui: WARNING binding to %s. This UI has no authentication; "
            "put an authenticating reverse proxy in front of it.\n" % bind)
    sys.stderr.write("flowsight-ui: listening on http://%s:%s\n" % (bind, port))
    ThreadingHTTPServer((bind, port), Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
