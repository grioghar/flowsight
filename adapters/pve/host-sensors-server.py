#!/usr/bin/env python3
"""Serve pve1's hardware temperatures as JSON on the LAN.

VM 102 (OPNsense) is a KVM guest whose PCI bus is an emulated Intel Q35, so
amdtemp/coretemp never attach and it has no thermal sysctls of its own. The
physical sensors only exist here on the host. OPNsense's dashboard widget pulls
this endpoint.

Deliberately a plain HTTP pull rather than a push through the qemu guest agent:
driving `qm guest exec` on a short loop wedged the agent, and that agent is the
management path for the firewall. Nothing here can hang the guest.
"""

import json
import os
import re
import socket
import sys
import subprocess
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND = "192.168.1.252"
PORT = 9099
CACHE_TTL = 5  # seconds; sensors don't move fast and this caps `sensors` execs

# Metrics go to the telemetry VIP, matching how the other agents report: the
# keepalived VIP fronts whichever gateway node is active, so this survives a
# node failover without knowing which node is up.
OTLP_ENDPOINT = "http://192.168.1.251:4318/v1/metrics"
# Guest identity map. Regenerated on a slow cycle: VMs and containers are
# created and renamed on human timescales, and building it shells out to
# qm/pct once per guest, which is slow on a busy host.
HOSTMAP_SCRIPT = "/usr/local/sbin/flowsight-hostmap"
HOSTMAP_PATH = "/var/lib/flowsight/hostmap.json"
HOSTMAP_TTL = 900
OTLP_INTERVAL = 15  # seconds between metric pushes
METRIC_NAME = "host_sensor_temperature_celsius"

CHIP_LABELS = {
    "k10temp": ("CPU", "cpu"),
    "coretemp": ("CPU", "cpu"),
    "nvme": ("NVMe", "disk"),
    "amdgpu": ("GPU", "gpu"),
    "i915": ("GPU", "gpu"),
    "iwlwifi": ("WiFi", "other"),
}

_cache = {"at": 0.0, "body": b""}


def collect():
    raw = json.loads(
        subprocess.run(
            ["sensors", "-j"], capture_output=True, text=True, timeout=10
        ).stdout
    )

    out = []
    for chip, feats in raw.items():
        # "iwlwifi_1-virtual-0" -> "iwlwifi"; drop the hwmon index too
        base = re.sub(r"_\d+$", "", chip.split("-")[0])
        label, kind = CHIP_LABELS.get(base, (base, "other"))
        if not isinstance(feats, dict):
            continue
        for feat, vals in feats.items():
            if not isinstance(vals, dict):
                continue
            for key, val in vals.items():
                # current temperature readings only, not the min/max/crit limits
                if not (key.startswith("temp") and key.endswith("_input")):
                    continue
                try:
                    temp = float(val)
                except (TypeError, ValueError):
                    continue
                # lm-sensors reports unset limits as absurd values
                if temp < -50 or temp > 200:
                    continue
                out.append({
                    "device": "%s %s" % (label, feat),
                    "type": kind,
                    "temperature": round(temp, 1),
                })

    return {
        "host": socket.gethostname(),
        "timestamp": int(time.time()),
        "sensors": out,
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = self.path.rstrip("/")
        if path == "/hostmap.json":
            try:
                body = _hostmap()
            except Exception:
                self.send_error(503, "hostmap unavailable")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path not in ("", "/host_sensors.json"):
            self.send_error(404)
            return

        now = time.monotonic()
        if now - _cache["at"] > CACHE_TTL or not _cache["body"]:
            try:
                _cache["body"] = json.dumps(collect()).encode()
                _cache["at"] = now
            except Exception:
                self.send_error(503, "sensor read failed")
                return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(_cache["body"])))
        self.end_headers()
        self.wfile.write(_cache["body"])

    def log_message(self, *args):
        pass  # don't spam the journal on every dashboard tick


_hostmap_cache = {"at": 0.0, "body": b""}


def _hostmap():
    """Guest identity map, regenerated at most every HOSTMAP_TTL.

    Serves a stale map rather than blocking or failing when regeneration is
    slow, and never replaces a good cache with a truncated write.
    """
    now = time.monotonic()
    if _hostmap_cache["body"] and now - _hostmap_cache["at"] < HOSTMAP_TTL:
        return _hostmap_cache["body"]
    try:
        os.makedirs(os.path.dirname(HOSTMAP_PATH), exist_ok=True)
        subprocess.run([HOSTMAP_SCRIPT, HOSTMAP_PATH], capture_output=True,
                       text=True, timeout=240)
    except Exception as exc:
        # Reported, not swallowed. "os" was missing from the imports here for
        # some time: every refresh raised NameError, this handler discarded it,
        # and the guest map silently served a 22-hour-old snapshot while
        # looking perfectly healthy.
        sys.stderr.write("host-sensors: hostmap refresh failed: %r\n" % (exc,))
    try:
        with open(HOSTMAP_PATH, "rb") as fh:
            body = fh.read()
        json.loads(body)
        _hostmap_cache["body"] = body
        _hostmap_cache["at"] = now
    except Exception:
        if not _hostmap_cache["body"]:
            raise
    return _hostmap_cache["body"]



# ---------------------------------------------------------------------------
# Host resource metrics
#
# Added because this host went unreachable for a quarter of an hour with swap
# completely full and nothing recorded it. Only temperatures were being
# published, so the one failure that actually took the machine down was the one
# thing invisible in the telemetry.
#
# Everything here is read from /proc and /sys - no subprocesses. On a host that
# has already been pushed over by a burst of short-lived processes, a metrics
# collector that forks is part of the problem.

# Unit strings matter: the OTLP-to-Prometheus translation appends the unit to
# the metric name, so a dimensionless count declared as unit "1" arrives as
# host_load1_ratio rather than host_load1. Counts therefore carry no unit, and
# only genuine ratios use "1" - their names already end in _ratio, which the
# exporter does not duplicate.
_disk_prev = {}


def _meminfo():
    out = {}
    with open("/proc/meminfo") as fh:
        for line in fh:
            key, _, rest = line.partition(":")
            parts = rest.split()
            if parts:
                out[key] = int(parts[0]) * 1024
    return out


def _disk_util():
    """Per-device busy fraction, from the io_ticks counter in /proc/diskstats.

    io_ticks is milliseconds during which the queue was non-empty, so the
    fraction of wall time it advanced is exactly the utilisation iostat prints.
    Needs two samples, so the first call after start reports nothing.
    """
    now = time.monotonic()
    out = {}
    try:
        with open("/proc/diskstats") as fh:
            rows = fh.read().splitlines()
    except OSError:
        return out
    for line in rows:
        f = line.split()
        if len(f) < 13:
            continue
        name = f[2]
        # Whole devices only: partitions and device-mapper nodes duplicate the
        # same physical busy time and would be counted several times over.
        if name.startswith(("loop", "dm-", "zram", "sr")) or name[-1].isdigit():
            continue
        try:
            io_ticks = int(f[12])
        except ValueError:
            continue
        prev = _disk_prev.get(name)
        _disk_prev[name] = (now, io_ticks)
        if not prev:
            continue
        dt = now - prev[0]
        if dt <= 0:
            continue
        frac = (io_ticks - prev[1]) / (dt * 1000.0)
        out[name] = max(0.0, min(1.0, frac))
    return out


def collect_host():
    """(metric_name, value, attributes, unit) for this host's resource state."""
    series = []
    try:
        mem = _meminfo()
    except OSError:
        return series

    total = mem.get("MemTotal", 0)
    avail = mem.get("MemAvailable", 0)
    if total:
        series.append(("host_memory_total_bytes", total, {}, "By"))
        series.append(("host_memory_available_bytes", avail, {}, "By"))
        series.append(("host_memory_used_ratio", (total - avail) / total, {}, "1"))

    sw_total = mem.get("SwapTotal", 0)
    sw_free = mem.get("SwapFree", 0)
    series.append(("host_swap_total_bytes", sw_total, {}, "By"))
    series.append(("host_swap_used_bytes", sw_total - sw_free, {}, "By"))
    if sw_total:
        # The metric that would have caught the outage: swap filling, not
        # memory being merely used.
        series.append(("host_swap_used_ratio",
                       (sw_total - sw_free) / sw_total, {}, "1"))

    try:
        with open("/proc/loadavg") as fh:
            la = fh.read().split()
        series.append(("host_load1", float(la[0]), {}, ""))
        series.append(("host_load15", float(la[2]), {}, ""))
    except (OSError, ValueError, IndexError):
        pass

    try:
        with open("/proc/stat") as fh:
            for line in fh:
                if line.startswith("procs_blocked"):
                    # Processes in uninterruptible sleep. This is what a load
                    # average of 30 on an idle CPU is actually made of.
                    series.append(("host_procs_blocked",
                                   float(line.split()[1]), {}, ""))
                    break
    except (OSError, ValueError, IndexError):
        pass

    for dev, frac in _disk_util().items():
        series.append(("host_disk_utilisation_ratio", frac,
                       {"device": dev}, "1"))

    try:
        cpus = os.cpu_count() or 1
        series.append(("host_cpu_count", float(cpus), {}, ""))
    except Exception:
        pass
    return series


def push_otlp(reading):
    """Send one OTLP/HTTP JSON metric batch to the telemetry gateway."""
    now = str(int(time.time() * 1e9))

    points = [{
        "asDouble": s["temperature"],
        "timeUnixNano": now,
        "attributes": [
            {"key": "sensor", "value": {"stringValue": s["device"]}},
            {"key": "type", "value": {"stringValue": s["type"]}},
        ],
    } for s in reading["sensors"]]

    metrics = [{
        "name": METRIC_NAME,
        "unit": "Cel",
        "gauge": {"dataPoints": points},
    }]

    # Resource metrics ride along in the same batch: one request, one timestamp,
    # and no second thing to notice has stopped working.
    for name, value, attrs, unit in collect_host():
        metrics.append({
            "name": name,
            "unit": unit,
            "gauge": {"dataPoints": [{
                "asDouble": float(value),
                "timeUnixNano": now,
                "attributes": [
                    {"key": k, "value": {"stringValue": v}}
                    for k, v in attrs.items()
                ],
            }]},
        })

    payload = {"resourceMetrics": [{
        "resource": {"attributes": [
            {"key": "host.name", "value": {"stringValue": reading["host"]}},
        ]},
        "scopeMetrics": [{
            "scope": {"name": "host-sensors"},
            "metrics": metrics,
        }],
    }]}

    req = urllib.request.Request(
        OTLP_ENDPOINT,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=5).close()


def metrics_loop():
    """Push readings on an interval.

    Deliberately swallows every error: this thread must never be able to take
    down the HTTP endpoint that the OPNsense dashboard widget depends on.
    """
    while True:
        try:
            push_otlp(collect())
        except Exception:
            pass
        time.sleep(OTLP_INTERVAL)


if __name__ == "__main__":
    threading.Thread(target=metrics_loop, daemon=True).start()
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
