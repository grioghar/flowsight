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

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_PATHS = [
    os.environ.get("FLOWSIGHT_UI_CONFIG", ""),
    "/usr/local/etc/flowsight/ui.json",
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
}

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


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
            [CFG["policy_bin"], "status", "-f", CFG["policy_file"]],
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


def api_policy():
    """Declared policy and what applying it would change. Never applies."""
    out = {"exists": os.path.isfile(CFG["policy_file"]),
           "path": CFG["policy_file"], "status": "", "plan": "", "error": ""}
    if not out["exists"]:
        out["error"] = "No policy file at %s" % CFG["policy_file"]
        return out
    for key, cmd in (("status", "status"), ("plan", "plan")):
        try:
            r = subprocess.run([CFG["policy_bin"], cmd, "-f", CFG["policy_file"]],
                               capture_output=True, text=True, timeout=30)
            out[key] = r.stdout or r.stderr
        except Exception as exc:
            out["error"] = str(exc)
    return out


ROUTES = {
    "/api/status": api_status,
    "/api/summary": api_summary,
    "/api/alerts": api_alerts,
    "/api/policy": api_policy,
}

PAGE = """<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Flowsight</title>
<style>
:root{--bg:#f7f7f6;--fg:#1b1b1a;--mut:#6b6b68;--card:#fff;--line:#e2e2df;
      --ok:#2f7d4f;--warn:#b8791b;--crit:#b3352e;--accent:#2b5f8a}
@media(prefers-color-scheme:dark){:root{--bg:#16181a;--fg:#e8e8e6;--mut:#9a9a97;
      --card:#1e2124;--line:#2f3336;--ok:#6cc08b;--warn:#e0a84a;--crit:#e0736a;--accent:#7fb3e0}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
     font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;padding:24px 16px}
.wrap{max-width:1100px;margin:0 auto}
h1{font-size:19px;margin:0 0 2px} .sub{color:var(--mut);font-size:12px;margin-bottom:20px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));margin-bottom:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .k{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em}
.card .v{font-size:22px;font-weight:600;margin-top:4px;font-variant-numeric:tabular-nums}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);
   margin:24px 0 8px;font-weight:600}
table{width:100%;border-collapse:collapse;background:var(--card);
      border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase}
tr:last-child td{border-bottom:0}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;
    padding:12px;overflow-x:auto;font-size:12px;white-space:pre-wrap}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:600}
.ok{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}
.bad{background:color-mix(in srgb,var(--crit) 18%,transparent);color:var(--crit)}
.warn{background:color-mix(in srgb,var(--warn) 18%,transparent);color:var(--warn)}
.cap{display:inline-block;background:color-mix(in srgb,var(--accent) 15%,transparent);
     color:var(--accent);padding:2px 9px;border-radius:5px;font-size:12px;margin:0 6px 6px 0}
.note{color:var(--mut);font-size:12px;margin-top:6px}
.err{color:var(--crit);font-size:12px}
</style>
<div class="wrap">
  <h1>Flowsight</h1>
  <div class="sub" id="sub">read-only &middot; policy is applied from the CLI, never here</div>
  <div class="grid" id="summary"></div>
  <h2>Modules</h2><div id="modules"></div>
  <h2>Capabilities</h2><div id="caps"></div>
  <div class="note">Observation is what Flowsight can see. Enforcement is what it can actually change.</div>
  <h2>Recent alerts</h2><div id="alerts"></div>
  <h2>Policy</h2><div id="policy"></div>
</div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmt=v=>v==null?'&mdash;':(v>=1e9?(v/1e9).toFixed(1)+'G':v>=1e6?(v/1e6).toFixed(1)+'M':
  v>=1e3?(v/1e3).toFixed(1)+'k':(Number.isInteger(v)?v:v.toFixed(1)));
async function get(p){try{const r=await fetch(p);return await r.json()}catch(e){return null}}

async function render(){
  const s=await get('/api/summary');
  $('summary').innerHTML=(s||[]).map(m=>
    `<div class="card"><div class="k">${esc(m.label)}</div><div class="v">${fmt(m.value)}</div></div>`).join('');

  const st=await get('/api/status');
  if(st){
    const cls=st.collector==='running'?'ok':'bad';
    $('sub').innerHTML=`read-only &middot; policy is applied from the CLI, never here &middot; `+
      `collector <span class="pill ${cls}">${esc(st.collector)}</span>`;
    $('modules').innerHTML=st.sources.length?
      `<table><tr><th>Source</th><th>Health</th><th>Series</th><th>Provides</th></tr>`+
      st.sources.map(x=>{
        const h=x.ok===true?'<span class="pill ok">ok</span>':
                x.ok===false?`<span class="pill bad">failing</span>`:
                '<span class="pill warn">unknown</span>';
        return `<tr><td>${esc(x.name)}</td><td>${h}${x.error?' <span class="err">'+esc(x.error)+'</span>':''}</td>`+
               `<td>${x.series}</td><td>${(x.capabilities||[]).map(esc).join(', ')}</td></tr>`}).join('')+`</table>`
      :`<div class="note">No sources are reporting. The collector may be down, or nothing has been scraped yet.</div>`;
    const capRow=(t,list)=>`<div style="margin-bottom:6px"><span class="k" style="color:var(--mut);font-size:11px;text-transform:uppercase">${t}</span><br>`+
      (list.length?list.map(c=>`<span class="cap">${esc(c)}</span>`).join(''):'<span class="note">none</span>')+`</div>`;
    $('caps').innerHTML=capRow('Observe',st.observe_capabilities||[])+capRow('Enforce',st.enforce_capabilities||[]);
    if(st.stale) $('caps').innerHTML+=`<div class="err">Collector state is ${st.state_age_seconds}s old &mdash; it may have stopped without clearing it.</div>`;
    if(st.errors&&st.errors.length)
      $('caps').innerHTML+=st.errors.map(e=>`<div class="err">${esc(e)}</div>`).join('');
  }

  const a=await get('/api/alerts');
  if(a){
    $('alerts').innerHTML=a.alerts.length?
      `<table><tr><th>When</th><th>Severity</th><th>Actor</th><th>Target</th><th>Signature</th></tr>`+
      a.alerts.map(x=>{const p=(x.severity==='critical'||x.severity==='high')?'bad':
        (x.severity==='medium'?'warn':'ok');
        return `<tr><td>${esc(new Date(x.ts*1000).toLocaleTimeString())}</td>`+
        `<td><span class="pill ${p}">${esc(x.severity)}</span></td>`+
        `<td>${esc(x.actor)}</td><td>${esc(x.target)}</td><td>${esc(x.message)}</td></tr>`}).join('')+`</table>`
      :`<div class="note">No alerts in the query window. On a quiet WAN that is the expected state, not a fault.</div>`;
  }

  const p=await get('/api/policy');
  if(p){
    $('policy').innerHTML = p.exists
      ? `<pre>${esc(p.status)}\n${esc(p.plan)}</pre>`
      : `<div class="note">${esc(p.error||'No policy declared.')}</div>`;
  }
}
render(); setInterval(render, 15000);
</script>
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "flowsight-ui"

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        # This page renders only its own data; no third-party anything.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; connect-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        fn = ROUTES.get(path)
        if fn is None:
            return self._send(404, json.dumps({"error": "not found"}))
        try:
            return self._send(200, json.dumps(fn()))
        except Exception as exc:
            return self._send(500, json.dumps({"error": str(exc)}))

    def do_POST(self):
        # There is deliberately no write surface. Applying policy is a CLI act.
        self._send(405, json.dumps({"error": "this UI is read-only"}))

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
