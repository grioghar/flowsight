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


def _ntopng(path):
    url = "%s/lua/rest/v2/get/%s" % (CFG["ntopng_url"].rstrip("/"), path)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def api_hosts():
    """Per-device report: who is on the network and what they are doing."""
    try:
        rsp = _ntopng("host/active.lua?ifid=0&perPage=100").get("rsp", {})
        rows = []
        for h in rsp.get("data", []):
            b = h.get("bytes", {}) or {}
            rows.append({
                "ip": h.get("ip", ""),
                "name": (h.get("name") or "") if h.get("name") != h.get("ip") else "",
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
        rows = []
        for f in raw or []:
            cli = f.get("client", {}) or {}
            srv = f.get("server", {}) or {}
            proto = f.get("protocol", {}) or {}
            b = f.get("bytes", {}) or {}
            rows.append({
                "client": cli.get("ip") or cli.get("name", ""),
                "server": srv.get("ip") or srv.get("name", ""),
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
    "/api/hosts": api_hosts,
    "/api/flows": api_flows,
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
.fs{color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
.fs h1{font-size:19px;margin:0 0 2px}
.fs .sub{color:var(--mut);font-size:12px;margin-bottom:14px}
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--line);margin-bottom:16px;flex-wrap:wrap}
.tab{padding:7px 14px;cursor:pointer;border:0;background:none;color:var(--mut);
     font:600 12px/1.4 inherit;text-transform:uppercase;letter-spacing:.05em;
     border-bottom:2px solid transparent}
.tab:hover{color:var(--fg)}
.tab.on{color:var(--accent);border-bottom-color:var(--accent)}
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
</style>
<div class="fs">
  <h1>Flowsight</h1>
  <div class="sub" id="sub">read-only &middot; policy is applied from the CLI, never here</div>
  <div class="tabs" id="tabs"></div>
  <div id="view"></div>
</div>
<script>
(function(){
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const num=v=>v==null?'&mdash;':(v>=1e9?(v/1e9).toFixed(1)+'G':v>=1e6?(v/1e6).toFixed(1)+'M':
  v>=1e3?(v/1e3).toFixed(1)+'k':(Number.isInteger(v)?v:(+v).toFixed(1)));
const bytes=v=>v==null?'&mdash;':(v>=1073741824?(v/1073741824).toFixed(2)+' GB':
  v>=1048576?(v/1048576).toFixed(1)+' MB':v>=1024?(v/1024).toFixed(1)+' KB':v+' B');
const dur=s=>s==null?'':(s>=3600?Math.floor(s/3600)+'h':s>=60?Math.floor(s/60)+'m':s+'s');
async function get(p){try{const r=await fetch(p);return await r.json()}catch(e){return null}}

const TABS=[['overview','Overview'],['hosts','Devices'],['flows','Live flows'],
            ['alerts','Alerts'],['policy','Policy']];
let cur=location.hash.replace('#','')||'overview';
let sortKey={}, sortDir={};

function tabs(){
  $('tabs').innerHTML=TABS.map(([k,l])=>
    `<button class="tab ${k===cur?'on':''}" data-t="${k}">${l}</button>`).join('');
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

async function render(){
  const v=$('view');
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
      {k:'ip',t:'Address'},
      {k:'local',t:'Scope',f:r=>r.local?'<span class="pill ok">local</span>':'<span class="pill warn">remote</span>'},
      {k:'name',t:'Name'},{k:'mac',t:'MAC'},{k:'country',t:'CC'},
      {k:'total',t:'Total',n:1,f:r=>bytes(r.total)},
      {k:'sent',t:'Sent',n:1,f:r=>bytes(r.sent)},
      {k:'recvd',t:'Received',n:1,f:r=>bytes(r.recvd)},
      {k:'flows',t:'Flows',n:1},
      {k:'alerts',t:'Alerts',n:1,f:r=>r.alerts>0?`<span class="pill bad">${r.alerts}</span>`:'0'},
      {k:'blacklisted',t:'Flagged',f:r=>r.blacklisted?'<span class="pill bad">yes</span>':''}],
      d.hosts,'No devices reported. Is ntopng running?')+
      (d.error?`<div class="err">${esc(d.error)}</div>`:'')+
      `<div class="note">From ntopng. Includes remote peers as well as local devices &mdash; the Scope column distinguishes them. Sorted by traffic; click a column to re-sort.</div>`;
  }
  else if(cur==='flows'){
    const d=await get('/api/flows')||{flows:[]};
    v.innerHTML=`<h2>Active sessions</h2>`+table('flows',[
      {k:'client',t:'Client'},{k:'server',t:'Server'},
      {k:'app',t:'Application'},{k:'l4',t:'Proto'},
      {k:'bytes',t:'Bytes',n:1,f:r=>bytes(r.bytes)},
      {k:'duration',t:'Duration',n:1,f:r=>dur(r.duration)}],
      d.flows,'No active flows reported.')+
      (d.error?`<div class="err">${esc(d.error)}</div>`:'')+
      `<div class="note">Application is identified by nDPI, the same engine ntopng uses for L7 classification.</div>`;
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
  else if(cur==='policy'){
    const p=await get('/api/policy');
    v.innerHTML=`<h2>Declared policy and plan</h2>`+
      (p&&p.exists?`<pre>${esc(p.status)}\n${esc(p.plan)}</pre>`
        :`<div class="note">${esc((p&&p.error)||'No policy declared.')}</div>`)+
      `<div class="note">Editing and applying policy is deliberately not available here &mdash; use <code>flowsight-policy</code>.</div>`;
  }
  wireSort();
}
tabs(); render(); setInterval(render, 15000);
})();
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
