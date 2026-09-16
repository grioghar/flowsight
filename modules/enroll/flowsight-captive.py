#!/usr/bin/env python3
"""The identification page an unidentified device is redirected to.

This is deliberately a separate service from the Flowsight UI. The UI is
reached through the authenticated OPNsense web GUI; a device sitting in
quarantine cannot log in to anything, so the page it is redirected to has to be
reachable without credentials. Keeping it in its own process means the
unauthenticated surface is exactly this file and nothing else: it can read the
zone list and set one device's zone, and it can do nothing else.

Three constraints hold that surface down:

  * Requests are served only to clients whose address is inside the captive
    zone. Anything else gets 403, so this is not an unauthenticated zone-change
    endpoint for the rest of the network.
  * A device may only ever set its own zone - the MAC is looked up from the
    source address in the lease table, never taken from the request.
  * The offered zones come from the zone file, so a device cannot name a zone
    that does not exist, and zones marked "self_service": false are not offered.

A device declaring what it is remains a claim, not proof. With captive_policy
"approve", a declaration is queued for a human instead of applied.
"""

import html
import json
import os
import re
import subprocess
import sys
import time
import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

CONF_DIR = os.environ.get("FLOWSIGHT_ETC", "/usr/local/etc/flowsight")
STATE_DIR = os.environ.get("FLOWSIGHT_STATE", "/var/db/flowsight")
ZONES_FILE = os.path.join(CONF_DIR, "zones.json")
REGISTRY = os.path.join(STATE_DIR, "enroll-registry.json")
CLAIMS = os.path.join(STATE_DIR, "enroll-claims.jsonl")
LEASES = "/var/db/dnsmasq.leases"
ENROLL_BIN = "/usr/local/sbin/flowsight-enroll"
PORT = int(os.environ.get("FLOWSIGHT_CAPTIVE_PORT", "8081"))
MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")

# Every major OS probes one of these over plain HTTP to decide whether it is
# behind a captive portal. Answering them with a redirect is what makes the
# sign-in sheet open by itself instead of the user seeing a dead browser.
PROBES = ("/generate_204", "/gen_204", "/hotspot-detect.html", "/ncsi.txt",
          "/connecttest.txt", "/success.txt", "/canonical.html",
          "/library/test/success.html")

PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Identify this device</title><style>
:root{color-scheme:light dark;--bg:#f5f6f8;--fg:#14171c;--card:#fff;--line:#d9dde3;--accent:#2f6fed}
@media(prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e8eaed;--card:#1d2128;--line:#2c313a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
display:flex;justify-content:center;padding:24px 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:24px;max-width:520px;width:100%%}
h1{margin:0 0 4px;font-size:21px}p.sub{margin:0 0 20px;opacity:.7;font-size:14px}
dl{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;margin:0 0 22px;
font-size:13px}dt{opacity:.6}dd{margin:0;font-family:ui-monospace,Menlo,monospace}
label{display:block;border:1px solid var(--line);border-radius:9px;padding:12px 14px;
margin-bottom:9px;cursor:pointer}label:hover{border-color:var(--accent)}
label input{margin-right:9px}label b{font-weight:600}label span{display:block;
margin-left:25px;opacity:.65;font-size:13px}
button{width:100%%;padding:13px;border:0;border-radius:9px;background:var(--accent);
color:#fff;font-size:15px;font-weight:600;cursor:pointer}
.ok{border-left:3px solid var(--accent);padding-left:14px}
</style></head><body><div class="card">%s</div></body></html>"""


def _read_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return default


def leases_by_ip():
    out = {}
    try:
        with open(LEASES) as fh:
            for line in fh:
                p = line.split()
                if len(p) >= 4 and MAC_RE.match(p[1].upper()):
                    out[p[2]] = {"mac": p[1].upper(),
                                 "hostname": "" if p[3] == "*" else p[3]}
    except Exception:
        pass
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "flowsight-captive"

    def log_message(self, *args):
        pass

    # -- helpers ---------------------------------------------------------
    def _zones(self):
        return _read_json(ZONES_FILE, {"zones": []})

    def _captive_net(self, zones):
        for z in zones.get("zones", []):
            if z.get("captive"):
                try:
                    return ipaddress.ip_network(z["subnet"], strict=False)
                except ValueError:
                    return None
        return None

    def _client(self):
        """The device asking, identified from its address alone.

        Returns (ip, mac, hostname) or (ip, None, None) when the caller is not
        a quarantined device - which is the only thing this service will talk to.
        """
        ip = self.client_address[0]
        zones = self._zones()
        net = self._captive_net(zones)
        if net is None:
            return ip, None, None
        try:
            if ipaddress.ip_address(ip) not in net:
                return ip, None, None
        except ValueError:
            return ip, None, None
        rec = leases_by_ip().get(ip)
        if not rec:
            return ip, None, None
        return ip, rec["mac"], rec["hostname"]

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    # -- routes ----------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?")[0]
        if path in PROBES:
            self._send(302, "", extra={"Location": "http://%s:%d/" % (
                self.headers.get("Host", "").split(":")[0] or
                self.server.server_address[0], PORT)})
            return
        if path != "/":
            self._send(302, "", extra={"Location": "/"})
            return

        ip, mac, hostname = self._client()
        if not mac:
            self._send(403, PAGE % (
                "<h1>Not applicable</h1><p class='sub'>This page identifies "
                "devices being held in quarantine. This address is not one of "
                "them.</p>"))
            return

        zones = self._zones()
        choices = [z for z in zones.get("zones", [])
                   if not z.get("captive") and z.get("self_service", True)]
        opts = "".join(
            "<label><input type='radio' name='zone' value='%s'%s><b>%s</b>"
            "<span>%s</span></label>" % (
                html.escape(z["id"]), " required" if i == 0 else "",
                html.escape(z.get("name", z["id"])),
                html.escape(z.get("description", "")))
            for i, z in enumerate(choices))

        self._send(200, PAGE % (
            "<h1>Identify this device</h1>"
            "<p class='sub'>This network places devices by what they are. "
            "Tell it what this one is to get access.</p>"
            "<dl><dt>Address</dt><dd>%s</dd><dt>Hardware</dt><dd>%s</dd>"
            "<dt>Name</dt><dd>%s</dd></dl>"
            "<form method='POST' action='/identify'>%s"
            "<button type='submit'>Continue</button></form>" % (
                html.escape(ip), html.escape(mac),
                html.escape(hostname or "(none given)"), opts)))

    def do_POST(self):
        if self.path.split("?")[0] != "/identify":
            self._send(404, PAGE % "<h1>Not found</h1>")
            return
        ip, mac, hostname = self._client()
        if not mac:
            self._send(403, PAGE % "<h1>Not applicable</h1>")
            return

        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > 4096:
            self._send(400, PAGE % "<h1>Bad request</h1>")
            return
        body = self.rfile.read(n).decode("utf-8", "replace")
        want = ""
        for pair in body.split("&"):
            k, _, v = pair.partition("=")
            if k == "zone":
                want = urllib_unquote(v)
        zones = self._zones()
        valid = {z["id"] for z in zones.get("zones", [])
                 if not z.get("captive") and z.get("self_service", True)}
        if want not in valid:
            self._send(400, PAGE % (
                "<h1>Unknown choice</h1><p class='sub'>That is not one of the "
                "offered options.</p>"))
            return

        # Every declaration is recorded whether or not it is applied. A device
        # choosing its own class is a claim, and the record is what makes a
        # wrong or dishonest claim reviewable afterwards.
        claim = {"at": int(time.time()), "mac": mac, "ip": ip,
                 "hostname": hostname, "zone": want,
                 "user_agent": self.headers.get("User-Agent", "")[:200],
                 "policy": zones.get("captive_policy", "self_service")}
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            with open(CLAIMS, "a") as fh:
                fh.write(json.dumps(claim) + "\n")
        except Exception:
            pass

        name = next((z.get("name", want) for z in zones.get("zones", [])
                     if z["id"] == want), want)
        if claim["policy"] == "approve":
            self._send(200, PAGE % (
                "<h1>Sent for approval</h1><p class='sub ok'>This device asked "
                "to join <b>%s</b>. Someone who administers the network has to "
                "approve it before it gets access.</p>" % html.escape(name)))
            return

        subprocess.run([sys.executable, ENROLL_BIN, "assign", mac, want],
                       capture_output=True, text=True, timeout=30)
        subprocess.run([sys.executable, ENROLL_BIN, "apply"],
                       capture_output=True, text=True, timeout=120)
        self._send(200, PAGE % (
            "<h1>Done</h1><p class='sub ok'>This device is now in <b>%s</b>. "
            "Disconnect from the network and reconnect - it needs a new address "
            "before it can reach anything.</p>" % html.escape(name)))


def urllib_unquote(s):
    from urllib.parse import unquote_plus
    return unquote_plus(s)


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
