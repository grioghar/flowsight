# Operations

Running FlowSight day to day: where things are, how to update and roll
back, what to back up, how to read the logs, and what to do when something
looks wrong.

## Where things are

| | OPNsense / FreeBSD | Linux |
|---|---|---|
| Binary | `/usr/local/sbin/flowsightd` (`.previous` after an update) | `/usr/local/sbin/flowsightd` |
| Configuration | `/usr/local/etc/flowsight/flowsight.json` | `/etc/flowsight/flowsight.json` |
| Policy document | `/usr/local/etc/flowsight/policy.json` (+ `.bak`) | `/etc/flowsight/policy.json` |
| Generated backend files | `/usr/local/etc/flowsight/{squid,pf,tls}/` | `/etc/flowsight/…` |
| Store (SQLite) | `/var/db/flowsight/flowsight.db` | `/var/lib/flowsight/flowsight.db` |
| Logs | `/var/log/flowsight/flowsightd.log`, `/var/log/flowsight/squid/` | `journalctl -u flowsight`, `/var/log/flowsight/` |
| Runtime | `/var/run/flowsight/` (pids, squid socket) | `/run/flowsight/` |
| Documentation | `/usr/local/share/flowsight/docs/` | `/usr/share/doc/flowsight/` |
| Service | `service flowsight start|stop|restart|status` | `systemctl … flowsight` |

The rc script on FreeBSD supervises the daemon with `daemon(8)` and
restarts it after five seconds if it exits; systemd does the same on Linux.

## Updating

**In place (recommended).** FlowSight › Updates › *Check now* reads the
signed release manifest; *Install update* downloads the binary for this
OS and architecture, verifies the sha256 and the ed25519 signature against
the key compiled into the running build, swaps the binary atomically and
restarts the service. Downtime is about ten seconds; traffic is unaffected
(interception rules stay loaded because the proxy keeps running). The
previous binary is kept as `flowsightd.previous`; *Roll back* swaps it
back. Only a version newer than the running one is ever applied. Turn on
*Apply updates automatically* under Settings › updater to do this on the
daily check.

**By package.** `pkg add -f os-flowsight-<version>-<arch>.pkg`,
`apt install ./flowsight_<version>_<arch>.deb` or
`dnf install ./flowsight-<version>.<arch>.rpm`. The package also refreshes
the plugin files and the documentation, which in-place updates do not (they
replace the binary only; the plugin files change rarely and the release
notes say when they did).

Every release lists its assets, their checksums and the release notes at
<https://github.com/grioghar/flowsight/releases>.

## Backing up

Three things matter, in this order:

1. **The policy document and configuration**: `flowsight.json`,
   `policy.json`, `zones.json`, `enroll-rules.json`, and on OPNsense the
   OPNsense configuration backup (which carries the plugin's enabled flag).
   Small text files; keep them in version control if you like.
2. **The TLS inspection CA** under `<etc>/tls/`. Losing it means every
   inspected device needs a new root certificate. It is never transmitted,
   so it exists only here.
3. **The store**. History and rollups. It is one SQLite file in WAL mode;
   copy it with `sqlite3 flowsight.db ".backup /path/copy.db"` for a
   consistent snapshot, or stop the service and copy the file. Losing it
   loses history, not configuration.

An OPNsense configuration backup does not include any of these; back up
the directories above with your usual host backup.

## Resources

The daemon runs inside a soft memory limit (default 256 MB, `memory_limit_mb`
in the configuration) and trims its caches as it approaches it; a typical
home network sits at 120 to 180 MB with six million category domains
indexed. squid uses another 50 to 100 MB. CPU is idle apart from feed
refreshes and rollups. The store grows with retention; the System page
shows its size and row counts, and retention is capped by the license tier.

## Logs

- `flowsightd.log` is the daemon log (level set by `log_level`). Module
  loads, applies, findings, job failures and every API error land here.
- The **Events** page is the structured log of what happened; the
  **Audit** view records every write with user and client.
- `squid/cache.log` and `squid/access.log` belong to the FlowSight proxy
  instance. `NAT lookup failed` on a connection from `127.0.0.1` is the
  daemon's own liveness probe and harmless; on a LAN address it means squid
  cannot read `/dev/pf` (see below).
- Unbound's reply log is read where OPNsense writes it
  (`/var/log/resolver/latest.log`); FlowSight adds `log-replies` through an
  include file and removes it on uninstall.

## Health

FlowSight › System shows every module's health and every job's last run.
`GET /api/system/health` returns the same as JSON (`ok` overall, one entry
per module, every job with `ok`, `error`, `duration`, `locked`). A monitoring
system can poll it; the response is loopback-only unless a token is used.

## Troubleshooting

**The FlowSight pages show "authentication required".** On OPNsense the GUI
page proxies with the session's CSRF token; log out and in again. Elsewhere,
sign in with the API token from `flowsight.json`.

**Hosts and sessions stay empty.** Visibility reads ntopng. Check that the
os-ntopng plugin is installed and running, and Settings › visibility for the
last error. FlowSight provisions its own ntopng account through Redis; if
ntopng's Redis is not on the default port, set it there.

**Interception is on but the Web page stays empty.** Settings › web shows
the proxy state. Common causes: another proxy already listens on the
chosen ports (pick others), the OPNsense proxy plugin also intercepts the
same networks (turn its transparent mode off), or the interception rules
were withdrawn because squid stopped answering (read `squid/cache.log`).
Confirm with `pfctl -a flowsight/web -s nat` (rules present) and
`sockstat -4l | grep squid` (listening).

**Every intercepted connection fails and cache.log says NAT lookup failed
for LAN clients.** squid must run in a group that can read `/dev/pf`. The
web module sets `cache_effective_group proxy`; if the group was changed or
removed, restore it or set `squid_group` in Settings › web.

**A port forward or NAT reflection stopped working after interception.**
FlowSight's `rdr-anchor "flowsight/*"` must come after every port forward.
The plugin registers it at the tail; if the anchor was added by hand to
`pf.conf`, move it below the port forwards. See
[Interception](INTERCEPTION.md).

**A policy shows "unmet".** A requirement names a capability no provider
offers: `tls.inspect` without a CA, `web.block` without interception,
`app.block` without ntopng, any pf capability on Linux. The plan names the
capability.

**DNS blocking does not bite.** Clients must use Unbound on this box.
Check the DNS page: if it is empty, clients resolve elsewhere (a Pi-hole,
DoH in the browser, a hard-coded 8.8.8.8). Web blocking still catches them
at the handshake when interception is on.

**The License page says the build cannot verify licenses.** The binary was
built without the release public keys (a developer build). Install a release
build; the tier is Community until then.

**A tier feature says "expired".** The license passed its date. Nothing has
switched off; renew (refresh an online activation, or install a new file) to
change tier settings again.

**Unbound refused a configuration.** FlowSight validates with
`unbound-checkconf` before reloading and reverts on rejection; the apply
result and the Events page carry the checker's message. A hand-written
include with a syntax error under `unbound.opnsense.d` will fail the same
check; fix or remove it.

**The daemon uses more memory than expected.** Lower `memory_limit_mb` (it
is a soft target the Go runtime works towards), reduce category feeds in
Settings › categories, or shorten retention. The System page shows the
runtime statistics.

**Rolling everything back.** Settings › policy › *Enforce policy* off stops
reconciliation; Settings › web › *Intercept* off withdraws the redirects
and stops the proxy. Both take effect within seconds and leave the
document intact. `pkg delete os-flowsight` removes everything FlowSight put
in front of traffic and keeps the data.

## Uninstalling

`pkg delete os-flowsight`, `apt remove flowsight` or `dnf remove flowsight`
stops the service, flushes the `flowsight/*` anchors, removes the Unbound
include files, reloads the resolver and the filter and removes the menu.
The configuration, policy, CA and store directories are left in place.
