# Licensing

FlowSight has three tiers. Community is the free product and is complete for
a home network; Pro and Business unlock features on top. Nothing in
Community expires, phones home or needs registration.

| | Community | Pro | Business |
|---|---|---|---|
| Visibility (flows, apps, web, DNS, TLS, hosts) | yes | yes | yes |
| DNS, web and application policy | 3 policies, 2 schedules | unlimited | unlimited |
| History kept | 7 days | 90 days | 365 days |
| TLS inspection with a FlowSight CA | | yes | yes |
| Firewall rule hygiene | | yes | yes |
| Device enrolment: enforce mode | monitor only | yes | yes |
| Scheduled reports, CSV export | on-screen reports | yes | yes |
| Notification channels (e-mail, webhook, chat) | alerts in the UI | yes | yes |
| Traffic priority and shaping | | yes | yes |
| Deep inspection of decrypted sessions | | | yes |
| Live egress monitoring and interdiction | | | yes |
| Telemetry export (OTLP / SIEM) | | | yes |
| Directory identity (LDAP / AD / RADIUS) | | | yes |
| Multiple administrators | | | yes |
| Commercial use, SLA support | | | yes |
| Installations per key | 1 | 1 | 5 |

The catalogue lives in `internal/licensing/tiers.go`; the License page shows
it live, with what the installation has.

## How a license works

A license is a small JSON document signed with ed25519. Release builds carry
the public key (`packaging/release/license.pub`) and verify every document
locally; the private key never leaves the license server. There are two ways
to get one onto a firewall:

- **Online activation.** The operator enters an activation key
  (`FSP-XXXX-XXXX-XXXX-XXXX`). The daemon sends it with its installation id,
  hostname and version to the license server, which counts seats and returns
  a signed document bound to that installation, with a lease that the daemon
  refreshes every 24 hours. If the server is unreachable nothing changes;
  if the server says the key is revoked or unknown, the installation returns
  to Community.
- **Offline license file.** For air-gapped firewalls the operator pastes a
  document the server minted for their installation id (shown on the License
  page). It is verified locally and never contacts anything.

Both end in the same verified document, so gating code has one source of
truth: `core.License()`.

**Expiry is soft.** When a license passes its date nothing switches off:
tier features keep their current state and keep running, reads work, but
tier-gated changes (enabling a tier module, saving gated settings, running
gated actions) answer `402` until the license is renewed.

**Builds without the key** (developer builds) cannot verify documents and
run Community. A binary can always be patched, so licensing is a fair-play
mechanism for people who want to pay, not copy protection.

## What gating looks like in code

```go
ctx.Route("POST", "/api/tls/ca/create", m.apiCreate, core.Write(), core.Needs("tls.inspect"))
ctx.Every("analyse", interval, m.analyse, core.NeedsJob("firewall.analyse"))
ctx.Panel(core.Panel{ID: "firewall", ..., Feature: "firewall.analyse"})
if err := m.ctx.License().Allowed("device.enroll"); err != nil { return nil, err }
if lim := m.ctx.License().Limit(licensing.LimitPolicies); lim > 0 && n >= lim { return nil, core.LimitError(...) }
```

`Needs` makes the API answer `402 {"error", "locked": true, "feature", "required", "tier"}`
below the tier; `NeedsJob` makes the scheduler skip the job and report it
as locked; a panel with `Feature` shows a lock in the menu; a module with
`Tier` set cannot be enabled below that tier. The front end turns a 402
into a card that links to the License page.

## The license server

`flowsight-licensed` is one static Linux binary with a SQLite file. It
holds activation keys, records activations per installation, enforces seats,
revokes, and mints documents. Run it behind TLS (a reverse proxy, or
`-tls-cert/-tls-key`) at the address release builds default to
(`https://license.grio.co`; change it in the license module
settings if you host your own).

```sh
# keys: the private one stays on the server, the public one is baked into releases
go run ./cmd/flowsight-sign gen           # -> packaging/release/license.pub + server key file

flowsight-licensed serve  -db /var/lib/flowsight-licensed/licenses.db -key /etc/flowsight-licensed/license.key \
                          -listen 127.0.0.1:8770 -admin-token "$ADMIN" -issuer license.grio.co
flowsight-licensed create -db ... -tier pro -licensee "Ada Lovelace" -email ada@example.org -expires +365d
flowsight-licensed list   -db ...
flowsight-licensed revoke -db ... -key FSP-... -reason "refunded"
flowsight-licensed offline -db ... -key /etc/flowsight-licensed/license.key -lic FSB-... -installation inst_...
```

The same operations exist over HTTP under `/admin/licenses` with a bearer
token, so a shop or a billing system can create keys and revoke them.
Installations only ever call `/v1/activate`, `/v1/refresh` and
`/v1/deactivate` with `{key, installation, hostname, version, platform}`;
no traffic data or device inventory is sent.

## Rotating the license key

Ship one release signed by the current release key that carries the new
license public key, wait for installations to update, then switch the
server to the new private key. Documents signed by the old key stop
verifying on the new builds, so re-issue them (online activations refresh
themselves).
