# Installing Flowsight

## OPNsense

1. Install `os-ntopng` from System › Firmware › Plugins (recommended; it
   provides application identification). Leave the OPNsense proxy plugin
   (`os-squid`) without transparent interception on the networks Flowsight
   will intercept, or uninstall it: Flowsight runs its own squid instance.
2. Install the package:

   ```sh
   fetch https://github.com/grioghar/flowsight/releases/latest/download/os-flowsight-amd64.pkg
   pkg add os-flowsight-amd64.pkg
   ```

   The post-install script enables the service, registers the pf anchors and
   reloads the filter. Open **Services › Flowsight**.
3. First run: the Overview shows hosts and flows within a minute. Under
   *Settings › visibility* the daemon has created its own ntopng account; no
   ntopng login is needed. Category feeds download in the background (a few
   minutes; roughly 6 million domains).
4. Web interception: *Settings › web › Intercept web traffic*. From then on
   every web session carries its server name and web policies can block.
5. Policies: create groups and policies, look at the plan, then turn on
   *Settings › policy › Enforce policy*. Until then nothing is written to any
   backend.
6. TLS inspection: *TLS › Create inspection CA*, download the certificate,
   install it as a trusted root on the devices you intend to inspect, and set
   `tls.inspect` on their policy with a bypass list for banking and pinned
   applications.

Uninstalling (`pkg delete os-flowsight`) stops the service, withdraws the
interception and policy rules, removes the resolver includes and reloads the
resolver and filter. The store under `/var/db/flowsight` and the policy under
`/usr/local/etc/flowsight` are kept.

## Debian and Ubuntu

```sh
curl -fsSL https://github.com/grioghar/flowsight/releases/latest/download/install.sh | sh
```

or build the package yourself with `packaging/debian/build-deb.sh`. The
installer writes `/etc/flowsight/flowsight.json` with a generated API token
and starts the `flowsight` unit. The UI is on `http://127.0.0.1:8080`; to
expose it on a LAN set `"bind"` in the config file (the token protects it) or
put it behind a reverse proxy.

Backends are found where the distribution keeps them (Unbound in
`/etc/unbound`, squid in `/etc/squid`, Suricata's EVE log in
`/var/log/suricata`). Paths can be overridden under `"paths"` in the config.
On Linux the pf providers are unavailable: DNS policy, visibility, reports
and alerting work; web and application enforcement wait for nftables
providers.

## FreeBSD (not OPNsense)

The same installer works. Add to `pf.conf`:

```
nat-anchor "flowsight/*"
rdr-anchor "flowsight/*"
anchor "flowsight/*" quick
```

and reload pf. The firewall module reports a finding until the anchor is
referenced.

## Configuration file

`flowsight.json` holds only what you change; every key has a default.

```json
{
  "site_name": "Home",
  "bind": "127.0.0.1",
  "port": 8080,
  "api_token": "",
  "retention": { "flows_days": 7, "dns_days": 7, "alerts_days": 30, "rollup_days": 400 },
  "modules": {
    "web": { "intercept": true, "networks": ["10.0.0.0/24"] },
    "policy": { "enforce": true },
    "telemetry": { "enabled": true, "metrics_endpoint": "http://metrics:4318/v1/metrics" }
  }
}
```

`bind`, `port`, `api_token`, `data_dir` and `paths` can only be changed in
this file, never through the API: whoever can change where the daemon listens
is root, and the API is not.

## Building from source

```sh
git clone https://github.com/grioghar/flowsight && cd flowsight
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.Version=1.0.0" -o flowsightd ./cmd/flowsightd
packaging/freebsd/build-pkg.sh 1.0.0 amd64 ./flowsightd plugin/os-flowsight/src ./dist   # run on FreeBSD (needs pkg)
```

Go 1.24 or newer, no cgo, no other toolchain.
