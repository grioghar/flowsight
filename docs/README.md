# FlowSight documentation

FlowSight is open, self-hosted layer-7 visibility, policy and enforcement
for OPNsense and other gateways: one static binary that compiles one policy
onto the engines the firewall already runs (Unbound, squid, pf, nDPI through
ntopng, Suricata), keeps everything in an embedded store, and never sends
data anywhere.

This is the complete manual. It is shipped with every package under
`/usr/local/share/flowsight/docs` (OPNsense and FreeBSD) or
`/usr/share/doc/flowsight` (Linux), as Markdown and as PDF, and published
with every release.

| Chapter | Read it when |
|---|---|
| [Getting started](GETTING-STARTED.md) | You have a gateway and thirty minutes. Install, first look, first policy, interception, TLS inspection. |
| [Concepts](CONCEPTS.md) | You want to understand the model before trusting it: modules, capabilities, providers, the policy document, tiers. |
| [User guide](USER-GUIDE.md) | Page by page: what every screen shows, what every button does. |
| [The policy document](POLICY.md) | The exact grammar of groups, schedules, policies, exclusions, and what each denial compiles to. |
| [Interception](INTERCEPTION.md) | How web traffic is redirected to the proxy, IPv6, pf ordering, what can go wrong. |
| [Configuration reference](CONFIGURATION.md) | Every setting of every module, with defaults. |
| [API reference](API.md) | Every HTTP route, conventions, examples. |
| [Operations](OPERATIONS.md) | Updates and roll back, backups, logs, resources, uninstalling, troubleshooting. |
| [Security](SECURITY.md) | What listens where, who can write, how the CA and keys are handled, what data is kept. |
| [Licensing](LICENSING.md) | Community, Pro and Business; activation, offline files, the license server. |
| [Architecture](ARCHITECTURE.md) | For contributors: the daemon, the module contract, the data path, the store. |
| [Releasing](RELEASING.md) | For maintainers: building, signing and publishing a release. |
| [Roadmap](ROADMAP.md) | What is planned and what is deliberately not. |

## Conventions used in this manual

- **FlowSight › Overview** means the page reached from the FlowSight
  section of the OPNsense menu; on other systems the same page is reached
  from the left-hand menu of the web interface at `http://127.0.0.1:8080`.
- *Settings › web* means the module's settings page under FlowSight ›
  Settings.
- `monospace` is a file path, a setting key, a command or an API route.
- **Pro** and **Business** mark features that need that license tier; see
  [Licensing](LICENSING.md). Everything unmarked is in Community.

## Versions

This manual describes FlowSight 0.9.x. The version an installation runs is
shown at the bottom of the left-hand menu and under FlowSight › Updates.
