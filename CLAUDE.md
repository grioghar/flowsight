# FlowSight: rules for working in this repository

These apply to every change, by anyone, human or agent.

## Every change ships with its documentation

A change is not done until the manual under `docs/` says what the product
now does. Concretely:

- A new or changed setting: `docs/CONFIGURATION.md` (regenerate the module
  tables from a running build or edit by hand) and, if it is user-facing,
  the relevant page in `docs/USER-GUIDE.md`.
- A new or changed API route: `docs/API.md`.
- New behaviour, a new page, a new module: `docs/USER-GUIDE.md` and, when
  the model changes, `docs/CONCEPTS.md` or `docs/POLICY.md`.
- Anything an operator would need at 3 a.m.: `docs/OPERATIONS.md`.
- Anything that changes what listens, what is stored or what leaves the
  box: `docs/SECURITY.md`.
- Tier gating: `docs/LICENSING.md` and the catalogue in
  `internal/licensing/tiers.go` stay in step.
- Release notes name every user-visible change.

The manual is shipped inside every package (Markdown, HTML and PDF built by
`packaging/docs/build-docs.sh`) and published with every release, so a
stale manual reaches customers.

## Product name

The product is **FlowSight** (capital F, capital S) in every user-visible
string, document and menu. Identifiers stay lower-case: the binary is
`flowsightd`, the package `os-flowsight`, the service `flowsight`, the
Go module `github.com/grioghar/flowsight`. Protocol constants never change
case: the write-gate header is `X-Requested-With: Flowsight`, the token
header `X-Flowsight-Token`, the GUI user header `X-Flowsight-User`.

## Engineering rules

- Native, compiled, no scripts in the data path. New function goes into
  the daemon as a module behind the module contract (`internal/core/module.go`).
- Nothing enforces before the operator turns enforcement on; every apply
  validates with the backend's own checker, keeps a backup, reverts on
  rejection.
- Interception must never fail closed: redirects exist only while the
  proxy answers.
- Shared pf tables live in the root ruleset; never define one inside an
  anchor (see `docs/INTERCEPTION.md`).
- Tier-gated features use `core.Needs`, `core.NeedsJob`, `Panel.Feature`,
  `ModuleInfo.Tier` or `License().Limit`; never ad-hoc checks.
- `go build ./... && go vet ./... && go test ./...` before every commit.
- Test on the PVE2 test bed (VM 9100) before the live gateway; deploy to
  the live gateway only what the test bed has run.

## Version numbers

The version increments only when the product owner approves it. Until then,
every fix or change is released as a revision of the current version:
`<current>r<YYYYMMDDHHMM>` (UTC), tagged the same way, for example
`0.9.8r202609211730`. See docs/RELEASING.md.

## Releasing

`docs/RELEASING.md` is the procedure. Both public keys
(`packaging/release/signing.pub`, `packaging/release/license.pub`) are
baked into release builds; the private keys are never committed.
