# flowsight-policy

Compiles one declarative policy into whatever each installed backend
understands, then reconciles it.

```bash
flowsight-policy status          # what is declared, and who could enforce it
flowsight-policy plan            # what would change  (default, never writes)
flowsight-policy apply           # enforce it
```

## Policy targets capabilities, not backends

A policy says *"deny these domains for the kids group"*. Which module enforces
that is resolved at compile time from the capabilities each provider declares.
Swapping Unbound for AdGuard Home should not require touching a single policy.

If no installed provider offers a required capability, the compiler **refuses**
rather than emitting a policy that enforces nothing.

## Why Unbound views, not local-zone

`local-zone` is global — it cannot express "deny this for the kids only". Views
plus `access-control-view` bind a ruleset to specific client addresses, which is
what the policy model actually means:

```
view:
    name: "flowsight-no-adult-content-for-kids"
    view-first: yes
    local-zone: "example.invalid." always_nxdomain

server:
    access-control-view: 192.168.1.50/32 flowsight-no-adult-content-for-kids
```

`view-first: yes` means anything the view does not deny still falls through to
normal resolution, so a view only ever subtracts.

## Failing loudly on purpose

The compiler rejects, rather than quietly accepting:

- `deny.categories` — needs a category feed that is not wired up yet
- unknown groups, duplicate policy names, policies that deny nothing
- malformed domains, and IPs whose octets are out of range (`999.1.1.1` matches
  a naive dotted-quad pattern and would otherwise reach the backend)
- a required capability no installed provider offers

A policy that compiles to nothing is worse than one that refuses to compile,
because it looks like protection.

## Apply safety

`apply` backs up the existing artifact, writes atomically, then runs
`unbound-checkconf` **before** reloading. If validation fails the previous file
is restored and nothing is reloaded — a bad include would take DNS down for the
entire network.

## Known integration caveat

The generated file lives at `/var/unbound/etc/flowsight-policy.conf`, picked up
by Unbound's existing `include: /var/unbound/etc/*.conf`. OPNsense regenerates
its *own* files in that directory on reconfigure; this one is not among them,
but verify it survives after an Unbound reconfigure.
