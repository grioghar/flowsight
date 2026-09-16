#!/usr/bin/env python3
"""Flowsight policy compiler.

Turns one declarative policy into whatever each installed backend actually
understands, then reconciles it.

The design rule is that policy names **capabilities, never backends**. A policy
says "deny these domains for the kids group"; which module enforces that is
resolved at compile time from the capabilities each provider declares. Swapping
Unbound for AdGuard Home must not require touching a single policy.

Safety: `plan` is the default and never writes. `apply` is explicit, takes a
backup, and refuses to act on a plan it cannot fully compile - a partially
applied firewall policy is worse than none.
"""

import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import sys
import time

try:
    import yaml
except ImportError:
    yaml = None

DEFAULT_POLICY_PATH = "/usr/local/etc/flowsight/policy.yaml"


def _platform_defaults():
    """Unbound's drop-in directory and control paths differ per platform."""
    if os.path.exists("/usr/local/sbin/opnsense-version") or \
            os.uname()[0] == "FreeBSD":
        return {
            "include_path": "/var/unbound/etc/flowsight-policy.conf",
            "control": "/usr/local/sbin/unbound-control",
            "checkconf": "/usr/local/sbin/unbound-checkconf",
            "config": "/var/unbound/unbound.conf",
        }
    return {
        "include_path": "/etc/unbound/unbound.conf.d/flowsight-policy.conf",
        "control": "/usr/sbin/unbound-control",
        "checkconf": "/usr/sbin/unbound-checkconf",
        "config": "/etc/unbound/unbound.conf",
    }


_P = _platform_defaults()

# Capabilities a policy clause needs, mirroring docs/SCHEMA.md.
CAP_DNS_BLOCK = "dns.block"

CATEGORY_CACHE = "/usr/local/share/flowsight/categories"

# A per-view local-zone of this size is already a lot of resolver state. Some
# feeds are millions of domains: compiling those into a view would degrade DNS
# for the whole network, so the compiler refuses and says what to do instead.
MAX_DOMAINS_PER_POLICY = 200000

_IPV4 = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?$")
_DOMAIN = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


class PolicyError(Exception):
    """A policy that cannot be compiled. Always fatal - never partially applied."""


# --------------------------------------------------------------------------
# Model
# --------------------------------------------------------------------------

def _resolve_categories(categories, policy_name):
    """Expand category names to domains from the on-disk feed cache.

    Reads the cache only - a policy compile must not depend on the network
    being reachable, and a feed fetch failing mid-compile would silently
    shrink enforcement.
    """
    domains, counts = [], {}
    for cat in categories:
        path = os.path.join(CATEGORY_CACHE, "%s.list" % cat)
        if not os.path.isfile(path):
            raise PolicyError(
                "policy %r uses category %r, which has no cached feed. Run "
                "'flowsight-categories update %s' first - refusing rather than "
                "compiling a policy that would enforce nothing."
                % (policy_name, cat, cat))
        with open(path) as fh:
            got = [ln.strip().lower() for ln in fh if ln.strip()]
        if not got:
            raise PolicyError(
                "policy %r uses category %r but its cached feed is empty"
                % (policy_name, cat))
        counts[cat] = len(got)
        domains.extend(got)
    return domains, counts


class Policy:
    def __init__(self, name, members, deny_domains, enabled=True, comment="",
                 categories=None):
        self.name = name
        self.members = members          # list of client IPs/CIDRs
        self.deny_domains = deny_domains
        self.enabled = enabled
        self.comment = comment
        self.categories = categories or {}

    def required_capabilities(self):
        caps = set()
        if self.deny_domains:
            caps.add(CAP_DNS_BLOCK)
        return caps


def _validate_member(value, where):
    """Validate an IPv4 address or CIDR.

    Octet ranges are checked, not just digit counts: 999.1.1.1 matches a naive
    dotted-quad pattern and would sail through to the generated config, where
    it becomes the backend's problem instead of being rejected at the source.
    """
    m = _IPV4.match(value.strip())
    if not m:
        raise PolicyError("%s: %r is not an IPv4 address or CIDR" % (where, value))

    octets = m.group(1).split(".")
    if any(not o.isdigit() or int(o) > 255 or (len(o) > 1 and o[0] == "0")
           for o in octets):
        raise PolicyError("%s: %r has an octet outside 0-255" % (where, value))

    prefix = m.group(2)
    if prefix is None:
        return m.group(1) + "/32"
    if not prefix.isdigit() or int(prefix) > 32:
        raise PolicyError("%s: %r has an invalid prefix length" % (where, value))
    return "%s/%d" % (m.group(1), int(prefix))


def _validate_domain(value, where):
    value = value.strip().lower().rstrip(".")
    if not _DOMAIN.match(value):
        raise PolicyError("%s: %r is not a valid domain" % (where, value))
    return value


def load_policies(path):
    if yaml is None:
        raise PolicyError("PyYAML is required to read policy files")
    if not os.path.isfile(path):
        raise PolicyError("policy file not found: %s" % path)

    with open(path) as fh:
        doc = yaml.safe_load(fh) or {}

    if doc.get("version") != 1:
        raise PolicyError("unsupported policy version %r (expected 1)"
                          % doc.get("version"))

    groups = {}
    for gname, gdef in (doc.get("groups") or {}).items():
        members = (gdef or {}).get("members") or []
        groups[gname] = [_validate_member(str(m), "group %s" % gname)
                         for m in members]

    policies = []
    seen = set()
    for entry in (doc.get("policies") or []):
        name = entry.get("name")
        if not name:
            raise PolicyError("a policy is missing 'name'")
        if name in seen:
            raise PolicyError("duplicate policy name %r" % name)
        seen.add(name)

        match = entry.get("match") or {}
        if "group" in match:
            gname = match["group"]
            if gname not in groups:
                raise PolicyError("policy %r targets unknown group %r" % (name, gname))
            members = groups[gname]
        elif "members" in match:
            members = [_validate_member(str(m), "policy %s" % name)
                       for m in match["members"]]
        else:
            raise PolicyError("policy %r has no 'match.group' or 'match.members'"
                              % name)
        if not members:
            raise PolicyError("policy %r matches no members" % name)

        deny = entry.get("deny") or {}
        domains = [_validate_domain(str(d), "policy %s" % name)
                   for d in (deny.get("domains") or [])]

        categories = [str(c).strip().lower() for c in (deny.get("categories") or [])]
        cat_domains, cat_counts = _resolve_categories(categories, name)
        domains = sorted(set(domains) | set(cat_domains))

        if not domains:
            raise PolicyError("policy %r denies nothing" % name)

        if len(domains) > MAX_DOMAINS_PER_POLICY:
            raise PolicyError(
                "policy %r resolves to %s domains, over the %s limit. A view "
                "that large degrades DNS for the whole network. Use a smaller "
                "category, or block it resolver-wide with the DNSBL instead of "
                "per-group." % (name, f"{len(domains):,}",
                                f"{MAX_DOMAINS_PER_POLICY:,}"))

        policies.append(Policy(name=name, members=members, deny_domains=domains,
                               enabled=bool(entry.get("enabled", True)),
                               comment=str(entry.get("comment", "")),
                               categories=cat_counts))
    return policies


# --------------------------------------------------------------------------
# Providers
# --------------------------------------------------------------------------

class Provider:
    """A backend that can enforce some capability."""

    name = "provider"
    capabilities = ()

    def compile(self, policies):
        """Return the desired artifact text for these policies."""
        raise NotImplementedError

    def current(self):
        """Return the artifact text currently in place."""
        raise NotImplementedError

    def apply(self, text):
        raise NotImplementedError


class UnboundViewProvider(Provider):
    """Per-group DNS blocking via Unbound views.

    local-zone alone is global, which cannot express "deny this for the kids
    only". Unbound views plus access-control-view bind a ruleset to specific
    client addresses, which is what the policy model actually means.

    Writes one file into Unbound's include directory. OPNsense regenerates its
    own files there on reconfigure; this file is not one of them, but verify
    after an Unbound reconfigure that it survived.
    """

    name = "unbound"
    capabilities = (CAP_DNS_BLOCK,)

    HEADER = ("# Generated by flowsight-policy. Do not edit.\n"
              "# Source of truth is the policy file; edits here are overwritten.\n")

    def __init__(self, cfg=None):
        cfg = cfg or {}
        self.path = cfg.get("include_path", _P["include_path"])
        self.control = cfg.get("control", _P["control"])
        self.checkconf = cfg.get("checkconf", _P["checkconf"])
        self.config = cfg.get("config", _P["config"])

    def compile(self, policies):
        lines = [self.HEADER]
        acls = []
        for pol in policies:
            if not pol.enabled or not pol.deny_domains:
                continue
            view = "flowsight-%s" % re.sub(r"[^a-z0-9-]", "-", pol.name.lower())
            lines.append("view:")
            lines.append('    name: "%s"' % view)
            # view-first lets global config still answer anything not denied here
            lines.append("    view-first: yes")
            if pol.comment:
                lines.append("    # %s" % pol.comment)
            for domain in sorted(set(pol.deny_domains)):
                lines.append('    local-zone: "%s." always_nxdomain' % domain)
            lines.append("")
            for member in pol.members:
                acls.append('    access-control-view: %s %s' % (member, view))

        if acls:
            lines.append("server:")
            lines.extend(sorted(set(acls)))
            lines.append("")
        return "\n".join(lines)

    def current(self):
        try:
            with open(self.path) as fh:
                return fh.read()
        except (OSError, IOError):
            return ""

    def apply(self, text):
        backup = None
        if os.path.exists(self.path):
            backup = "%s.bak-%s" % (self.path, time.strftime("%Y%m%d%H%M%S"))
            shutil.copy2(self.path, backup)

        tmp = self.path + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(text)
        os.chmod(tmp, 0o640)
        os.rename(tmp, self.path)

        # Validate before reloading: a bad include takes DNS down for everyone,
        # and on a gateway that is the whole network.
        check = subprocess.run([self.checkconf, self.config],
                               capture_output=True, text=True)
        if check.returncode != 0:
            if backup:
                shutil.copy2(backup, self.path)
            else:
                os.unlink(self.path)
            raise PolicyError("unbound-checkconf rejected the generated config, "
                              "reverted: %s" % check.stderr.strip()[:300])

        reload_out = subprocess.run([self.control, "-c", self.config, "reload"],
                                    capture_output=True, text=True)
        if reload_out.returncode != 0:
            raise PolicyError("unbound reload failed: %s"
                              % reload_out.stderr.strip()[:200])
        return backup


PROVIDERS = {"unbound": UnboundViewProvider}


# --------------------------------------------------------------------------
# Compile / plan / apply
# --------------------------------------------------------------------------

def resolve(policies, providers):
    """Map each required capability to a provider that declares it."""
    available = {}
    for prov in providers:
        for cap in prov.capabilities:
            available.setdefault(cap, prov)

    needed = set()
    for pol in policies:
        if pol.enabled:
            needed |= pol.required_capabilities()

    missing = sorted(needed - set(available))
    if missing:
        raise PolicyError(
            "no installed provider offers: %s. Policy would silently enforce "
            "nothing, so refusing to continue." % ", ".join(missing))
    return {cap: available[cap] for cap in needed}


def build_plan(policies, providers):
    resolve(policies, providers)
    plan = []
    for prov in providers:
        desired = prov.compile(policies)
        current = prov.current()
        if desired.strip() == current.strip():
            plan.append((prov, desired, None))
            continue
        diff = list(difflib.unified_diff(
            current.splitlines(), desired.splitlines(),
            fromfile="%s (current)" % prov.name,
            tofile="%s (desired)" % prov.name, lineterm=""))
        plan.append((prov, desired, diff))
    return plan


def cmd_plan(args, policies, providers):
    plan = build_plan(policies, providers)
    changed = False
    for prov, _desired, diff in plan:
        if diff is None:
            print("  %s: up to date" % prov.name)
            continue
        changed = True
        print("  %s: %d line(s) would change" % (prov.name, len(diff)))
        for line in diff:
            print("    " + line)
    if not changed:
        print("\nNothing to do.")
    else:
        print("\nThis was a plan. Nothing has been changed. "
              "Re-run with 'apply' to enforce it.")
    return 0


def cmd_apply(args, policies, providers):
    plan = build_plan(policies, providers)
    if all(diff is None for _p, _d, diff in plan):
        print("  already up to date, nothing applied")
        return 0
    for prov, desired, diff in plan:
        if diff is None:
            continue
        backup = prov.apply(desired)
        print("  %s: applied%s" % (prov.name,
                                   (" (backup %s)" % backup) if backup else ""))
    return 0


def cmd_status(args, policies, providers):
    print("  policies: %d (%d enabled)"
          % (len(policies), sum(1 for p in policies if p.enabled)))
    for pol in policies:
        cats = (" categories=%s" % ",".join(
            "%s:%s" % (k, f"{v:,}") for k, v in sorted(pol.categories.items()))
        ) if pol.categories else ""
        print("   - %-28s %-8s members=%d deny_domains=%d%s"
              % (pol.name, "enabled" if pol.enabled else "disabled",
                 len(pol.members), len(pol.deny_domains), cats))
    print("  providers:")
    for prov in providers:
        print("   - %-10s capabilities=%s" % (prov.name, ",".join(prov.capabilities)))
    return 0


def main():
    ap = argparse.ArgumentParser(description="Flowsight policy compiler")
    ap.add_argument("command", choices=["plan", "apply", "status"], nargs="?",
                    default="plan")
    ap.add_argument("-f", "--file", default=DEFAULT_POLICY_PATH)
    args = ap.parse_args()

    try:
        policies = load_policies(args.file)
        providers = [cls() for cls in PROVIDERS.values()]
        return {"plan": cmd_plan, "apply": cmd_apply,
                "status": cmd_status}[args.command](args, policies, providers)
    except PolicyError as exc:
        sys.stderr.write("flowsight-policy: %s\n" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
