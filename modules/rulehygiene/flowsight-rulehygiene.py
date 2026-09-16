#!/usr/bin/env python3
"""Flowsight rulehygiene - firewall ruleset analysis.

Firewall rulesets decay. Rules get added for a reason nobody records, shadow
each other, stop matching anything, and quietly widen exposure. Commercial
tools solve this and are priced for enterprises.

The distinguishing idea here is that findings are grounded in **live pf
counters**, not in static rule text. Any tool can say "this rule looks broad".
Only counters can separate a rule that is genuinely dead from one that is
simply rarely hit, and that distinction is what makes the output trustworthy
enough to act on.

Read-only. It never modifies a ruleset - it tells you what to look at.
"""

import argparse
import json
import re
import subprocess
import sys
import time

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# A rule seen fewer times than this has not had a fair chance to match, so
# "never matched" says nothing useful about it yet.
MIN_EVALUATIONS_FOR_UNUSED = 1000

# Below this uptime, "unused since boot" is not evidence of anything.
MIN_UPTIME_SECONDS_FOR_UNUSED = 86400


class Rule:
    __slots__ = ("index", "text", "evaluations", "packets", "bytes", "states")

    def __init__(self, index, text):
        self.index = index
        self.text = text
        self.evaluations = 0
        self.packets = 0
        self.bytes = 0
        self.states = 0

    @property
    def action(self):
        head = self.text.split(None, 1)[0] if self.text else ""
        return head

    @property
    def is_pass(self):
        return self.text.startswith("pass")

    @property
    def interface(self):
        m = re.search(r"\son\s+(\S+)", self.text)
        return m.group(1) if m else ""

    def matches_any_source(self):
        return bool(re.search(r"\bfrom any\b", self.text))

    def matches_any_dest(self):
        return bool(re.search(r"\bto any\b", self.text))

    def restricts_port(self):
        """A port-qualified rule is not 'any to any' in the sense that matters."""
        return bool(re.search(r"\bport\s*(=|!=|<|>|:)", self.text))

    @property
    def direction(self):
        m = re.search(r"^\w+\s+(?:drop\s+)?(in|out)\b", self.text)
        return m.group(1) if m else ""


def get_uptime_seconds():
    try:
        out = subprocess.run(["/sbin/sysctl", "-n", "kern.boottime"],
                             capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"sec\s*=\s*(\d+)", out)
        if m:
            return int(time.time()) - int(m.group(1))
    except Exception:
        pass
    return 0


def parse_rules(text):
    """Parse `pfctl -vsr` output.

    Format is a rule line followed by indented bracketed counter lines.
    """
    rules = []
    current = None
    index = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not line.startswith(" ") and not stripped.startswith("["):
            current = Rule(index, stripped)
            rules.append(current)
            index += 1
            continue
        if current is None:
            continue
        m = re.search(r"Evaluations:\s*(\d+)\s+Packets:\s*(\d+)\s+"
                      r"Bytes:\s*(\d+)\s+States:\s*(\d+)", stripped)
        if m:
            current.evaluations = int(m.group(1))
            current.packets = int(m.group(2))
            current.bytes = int(m.group(3))
            current.states = int(m.group(4))
    return rules


# Patterns that look permissive but cannot be written any other way. Flagging
# these is how a hygiene tool teaches people to ignore it.
BENIGN_PATTERNS = [
    (re.compile(r"proto udp .*port = bootps .*port = bootpc"),
     "DHCP client",
     "A DHCP client cannot constrain the server address - it does not know it "
     "until it has a lease. Unbounded source is inherent to the protocol."),
    (re.compile(r"proto udp .*port = dhcpv6-server .*port = dhcpv6-client"),
     "DHCPv6 client",
     "Same as DHCP: the server address is unknown until configured."),
    (re.compile(r"proto ipv6-icmp"),
     "IPv6 ICMP",
     "IPv6 requires ICMP for neighbour discovery and path MTU; blocking it "
     "breaks connectivity rather than hardening it."),
]


def benign_reason(rule):
    for pattern, label, why in BENIGN_PATTERNS:
        if pattern.search(rule.text):
            return label, why
    return None, None


def finding(severity, kind, rule, summary, detail):
    return {
        "severity": severity,
        "kind": kind,
        "rule_index": rule.index,
        "rule": rule.text[:220],
        "evaluations": rule.evaluations,
        "packets": rule.packets,
        "summary": summary,
        "detail": detail,
    }


def analyse(rules, uptime):
    findings = []
    days = uptime / 86400.0

    for rule in rules:
        # scrub/match rules are infrastructure, not policy decisions
        if rule.text.startswith(("scrub", "anchor", "set ", "table")):
            continue

        # Never evaluated at all: pf did not even consider it, which means an
        # earlier quick rule always matched first. This is literal shadowing,
        # and it is the one finding counters can prove rather than infer.
        if rule.evaluations == 0 and uptime > MIN_UPTIME_SECONDS_FOR_UNUSED:
            findings.append(finding(
                "high", "shadowed", rule,
                "Never evaluated - an earlier rule always matches first",
                "pf has not evaluated this rule once in %.1f days of uptime. It "
                "cannot affect traffic while the rule above it keeps matching."
                % days))
            continue

        # Evaluated many times, matched nothing. Suggestive, not conclusive:
        # a deliberate catch-all safety net looks identical to dead weight.
        if (rule.packets == 0
                and rule.evaluations >= MIN_EVALUATIONS_FOR_UNUSED
                and uptime > MIN_UPTIME_SECONDS_FOR_UNUSED):
            findings.append(finding(
                "medium", "unused", rule,
                "Evaluated %s times, never matched" % f"{rule.evaluations:,}",
                "Considered often but matched no traffic in %.1f days. Could be "
                "dead weight, or an intentional catch-all that correctly never "
                "fires - confirm intent before removing." % days))

        # Breadth only matters on a pass rule; a broad block is usually the point.
        if not rule.is_pass:
            continue
        if not (rule.matches_any_source() and rule.matches_any_dest()):
            continue

        # An outbound any->any rule is the normal egress posture of almost every
        # gateway. Reporting it as high severity trains people to ignore the
        # tool, which costs more than the finding is worth.
        outbound = rule.direction == "out"
        external = rule.interface.startswith(("vtnet1", "wan"))

        label, why = benign_reason(rule)
        if label:
            findings.append(finding(
                "info", "expected", rule,
                "%s - broad by necessity" % label, why))
            continue

        if rule.restricts_port():
            # Port-qualified: the breadth is in the addresses only.
            if external and not outbound:
                findings.append(finding(
                    "medium", "permissive", rule,
                    "Any source to any destination on a specific port",
                    "Address range is unbounded on an external interface, though "
                    "the port is constrained. Narrow the source if this is not "
                    "meant to be reachable from the whole internet."))
            continue

        if outbound:
            findings.append(finding(
                "low", "permissive", rule,
                "Unrestricted outbound rule",
                "Permits all egress. This is the default posture for most "
                "gateways - listed for completeness, not as a defect."))
        elif external:
            findings.append(finding(
                "high", "permissive", rule,
                "Passes any source to any destination inbound on an external "
                "interface",
                "Permits all inbound traffic on a WAN-facing interface with no "
                "address or port constraint. Verify this is intentional."))
        else:
            findings.append(finding(
                "medium", "permissive", rule,
                "Passes any source to any destination",
                "Permits all traffic in its direction on an internal interface. "
                "Narrow the source or destination if the intent was specific."))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9),
                                 -f["evaluations"]))
    return findings


def risk_score(rules, findings):
    """A single number for tracking direction over time, not an absolute grade."""
    weights = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
    score = sum(weights.get(f["severity"], 0) for f in findings)
    policy_rules = [r for r in rules
                    if not r.text.startswith(("scrub", "anchor", "set ", "table"))]
    return {
        "score": score,
        "rules_analysed": len(policy_rules),
        "findings": len(findings),
        "per_rule": round(score / len(policy_rules), 2) if policy_rules else 0.0,
    }


def collect(pfctl="/sbin/pfctl"):
    out = subprocess.run([pfctl, "-vsr"], capture_output=True, text=True, timeout=30)
    if out.returncode != 0:
        raise RuntimeError("pfctl failed: %s" % out.stderr.strip()[:200])
    return parse_rules(out.stdout)


def main():
    ap = argparse.ArgumentParser(description="Flowsight firewall rule hygiene")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--pfctl", default="/sbin/pfctl")
    args = ap.parse_args()

    try:
        rules = collect(args.pfctl)
    except Exception as exc:
        sys.stderr.write("flowsight-rulehygiene: %s\n" % exc)
        return 2

    uptime = get_uptime_seconds()
    findings = analyse(rules, uptime)
    score = risk_score(rules, findings)

    if args.json:
        print(json.dumps({"uptime_seconds": uptime, "score": score,
                          "findings": findings}, indent=2))
        return 0

    print("  rules analysed : %d of %d loaded" % (score["rules_analysed"], len(rules)))
    print("  uptime         : %.1f days" % (uptime / 86400.0))
    print("  risk score     : %d  (%.2f per rule)" % (score["score"], score["per_rule"]))

    if uptime < MIN_UPTIME_SECONDS_FOR_UNUSED:
        print("\n  NOTE: uptime is under a day, so 'never matched' findings are "
              "suppressed - they would be meaningless this soon after boot.")

    if not findings:
        print("\n  No findings.")
        return 0

    print("\n  %d finding(s):" % len(findings))
    for f in findings:
        print("\n  [%s] %s  (rule %d)" % (f["severity"].upper(), f["summary"],
                                          f["rule_index"]))
        print("    %s" % f["rule"])
        print("    evaluations=%s packets=%s" % (f"{f['evaluations']:,}",
                                                 f"{f['packets']:,}"))
        print("    %s" % f["detail"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
