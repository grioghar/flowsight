"""Insert zone-isolation rules into OPNsense's firewall model.

Ordering is the whole game. Every rule OPNsense emits is "quick", so the first
match decides, and the automatic "Default allow LAN to any" rule sits at
sequence 1. These go in ahead of it. If that ordering were ever wrong the rules
simply never match - traffic still passes - which is the failure mode to prefer
while working on a live network.
"""
import re, shutil, sys, time, uuid
import xml.etree.ElementTree as ET

CONF = "/conf/config.xml"
MARK = "flowsight-zone"

ZONES = {"personal": "192.168.0.0/24", "infra": "192.168.1.0/24",
         "iot": "192.168.2.0/24", "media": "192.168.3.0/24",
         "quarantine": "192.168.9.0/24"}

# source zone -> zones it must not reach. Derived from reach_zones, with the
# pairs that would break this network deliberately absent: iot and media both
# keep access to infra, because DNS lives at 192.168.1.53 and Plex at
# 192.168.1.105, and cutting those segments nothing - it just breaks them.
DENY = [
    ("iot", "personal", "appliances have no business reaching people's devices"),
    ("iot", "media", "appliances have no business reaching consoles"),
    ("media", "personal", "consoles have no business reaching people's devices"),
    ("media", "iot", "consoles have no business reaching appliances"),
    ("personal", "quarantine", "nothing should initiate to an unidentified device"),
    ("iot", "quarantine", "nothing should initiate to an unidentified device"),
    ("media", "quarantine", "nothing should initiate to an unidentified device"),
]

TEMPLATE = """              <rule uuid="{uuid}">
                <enabled>1</enabled>
                <statetype>keep</statetype>
                <state-policy />
                <sequence>{seq}</sequence>
                <action>{action}</action>
                <quick>1</quick>
                <interfacenot>0</interfacenot>
                <interface>lan</interface>
                <received-on-not>0</received-on-not>
                <received-on />
                <direction>in</direction>
                <ipprotocol>inet</ipprotocol>
                <protocol>{proto}</protocol>
                <icmptype />
                <icmp6type />
                <source_net>{src}</source_net>
                <source_not>0</source_not>
                <source_port />
                <destination_net>{dst}</destination_net>
                <destination_not>{dstnot}</destination_not>
                <destination_port>{dport}</destination_port>
                <divert-to />
                <gateway />
                <replyto />
                <disablereplyto>0</disablereplyto>
                <log>{log}</log>
                <allowopts>0</allowopts>
                <nosync>0</nosync>
                <nopfsync>0</nopfsync>
                <statetimeout />
                <udp-first /><udp-multiple /><udp-single />
                <max-src-nodes /><max-src-states /><max-src-conn /><max />
                <max-src-conn-rate /><max-src-conn-rates />
                <max-pkt-rate-number /><max-pkt-rate-seconds />
                <overload /><adaptivestart /><adaptiveend />
                <prio /><set-prio /><set-prio-low />
                <tag /><tagged />
                <tcpflags1 /><tcpflags2 /><tcpflags_any>0</tcpflags_any>
                <categories /><sched /><tos /><shaper1 /><shaper2 />
                <description>{descr}</description>
              </rule>
"""

def rule(seq, action, src, dst, descr, proto="any", dport="", dstnot="0", log="1"):
    return TEMPLATE.format(uuid=uuid.uuid4(), seq=seq, action=action, proto=proto,
                           src=src, dst=dst, dstnot=dstnot, dport=dport,
                           log=log, descr=descr)

def main():
    shutil.copy2(CONF, "%s.bak-fwrules-%s" % (CONF, time.strftime("%Y%m%d%H%M%S")))
    x = open(CONF).read()
    if MARK in x:
        print("  rules already present - remove them first")
        return 1

    out = []
    # Blocks only. An earlier version also emitted "pass <zone> to DNS port 53"
    # with protocol any, which pf rejects outright - "port only applies to
    # tcp/udp/sctp" - and a single invalid rule makes pfctl refuse the whole
    # file, so nothing loaded at all while configctl still reported OK.
    #
    # They were redundant regardless: iot and media reach infra under
    # reach_zones, and the resolver lives there. A DNS exception only becomes
    # necessary alongside a rule blocking quarantine's egress, and it must then
    # carry protocol tcp/udp rather than any.
    #
    # All at sequence 0: the automatic allow is at sequence 1, and anything at
    # or above it is emitted afterwards where, being quick, it never matches.
    seq = 0
    for src, dst, why in DENY:
        out.append(rule(seq, "block", ZONES[src], ZONES[dst],
                        "%s: %s to %s - %s" % (MARK, src, dst, why)))

    block = "".join(out)
    # insert at the top of the model's rule list so these are emitted first
    m = re.search(r"(<Filter version[^>]*>.*?<rules>)", x, re.S)
    if not m:
        print("  could not find the Filter model rule list")
        return 1
    x = x[:m.end(1)] + "\n" + block + x[m.end(1):]
    ET.fromstring(x)
    open(CONF, "w").write(x)
    print("  inserted %d block rules" % len(out))
    return 0

sys.exit(main())
