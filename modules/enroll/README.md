# Enrollment

Identify a device when it asks for an address, then place it in the zone that
matches what it is.

A flat network gives a smart plug the same reach as a laptop. Enrollment watches
DHCP, fingerprints each device from the signals its own request carries, and
assigns it an address inside a zone whose subnet, DNS and firewall policy suit
that class of device. Anything it cannot identify goes to the captive zone,
where HTTP is answered by an identification page instead of the internet.

## Parts

| Component | Role |
|---|---|
| `flowsight-enroll-hook` | dnsmasq `--dhcp-script`. Appends one JSON line and exits. |
| `flowsight-enroll.py` | Classifies, keeps the registry, renders dnsmasq and pf config. |
| `flowsight-captive.py` | The unauthenticated identification page for quarantined devices. |
| `zones.example.json` | Zone definitions: subnet, gateway, DHCP range, DNS, reachability. |
| `rules.example.json` | Ordered classification rules. |

The hook runs inside dnsmasq's request path — dnsmasq waits for it before the
client gets its reply — so it records and exits, and nothing interprets anything
there. The vendor class (DHCP option 60) and parameter request list (option 55)
are the two signals that actually identify a device, and they exist **only** in
that hook's environment: they are not in the lease file and cannot be recovered
afterwards.

## Two safety properties

**Monitor mode is the default.** It classifies and reports but writes no
enforcement, because the cost of a wrong rule is a device that silently loses
the network. `apply` refuses to write until `mode` is `enforce`.

**Devices present when enrollment is first enabled are pinned where they are.**
Only devices first seen afterwards are placed. Migrating an existing device is an
explicit action, never a side effect of adding a rule.

Monitor mode is not decoration. On its first real run it exposed five defects
that would each have removed working devices from the network: IPv6 lease lines
overwriting IPv4 addresses, DHCPv6 DUIDs parsed as MAC addresses, laptops and
phones quarantined because they rotate a private MAC and the rules demanded an
OUI vendor, every hypervisor NIC falling through, and multicast groups enrolled
as if they were hosts.

## Writing rules

Keys inside one rule are ANDed; a list of values inside one key is ORed; an
`any` block is ORed. First rule that matches wins, so order is policy.

```json
{"id": "tuya-iot", "zone": "iot", "confidence": "high",
 "why": "Tuya/SmartLife appliance - plugs, bulbs and sensors.",
 "when": {"any": [{"vendor": ["Tuya"]}, {"hostname_re": "^tuya-"}]}}
```

Conditions: `vendor` (substring, case-insensitive), `guest_kind`, `mac_prefix`,
any field plus `_re` for a regex (`hostname_re`, `vendor_class_re`,
`fingerprint_re`), or an exact field match.

Rules are rejected at save time if a regex does not compile — a bad rule file
does not fail loudly at runtime, it makes the engine fall back to its empty
default, which would quarantine the whole network on the next apply.

**Vendor is often empty, by design.** Current iOS, Android and Windows rotate a
private MAC per network, so the OUI identifies nothing. Hostname and DHCP
fingerprint rules are what carry those devices; the registry flags them with
`randomized_mac` so an empty vendor column reads as expected rather than broken.

## Self-identification is a claim, not proof

A device choosing its own class is an assertion by that device. Every
declaration is recorded to `enroll-claims.jsonl` whether or not it is applied,
which is what makes a dishonest claim reviewable. Set `captive_policy` to
`approve` to queue declarations for a human instead of applying them, and
`"self_service": false` on a zone to keep it from being offered at all.

The captive service is deliberately a separate process from the Flowsight UI: a
quarantined device cannot authenticate to the OPNsense GUI that fronts the UI,
so its page must be reachable without credentials. Keeping it separate means the
unauthenticated surface is exactly that one file. It serves only clients inside
the captive subnet, and a device can only ever set its own zone — the MAC is
looked up from the source address, never taken from the request.

## Segmentation on a flat network

Multiple subnets on one physical segment give each class its own addressing, DNS
and firewall policy, and that is what this module configures. It is **policy
segmentation, not isolation**: a device can still statically assign itself into
another subnet, and same-segment neighbours can reach each other at layer 2.

True isolation needs VLANs, a managed switch and VLAN-capable APs. The zone
model maps onto VLANs unchanged when that hardware exists — only the interface
each `dhcp-range` binds to changes.

## Install

The dnsmasq drop-in goes in `/usr/local/etc/dnsmasq.conf.d/`, which OPNsense's
generated `dnsmasq.conf` already includes via `conf-dir`. Anything written into
`dnsmasq.conf` itself is discarded on the next reconfigure.

```
dhcp-script=/usr/local/sbin/flowsight-enroll-hook
```
