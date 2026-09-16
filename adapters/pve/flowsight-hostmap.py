#!/usr/bin/env python3
"""Export a MAC -> guest identity map from Proxmox.

Every virtual NIC shares the Proxmox OUI, so MAC-vendor lookup reports
"Proxmox Server Solutions GmbH" for every VM and container and tells you
nothing useful. Proxmox knows exactly which MAC belongs to which guest and what
it is called; this publishes that so Flowsight can name them.

Identity is read from the cluster filesystem rather than by shelling out. An
earlier version ran "qm config" and "qm status" per guest, which on a host with
56 guests meant 112 Perl interpreters, each wanting fresh memory. On a busy
host that is a burst big enough to matter, and it once landed while the machine
was already thrashing on a full swap partition. The same facts are in
/etc/pve/{qemu-server,lxc}/*.conf, which are ordinary small files, so the whole
map now costs a directory listing and two cheap status calls.

Run on the Proxmox host. Output is a flat JSON object keyed by uppercase MAC.
"""

import json
import os
import re
import subprocess
import sys

MAC = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}")
SKIP_IF = re.compile(r"^(lo|tap|veth|fwbr|fwln|fwpr|nic|dummy)")
CONF_DIRS = (("/etc/pve/qemu-server", "vm", "name"),
             ("/etc/pve/lxc", "ct", "hostname"))


def run(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True,
                              timeout=30).stdout
    except Exception:
        return ""


def statuses(list_cmd):
    """vmid -> running/stopped, in a single call for all guests."""
    out = {}
    for line in run(list_cmd, "list").splitlines()[1:]:
        parts = line.split()
        if parts and parts[0].isdigit():
            # qm prints VMID NAME STATUS ...; pct prints VMID STATUS LOCK NAME
            out[parts[0]] = parts[2] if list_cmd == "qm" and len(parts) > 2 \
                else (parts[1] if len(parts) > 1 else "unknown")
    return out


def guests():
    out = {}
    for path, kind, name_key in CONF_DIRS:
        try:
            names = os.listdir(path)
        except OSError:
            continue
        state = statuses("qm" if kind == "vm" else "pct")
        for fn in names:
            if not fn.endswith(".conf"):
                continue
            vmid = fn[:-5]
            if not vmid.isdigit():
                continue
            try:
                with open(os.path.join(path, fn)) as fh:
                    cfg = fh.read()
            except OSError:
                continue
            name = ""
            for line in cfg.splitlines():
                # A snapshot section repeats these keys; the live config is the
                # part before the first [snapshot] header.
                if line.startswith("["):
                    break
                if line.startswith(name_key + ":"):
                    name = line.split(":", 1)[1].strip()
                    break
            for line in cfg.splitlines():
                if line.startswith("["):
                    break
                if not re.match(r"^net\d+:", line):
                    continue
                m = MAC.search(line)
                if not m:
                    continue
                out[m.group(0).upper()] = {
                    "kind": kind,
                    "id": vmid,
                    "name": name or "%s-%s" % (kind, vmid),
                    "status": state.get(vmid, "unknown"),
                }
    return out


def node_nics():
    """The hypervisor's own NICs.

    Guests get named by their config files, but the node itself has none - so
    without this the Proxmox host shows up in Flowsight as a bare IP with a
    MAC-vendor guess. Bridges and physical uplinks are the addresses the host
    actually speaks from; tap/veth/fwbr are per-guest plumbing and mostly carry
    the all-ff placeholder, so they are skipped.
    """
    name = run("hostname").strip() or "proxmox"
    out = {}
    for line in run("ip", "-o", "link").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        iface = parts[1].rstrip(":").split("@")[0]
        if SKIP_IF.match(iface):
            continue
        m = MAC.search(line)
        if not m:
            continue
        mac = m.group(0).upper()
        if mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            continue
        out[mac] = {"kind": "node", "id": name, "name": name,
                    "status": "running", "iface": iface}
    return out


def main():
    dest = sys.argv[1] if len(sys.argv) > 1 else "/tmp/flowsight-hostmap.json"
    table = {}
    table.update(node_nics())
    table.update(guests())
    tmp = dest + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(table, fh, indent=1, sort_keys=True)
    os.replace(tmp, dest)
    print("wrote %d entries to %s" % (len(table), dest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
