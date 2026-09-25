# Add a Switch or Another Router as a Flow Source

FlowSight's netflow module extends visibility beyond the gateway to the entire LAN by accepting flow exports from any device that supports NetFlow, IPFIX, or sFlow. This guide shows how to connect a switch, router, or other exporter.

## What You'll See

When a flow source is connected, you gain visibility of:
- **East-west traffic**: Traffic between two local devices (e.g., PC to NAS, server to workstation).
- **Switch-seen traffic**: All traffic forwarded through the switch, not just traffic that passes through the gateway.
- **Per-interface throughput**: Metrics from each switch port or router interface.

You will **not** see:
- Application identification from flow records alone (NetFlow v5 doesn't export it; v9 and IPFIX support it only if the exporter provides it).
- TLS SNI or JA3 fingerprints (flow records don't contain this; it requires inline inspection).
- Per-packet payload details (flows are summaries by 5-tuple).

## Prerequisites

1. **NetFlow module enabled**: Go to Settings → Network Flow Collection and turn on "Collect flows (open the listeners)"s".
2. **Network device**: A router, switch, or firewall that exports NetFlow v5, v9, IPFIX, or sFlow v5.
3. **FlowSight reachable**: The exporting device must be able to reach FlowSight on UDP port 2055 (NetFlow/IPFIX) or 6343 (sFlow), or the port you configured.

## Exporter Setup

### OPNsense / pfSense Router

1. Log in to OPNsense web interface.
2. Go to **Reporting → NetFlow**.
3. Turn on **Collect flows (open the listeners)** if it is not on already.
4. Under **NetFlow Collector** → **Add collector**:
   - **Host**: FlowSight's IP address (e.g., `192.168.1.1`)
   - **Port**: `2055` (default NetFlow port)
   - **Protocol**: NetFlow v5 or v9 (both work; v5 is simpler; v9 allows optional fields)
   - **Interval**: 30 seconds (default; shorter intervals = more frequent updates but higher CPU)
5. Apply.

The router will begin exporting flows immediately.

### Linux Router (softflowd)

On a Linux router, install and run `softflowd` to export flows:

```bash
apt-get install softflowd  # Debian/Ubuntu
```

Configure `/etc/softflowd/default` or start with command-line flags:

```bash
softflowd -i eth0 -n 192.168.1.1:2055 -v 5 -t tcp=3600
```

- `-i eth0`: Interface to sample
- `-n 192.168.1.1:2055`: NetFlow collector (FlowSight) and port
- `-v 5`: NetFlow v5 (use `9` for v9, `10` for IPFIX)
- `-t tcp=3600`: TCP timeout in seconds

Or run as a service:

```bash
systemctl enable softflowd
systemctl start softflowd
```

### Linux Router (pmacct)

`pmacct` is more flexible and supports sFlow and IPFIX as well:

```bash
apt-get install pmacct
```

Create `/etc/pmacct/pmacctd.conf`:

```
interface: eth0
aggregate: dst_host, dst_port, proto
nfacctd_port: 2055
nfacctd_version: 5
nfacctd_time_new: true
nfacctd_stitching: true
```

Start:

```bash
systemctl enable pmacctd
systemctl start pmacctd
```

### Switch (Arista, Juniper, Cisco)

Consult your switch's documentation. Common steps:

**Cisco (IOS-XE)**:
```
flow exporter netflow_exp
  destination 192.168.1.1 2055
  source Vlan1
  transport udp
flow monitor netflow_mon
  exporter netflow_exp
  record netflow ipv4 original-input
interface Eth0/0
  ip flow monitor netflow_mon input
  ip flow monitor netflow_mon output
```

**Juniper (Junos)**:
```
set services flow-monitoring version-ipfix template ipv4-template
set services flow-monitoring collector 192.168.1.1 port 2055 transport udp
set interfaces ge-0/0/0 unit 0 flow-monitoring version-ipfix-template ipv4-template
```

**Arista (EOS)**:
```
flow monitor ipfix-mon
  exporter ipfix 192.168.1.1 2055
  record netflow-ipv4
interface Ethernet1
  monitor flow ipfix-mon input
  monitor flow ipfix-mon output
```

### Switch (sFlow)

sFlow is often preferred for switches because it's lighter-weight and doesn't require templates:

**Typical switch configuration**:
```
sflow destination 192.168.1.1 6343
sflow sampling-rate 1024
sflow collector-ip 192.168.1.1
```

(Syntax varies by vendor.)

## Verifying the Connection

Once the exporter is configured, check FlowSight:

1. Go to **Monitor → Flow sources** (or Settings if the panel isn't visible).
2. You should see the exporter's address, protocol, record count, and last-seen timestamp.
3. Go to **Monitor → Sessions** and filter by **Source** to see flows from the new exporter.

If nothing appears:
- Check that the exporter is running and has traffic.
- Confirm FlowSight's IP and port are correct on the exporter.
- Check firewall rules: the exporter must be able to reach FlowSight on the UDP port.
- For NetFlow v9/IPFIX, the exporter must send templates before data records. If templates time out, data will be dropped. Configure the exporter to send templates every 5–10 seconds.

## Filtering by Source in the UI

The **Sessions** page supports filtering by source:
- **ntopng**: Traffic directly observed by the gateway's interface.
- **netflow5:192.168.1.50**: NetFlow v5 from a device at that IP.
- **ipfix:192.168.1.50**: IPFIX from that device.
- **sflow5:192.168.1.50**: sFlow v5 from that device.

A single flow may be reported by multiple sources (e.g., the gateway and a switch both see it). FlowSight de-duplicates reasonably but does not merge—two witnesses remain two rows. This visibility is valuable: if the switch reports a flow but the gateway does not, you know it traversed a path outside the gateway's purview.

## Bandwidth Limits

Be aware of the bandwidth impact:
- Each flow record is typically 40–80 bytes.
- A busy switch might export 1000–5000 flows/second.
- NetFlow v5 typically uses 1–2 Mbps per 100,000 flows/second.
- Sampling reduces this: a 1-in-1000 sample is 1/1000 the bandwidth.

For high-traffic switches, configure sampling on the exporter (e.g., 1 in 1000) or increase the interval between exports.

## Sampling Rate Handling

If an exporter reports a sampling rate (all sFlow packets do; NetFlow v5 and IPFIX optionally), FlowSight applies it to bytes and packets automatically so totals reflect actual traffic, not samples. If your exporter does not report a rate but applies one, use the `sampling_override` setting in the module configuration to correct for it.

## Troubleshooting

**No flows appear**:
- Ensure the exporter is enabled and has traffic.
- Verify the IP and port are correct.
- Check firewall rules between exporter and FlowSight.

**Templates not received (NetFlow v9 / IPFIX)**:
- Some exporters send templates infrequently (minutes apart). Force a retransmission on the exporter.
- Restart FlowSight's netflow module (Settings → Network Flow Collection → toggle off then on).

**Sampling looks wrong**:
- If bytes don't match what you expect, the sampling rate may not be set correctly. Use the `sampling_override` setting or verify the exporter's sampling configuration.

**Too many exporters, flows being dropped**:
- Increase `max_exporters` in the module settings if you have many devices exporting.

---

**Next**: See [docs/NETFLOW-MODULE.md](../NETFLOW-MODULE.md) for configuration details and API reference.
