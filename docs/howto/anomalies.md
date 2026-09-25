# Know When a Device Does Something New

The Anomalies page in FlowSight's Protect tab shows what devices are doing that they haven't done before. Unlike security rules that flag attacks or policy violations, anomalies detect behavior changes — the first time a device calls a new country, connects to a new port, beacons regularly, or tunnels through DNS.

## What You See

**Anomalies** lists open findings from the Baseline module:

- **Device**: The host name or IP that exhibited the anomaly.
- **Kind**: The type of deviation (first-seen country, port, destination; beaconing; DNS tunneling).
- **Severity**: Critical, high, medium, or low, based on the kind.
- **What**: A short description (e.g., "First time in IE" or "Beacon to 192.0.2.1 (~60s period").
- **Since**: How long ago the finding was raised.
- **Actions**:
  - **Acknowledge**: Mark as reviewed; stops re-flagging until the cooldown expires or the baseline changes.
  - **Sessions**: Open the Sessions view filtered to traffic from this device for this anomaly.
  - **Device**: Jump to the device's baseline profile.

## Device Baseline Profile

Click **Baseline** on a host's page to see what you know about that device:

- **Countries**: All countries the device has contacted, with first and last seen dates and byte counts.
- **Ports**: All protocol/port pairs it has used.
- **Destinations**: All IP and domain destinations, ranked by connection count.
- **Activity**: Hour-of-day histogram showing when the device is normally active.

This profile is your reference: anything not on it (or far outside its pattern) is an anomaly.

## Configuring Detection

Open **Settings** → **Baseline** to tune:

- **Learning period**: Days until a device's profile is mature enough to flag anomalies (default: 7). Useful for new devices that haven't settled yet.
- **Thresholds**: Adjust the coefficient-of-variation threshold for beaconing regularity, DNS entropy floors, etc.
- **Excluded zones**: Devices in these zones are never flagged (e.g., guest network, lab devices).
- **Cooldown**: How often the same finding can repeat (default: 60 minutes).

## Common Scenarios

### A new device joined; I see many "first-seen" findings.

This is expected during the learning phase. The device's profile is being built. After the learning period (7 days by default) passes, the noise stops and only real deviations are flagged.

### I see beaconing alerts from a device I trust.

Beaconing — regular connections with constant payload size — can indicate:
- **Legitimate**: A device checking for updates, phoning home to the vendor, or maintaining a persistent sync.
- **Suspicious**: Malware or C2 traffic.

Review the destination. If it's your vendor's update server, acknowledge the finding and adjust the threshold if it keeps recurring. If it's unknown, isolate the device and investigate.

### DNS tunneling findings.

A device is using DNS to tunnel data (high label entropy, high NXDOMAIN rate, suspicious domains). This often indicates:
- **Exfiltration**: An attacker using DNS as a covert channel.
- **Misconfiguration**: A DNS client with a buggy resolver, generating garbage queries.

Examine the device's DNS queries in detail (DNS view) and the destinations it resolved. Isolate if confirmed malicious.

### A device's bytes jumped 5× its normal daily amount.

Check the Sessions view filtered to that device. Is it downloading or uploading something legitimate? If so, it's normal. If the destination is new or untrusted, investigate further or apply a firewall rule.

## Integration with Policy

If you've configured alerting rules, anomalies can trigger notifications or auto-actions. For example:

```
rule "isolate_beaconing" {
  condition: baseline.beaconing
  action: block_device
  channels: [slack, syslog]
}
```

This rule blocks any device flagged for beaconing and notifies Slack and syslog.

## Tuning to Reduce False Positives

1. **Increase learning_days** for very variable device behavior (e.g., laptops, phones).
2. **Raise the bytes_multiplier** if you see legitimate spikes flagged.
3. **Lower beaconing_cv_threshold** only if you're confident: it catches irregular patterns.
4. **Add zones to excluded_zones** for devices you manage (e.g., your own backup server).

## What Gets Stored

Findings are kept until acknowledged or resolved. Resolved findings (when a device's behavior returns to baseline) are archived after 24 hours. You can always revisit acknowledged findings on the Anomalies page.
