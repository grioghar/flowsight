# NetFlow Module Configuration

## Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | false | Enable UDP collectors for NetFlow, IPFIX, and sFlow |
| `bind_address` | string | (LAN bind address) | Address to listen on; empty uses platform default |
| `netflow5_port` | int | 2055 | UDP port for NetFlow v5 |
| `netflow9_port` | int | 2055 | UDP port for NetFlow v9 |
| `ipfix_port` | int | 2055 | UDP port for IPFIX (IP Flow Information Export) |
| `sflow5_port` | int | 6343 | UDP port for sFlow v5 |
| `allowed_cidrs` | text | (RFC1918 + link-local) | Newline-separated CIDR ranges; empty defaults to 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fe80::/10 |
| `sampling_override` | int | 0 | Multiplier for bytes and packets (0 = use flow-provided rate) |
| `max_exporters` | int | 100 | Maximum concurrent exporters before dropping records |

## Protocols Supported

- **NetFlow v5** (RFC 3954): Fixed-format flow records. No templates needed. Widely supported on legacy routers and switches.
- **NetFlow v9** (RFC 3954): Template-based format. More flexible; templates must be sent before data records.
- **IPFIX** (RFC 5101, 7011): Internet Protocol Flow Information Export. Similar to NetFlow v9 with 64-bit counters and millisecond timestamps.
- **sFlow v5** (RFC 6343): Sampled flows; decodes raw packet headers (Ethernet, IPv4, IPv6, TCP, UDP). Includes sampling rate per sample.

## API Endpoints

### GET /api/netflow/status

Returns per-exporter statistics:

```json
{
  "enabled": true,
  "exporters": [
    {
      "address": "192.168.1.50",
      "protocol": "netflow5",
      "records_total": 1500,
      "flows_total": 1500,
      "drops_total": 0,
      "templates": 0,
      "last_seen": 1695298765
    }
  ],
  "ok": true,
  "error": ""
}
```

## Flow Enrichment

Flows from NetFlow, IPFIX, and sFlow are enriched the same way as ntopng flows:
- **Country lookup**: destination IP mapped to ISO country code
- **Anycast detection**: destination IP checked against known CDN/anycast ranges
- **Identity**: local IP addresses resolved to hostnames if the identity module is enabled

## Limitations

- **Application identity**: NetFlow v5 does not include application IDs. NetFlow v9 and IPFIX support application fields but export must provide them; the module falls back to empty app names.
- **TLS SNI and JA3**: Not available from flow records alone; would require inline inspection (see inspect module).
- **Direction ambiguity**: Some exporters report bidirectional byte totals; the module treats the reported bytes as outbound. For symmetric flows, this is acceptable for coarse metrics.
- **Sampling**: If the exporter applies sampling, bytes and packet counts reflect the sample rate. The `sampling_override` setting can correct for uniform sampling if not exported per-flow.

## Typical Deployment

1. **OPNsense/pfSense router**: Enable NetFlow export (Reporting → NetFlow) pointing to FlowSight's IP:2055.
2. **Linux router**: Use `softflowd` or `pmacct` to export NetFlow v5 or sFlow v5.
3. **Switch**: Enable sFlow or NetFlow export (varies by vendor; typically found in Monitoring or Telemetry).
4. **East-West visibility**: Any internal device that exports flows can be pointed at FlowSight; visibility expands from the gateway to the entire LAN.

## Exporter Template Cache

NetFlow v9 and IPFIX use templates to describe flow record schema. The module caches up to one template per (source-id, domain-id) pair per exporter. Templates are retained for 30 minutes after the last packet from an exporter.

Options Templates (used to describe optional metadata) are recognized but skipped.

## Known Issues & Future Work

- Template retransmission: NetFlow v9/IPFIX spec recommends periodic template retransmission; slow-changing deployments may re-send templates infrequently. If the module restarts or the template times out, template-based flow records will be dropped until the next template is received. Mitigate by configuring an exporter to send templates every few seconds.
- Variable-length fields: IPFIX supports variable-length fields (e.g., for hostname); the module currently skips them. A future update will decode them.
