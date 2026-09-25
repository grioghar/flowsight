# HOWTO: set up traffic sources and interception

Run the setup wizard to enable FlowSight to see traffic, capture web requests, and perform TLS inspection.

## Prerequisites

- FlowSight is installed on your gateway
- You have admin access to the web interface
- (Optional: a TLS certificate to trust for inspection)

## Steps

1. **Open the setup wizard.**
   - FlowSight › Setup wizard
   - Click **Open setup** on the banner at the top of any page, or go to Administration › Setup wizard

2. **Step 1: Choose your traffic sources.**
   - The wizard shows the networks and interfaces FlowSight can listen to
   - Check the interfaces where you want to capture traffic:
     - **LAN**: typically your home network (192.168.0.0/24 or similar)
     - **WAN**: if you want to see traffic to/from the internet
   - Click **Next**

3. **Step 2: Enable web interception (optional but recommended).**
   - Tick **Enable web traffic interception**
   - Choose the **proxy port** (default 3128)
   - Choose the **interception method**:
     - *Automatic* — uses pf (FreeBSD/OPNsense)
     - *Manual* — requires you to configure a DHCP option or device-by-device proxy setting
   - Click **Next**

4. **Step 3: TLS inspection setup (optional).**
   - Tick **Enable TLS inspection** if you want to see encrypted request details
   - The wizard will create a root CA if one does not exist
   - You can download the CA and trust it on your devices (Settings › TLS › Download CA)
   - **Be careful**: enabling TLS inspection on a device disables certificate pinning
   - Click **Next**

5. **Step 4: Review and apply.**
   - The wizard shows what it will configure:
     - Traffic sources and interfaces
     - Proxy port and interception method
     - TLS CA (if enabled)
   - Click **Apply**
   - The configuration is written and the daemon restarts

6. **Verify it is working.**
   - Return to FlowSight › Overview
   - After 30 seconds, you should see traffic:
     - Active flows increase
     - Top hosts appear
     - Top applications list starts to populate
   - If you see no traffic after a minute:
     - Check *Administration › Status › System* for the daemon status
     - Verify interfaces are online in *Administration › Settings › sources*
     - Check the gateway firewall is not blocking the proxy

## What to expect

- **First traffic appears in 10–30 seconds** after you enable sources
- **DNS queries** (every domain lookup) appear immediately; no interception needed
- **Web traffic** (HTTP and HTTPS site names) appears once interception is on
- **Encrypted requests** (request method, path, response code) need TLS inspection
- **Applications** are identified by nDPI over the first hour as patterns are recognized
- **Device names** come from DHCP leases and MDNS; unknown devices show as addresses

## Limits

- Traffic between two local devices (a phone talking to your printer) does **not** pass through the gateway and is not seen
- DNS over HTTPS (DoH) in browsers bypasses your resolver entirely and is invisible unless TLS inspection is on
- The proxy cannot intercept traffic if a device uses a hardcoded DNS server or proxy setting
- TLS inspection requires trusting the FlowSight CA; applications with certificate pinning (some banking apps) will not work

## Related

- [First look at the dashboard](first-look.md)
- [Enable TLS inspection for one device](tls-inspect-device.md)
- *User guide › Setup wizard*
- *User guide › Interception*
