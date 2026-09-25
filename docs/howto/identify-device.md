# HOWTO: identify an unknown device

Use network scanning and fingerprinting to name an unknown device, and assign it to a zone.

## Prerequisites

- The device has connected to the network and sent some traffic
- (Optional: FlowSight Scan enabled in *Inventory › Scan*)

## Steps

1. **Find the unknown device.**
   - FlowSight › IP Addresses or Devices
   - Look for a row with an address but no name, like `192.168.1.50`

2. **Option A: Use the Devices page for quick lookup.**
   - FlowSight › Devices
   - Unknown devices are grouped at the bottom with names like `Unknown-AABBCCDD`
   - Click the device to open its host page
   - Review the Sessions and Applications tables to identify it manually

3. **Option B: Use Scan for fingerprinting (Pro).**
   - FlowSight › Scan (under INVENTORY)
   - Click **New scan** or **Quick scan**
   - Select the subnet to scan (usually your LAN)
   - Click **Run**
   - Wait 1–2 minutes for the scan to complete
   - Each device row shows:
     - **Name**: what the scanner determined (OS, device type)
     - **Ports**: open ports (SSH, web server, etc.)
     - **Services**: what is running
   - Click a row to see full details

4. **Assign the device to a zone.**
   If you want to apply policies to this device later, put it in a zone:
   - FlowSight › Zones (under INVENTORY)
   - Click **New zone** or pick an existing zone
   - Add the device:
     - By MAC address: `aa:bb:cc:dd:ee:ff` (most stable, survives DHCP renewal)
     - By address: `192.168.1.50` (changes when the lease expires)
   - Name the zone: `guest-devices`, `iot`, `security-cameras`, etc.
   - Click **Save**

5. **Verify the zone assignment.**
   - Go back to FlowSight › Devices
   - The device should now show the zone name
   - On the host page (click the device) the zone appears in the Identity card

6. **Use the name in policies.**
   Once assigned to a zone, you can reference it in policies:
   - *Protect › Groups & Schedules* › new group
   - Use the member syntax: `zone:iot` (all devices in the iot zone)
   - Or: `mac:aa:bb:cc:dd:ee:ff` (this device by MAC)

## What to expect

- **New devices appear immediately** if they send traffic
- **Names come from multiple sources**:
  - DHCP hostname (if the device announces one)
  - mDNS name (if the device advertises itself)
  - Port service fingerprinting (if Scan runs)
  - Manual naming (when you create a zone)
- **MAC addresses are stable** across DHCP leases; IP addresses change
- **Scanning may take 1–2 minutes** for a full subnet
- **Some devices do not respond to scan requests** (firewalled hosts, sleepy devices)

## Limits

- A device must send traffic to appear on the Devices page
- Scan results are best-effort; not all ports and services are always identified
- A device on a different subnet may not appear on your LAN scan
- The MAC address is the most reliable identifier for policy purposes

## Related

- [See what one device is talking to](device-traffic.md)
- [Block apps and categories on a schedule](policy-schedule.md)
- *User guide › Zones*
- *User guide › Scan*
