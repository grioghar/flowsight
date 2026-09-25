# HOWTO: enable TLS inspection for one device with a bypass list

Turn on TLS inspection for a specific device to see inside encrypted traffic, and add exceptions for sites that should not be inspected.

## Prerequisites

- Web interception is enabled in *Administration › Settings › web*
- TLS inspection is enabled in *Administration › Settings › tls*
- The device is connected to the network
- A TLS CA has been created and trusted on the device (from the setup wizard or manually)

## Steps

1. **Trust the FlowSight CA on the device (first time only).**
   
   **On iOS/iPadOS:**
   - FlowSight › Settings (under ADMINISTRATION)
   - Click the *TLS* card
   - Click **Download CA** (or copy the link)
   - On the device, open the link and trust the certificate:
     - Settings › General › VPN & Device Management › FlowSight CA
     - Tap **Trust**
   
   **On macOS:**
   - Download the CA certificate to the device
   - Keychain Access › import the certificate
   - Double-click it and set trust to "Always Trust"
   
   **On Windows:**
   - Download the CA
   - Right-click › Install Certificate › Local Machine › Trusted Root Certification Authorities
   
   **On Android:**
   - Settings › Security › Advanced › Install from storage (or from link)
   - Select the CA file

2. **Find the device on the network.**
   - FlowSight › Devices (under INVENTORY)
   - Click the device to open its host page

3. **Enable inspection for this device only.**
   On the device:
   - Set the HTTP proxy to your gateway's address
   - Port: the proxy port (default 3128)
   - **macOS/iOS**: Settings › WiFi › (your network) › Configure Proxy › Manual
   - **Windows**: Settings › Network › Proxy › Manual proxy setup
   - **Android**: Settings › WiFi › (network name) › Advanced › Proxy › Manual
   - **Or use DHCP**: many gateways can set proxy via DHCP option 252

4. **Create a bypass list (optional but recommended).**
   Some sites and apps should not be inspected:
   - Banking apps and payment systems (certificate pinning)
   - Work VPNs and security tools
   - Apps that fail with an untrusted CA
   
   To bypass inspection for specific sites:
   - FlowSight › Settings (under ADMINISTRATION)
   - Click the *TLS* card, or go to *Administration › Settings › tls*
   - Find **Bypass list** or **Do not inspect**
   - Add domain names:
     - `*.bank.com` (wildcard)
     - `vpn.company.com` (exact)
     - `api.example.com`
   - One per line
   - Click **Save**

5. **Verify inspection is working.**
   - On the device, visit an HTTPS site (e.g., https://example.com)
   - Go back to FlowSight › Web (under MONITOR)
   - You should see the request logged with "decrypted" marked
   - Click the request to see the full URL and method

6. **Test the bypass list.**
   - Visit a site on the bypass list
   - On the Web page, it should show "encrypted (not inspected)"
   - This confirms the bypass is working

## What to expect

- **Certificate pinning fails**: banking and payment apps may break (this is why they are often bypassed)
- **Certificate warnings**: apps that expect the real certificate may warn or refuse to connect
- **Performance**: inspection adds a small latency (typically <10 ms)
- **Memory usage**: each inspection uses a small amount of RAM for buffering
- **Encrypted payloads**: the request body is decrypted, but encrypted protocol-level payloads (Signal, WhatsApp) are still encrypted

## Limits

- **Certificate pinning**: some applications check the certificate's exact fingerprint and refuse connections with any other CA, even trusted ones
- **DoH (DNS over HTTPS)**: Firefox and Chrome by default use DoH, which bypasses your DNS resolver; inspect GET requests to DoH endpoints to recover the domain
- **mTLS (mutual TLS)**: some apps present a client certificate; inspection may break these (add to bypass list)
- **QUIC (HTTP/3)**: encrypted over QUIC cannot be inspected; HTTP/2 over TLS can be
- **Limited to HTTP(S)**: inspection only works for web traffic, not SSH, TLS VPNs, or other encrypted protocols

## Related

- [Set up traffic sources and interception](getting-started.md)
- [Capture and inspect packets](packet-capture.md)
- *User guide › TLS inspection*
- *User guide › Settings › TLS*
