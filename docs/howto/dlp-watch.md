# HOWTO: watch data transfers and prevent them

Use the DLP (Data Loss Prevention) page to identify large file transfers, watch for repeated transfers to a destination, and stop them in flight.

## Prerequisites

- Traffic is being captured (at least 1 hour)
- You want to monitor a group of devices (e.g., `zone:iot`) or a specific application (e.g., Syncthing, S3)
- (Optional: watched groups enabled in *Protect › Groups & Schedules*)

## Steps

1. **Open the DLP page.**
   - FlowSight › DLP (under PROTECT)

2. **Understand the DLP cards.**
   The page shows several views:
   - **Transfers in progress**: active downloads and uploads right now
   - **Large downloads**: files being received (sorted by size)
   - **Large uploads**: files being sent (sorted by size)
   - **Leaving the country**: devices reaching servers abroad (if country enrichment is on)
   - **Repeated destinations**: devices connecting to the same destination multiple times (watching)

3. **Watch for large transfers.**
   Each large transfer shows:
   - **Device**: who is transferring
   - **Destination**: where it is going
   - **Size**: how much data
   - **Application**: what protocol (HTTP, FTP, S3, SMB, Syncthing, etc.)
   - **Bytes**: detailed breakdown
   - **Last seen**: when
   - **Stop** button (if enabled): kill the connection

4. **Set up watched groups (Pro).**
   To monitor specific devices or apps for repeated transfers:
   - FlowSight › Groups & Schedules (under PROTECT)
   - Click **New watched group**
   - Name it: `external-backup`, `cloud-sync`, etc.
   - Add the devices to watch: by MAC, zone, or address
   - (Or specify an application to watch: `app:Syncthing`, `app:S3`)
   - Click **Save**
   - The group now appears on the DLP page

5. **Understand the "Repeated destinations" card.**
   Once a watched group is set up, this card shows:
   - **Destination**: the server being accessed
   - **Sessions**: how many times in the window
   - **Bytes**: total data transferred
   - **Last seen**: when it was last active
   - **Block** button: write a policy denying this destination to the watched group
   - **Sessions** count: click to see all the sessions to this destination

6. **Stop a transfer (if enabled).**
   - In the *Transfers in progress* card, find the transfer
   - Click **Stop** to immediately cut the connection
   - (This requires the `stop_transfer` capability; check under *Administration › License*)

7. **Write a policy to block repeated transfers.**
   If you identify a destination you want to block:
   - Click **Block** on the destination's row
   - The policy editor opens with:
     - **Members**: the watched group pre-filled
     - **Destination**: the address or domain pre-filled
   - Set the **Action** to *block* (or *monitor* first)
   - Click **Save**

## What to expect

- **Large transfers** are typically:
  - Cloud backups (iCloud, Google Drive, OneDrive)
  - Media uploads (photos, videos)
  - Application updates
  - Database syncs (Syncthing, Resilio Sync)
  - Torrent or P2P uploads
- **Repeated destinations** from a watched group indicate:
  - Regular cloud sync (iCloud Photos, Syncthing)
  - Polling (apps checking for updates)
  - Telemetry (devices sending diagnostics)
- **The "Leaving the country" card** is useful for IoT devices that should not go abroad

## Limits

- The DLP page shows observed transfers; it cannot predict future ones
- Stopped transfers may reconnect immediately if the application retries
- Watched groups require the Pro tier
- Transfer monitoring is per-flow; a multi-threaded download may appear as several smaller transfers
- Encrypted transfers show the destination and size but not the file name

## Related

- [See what your IoT devices send abroad, and block it](iot-abroad.md)
- [Block apps and categories on a schedule](policy-schedule.md)
- [Watch data leaving and stop a transfer](dlp-watch.md)
- *User guide › DLP*
