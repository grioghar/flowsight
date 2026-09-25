# HOWTO: place devices in your physical space

Import a floor plan, place devices on it, and use the spatial view to understand your network topology.

**Tier**: Pro

## Prerequisites

- A floor plan image (PNG, JPG, or PDF of your home/office)
- Devices on your network (with known locations)

## Steps

1. **Open the Space page.**
   - FlowSight › Space (under INVENTORY)
   - If this is the first time, the page guides you to upload a floor plan

2. **Upload a floor plan.**
   - Click **Upload floor plan** or **Import scan**
   - Choose your floor plan image:
     - Hand-drawn sketch
     - Photo of a printed floor plan
     - CAD export (PDF or rasterized)
     - Overhead photo of your space
   - FlowSight analyzes the image and detects rooms and walls
   - Click **Next**

3. **Calibrate the scale (optional but recommended).**
   - If the floor plan is to scale, tell FlowSight:
     - Click **Calibrate** (or skip if you just want a rough visual)
     - Draw a line on the plan and tell it the real-world distance
     - Example: your hallway is 10 meters, draw a line and type `10m`
   - This helps with location-based recommendations

4. **Place devices on the floor plan.**
   - The page shows a list of known devices on the left
   - Click and drag each device to its location on the plan
   - Or:
     - Click the plan where a device is located
     - Select the device from the list
     - Click **Place**
   - As you place devices, FlowSight updates the map

5. **Mark areas of interest.**
   - Optional: draw zones on the plan:
     - **WiFi coverage zones**: weak or strong signal areas
     - **Network closets**: where equipment is
     - **No-go areas**: places to avoid (gardens, shops)
   - These help with diagnosis and planning

6. **View the dependency map.**
   - From the Space page, click **Map** or **Show graph**
   - See how devices connect to each other and to the gateway
   - Devices physically close together may use WiFi; far ones may have signal issues

7. **Add notes to locations.**
   - Click a region of the plan or a device
   - Add a note: `WiFi dead zone`, `Smart TV here`, `Home office`, etc.
   - Notes are saved with the plan

## What to expect

- **Layout takes 1–5 minutes** the first time
- **Devices can be anywhere**: you can place them even if FlowSight has not identified them yet
- **WiFi coverage**: devices far from the AP may have weak signal; the map can highlight this
- **Mobile devices**: phones and tablets may move; you can update their position as they roam
- **Shared devices**: if a device appears in multiple rooms (e.g., a laptop), place it where it is most often

## Limits

- **Scale accuracy**: hand-drawn plans may not be to scale; calibration helps but is not precise
- **Wall materials**: thick walls (concrete, metal) cause signal attenuation; the map is a rough guide
- **Mobile devices**: moving devices do not update automatically; refresh to see updated positions
- **Plans with many devices**: >100 devices on one plan may be hard to read; consider splitting into zones

## Advanced: import a scan

Instead of a floor plan image:
- Create a scan by walking through your space with a mobile device
- The Space page can analyze the scan and build a floor plan automatically
- This is faster than tracing a paper plan

## Related

- [Identify an unknown device](identify-device.md)
- [Map your Proxmox guests](proxmox-guests.md)
- *User guide › Space*
