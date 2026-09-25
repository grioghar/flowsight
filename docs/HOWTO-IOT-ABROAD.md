# HOWTO: see what your IoT devices send abroad, and block it

This walks through one question end to end: *which of my smart-home devices
talk to servers in other countries, what exactly are they doing, and how do I
stop it at the firewall?* It uses four FlowSight pages and takes about ten
minutes the first time.

## What you need switched on

1. **Country lookup.** *Administration › Settings › enrich* › turn on *Country
   lookup*. FlowSight downloads a free country database (DB-IP Lite) into its
   data directory and refreshes it monthly. From then on every session carries
   the far end's country, and FlowSight knows which country your own gateway
   sits in: that is what "home" and "abroad" mean below. Nothing is sent
   anywhere for this; lookups are local.
2. **A zone or group for the IoT devices.** *Inventory › Zones* already has an
   `iot` zone if you set one up; otherwise *Protect › Groups & Schedules* › *New
   group* with members like `zone:iot`, `mac:aa:bb:cc:dd:ee:ff` or
   `192.168.2.0/24`. A group is how a policy names "these devices".

## Step 1: see who leaves the country

*Protect › DLP* has a card called **Leaving the country**. One row per local
device that reached another country in the selected window (the 1h/6h/24h/7d
buttons at the top): how many sessions went abroad, which countries (each pill
shows sessions and bytes), and the destinations behind the top countries by
name where FlowSight knows one. The IoT devices are the rows whose names are
speakers, plugs, cameras and thermostats.

The same list is available as data at `GET /api/visibility/abroad?hours=24`,
per device with countries and destinations, if you would rather script it.

## Step 2: see the traffic itself

Click the sessions count on a row, or open *Monitor › Sessions* and press
**Outside \<your country\>**. Every session whose far end is abroad is listed:
client, server (the country appears as an amber pill next to the port), the
application nDPI recognised, the site name from DNS or the proxy, bytes each
way, duration and verdict. Click a country pill to narrow to that country;
add `ip` to narrow to one device (the row's Block button and the device's
host page both do this for you). The host page also has a **Sessions outside
the country** button in its Identity card.

For a camera or speaker the pattern to look for is steady small sessions to
the maker's cloud (telemetry, firmware checks) versus large uploads, which the
DLP page's transfer watch flags separately.

To go deeper on one session: **Map** on the row shows the route the traffic
takes and where it ends; *Protect › Packet Inspection* can capture that
device's packets for a minute and show DNS names, TLS server names and the
conversation table, or hand you a pcap for Wireshark.

## Step 3: block it

FlowSight policies can deny destination countries. In the firewall this
becomes one table per country, built locally from the same country database,
and a block rule from the group's devices to those tables; nothing leaves the
gateway to build it.

Two ways in:

- **From the DLP card:** press **Block…** on the device's row. The policy
  editor opens with the device pre-filled as a member and the countries it
  reached pre-filled on the *Countries* tab. Change the members to the IoT
  group or zone if you want the rule to cover all of them, review the list of
  countries, name the policy and save. Choose *monitor* first if you only want
  to see what would be blocked; switch to *block* when you are sure.
- **From scratch:** *Protect › Policies* › *New policy* › members
  `zone:iot` (or your group) › *Countries* tab › pick the countries to deny,
  or tick *block everything except* and pick the countries you allow (your
  own is included automatically) › action *block* › save.

Applying writes the rule set to FlowSight's own pf anchor; your OPNsense
firewall rules are not touched. *Protect › Firewall Analysis Engine (FAE)*
shows the anchor's tables with their prefix counts, and *Monitor › Sessions*
› **Blocked only** shows what the policy stopped, with the policy's name on
each row.

## What to expect, and the limits

- A device that cannot reach its cloud may retry hard or stop working. Start
  in monitor mode, watch **Blocked only** for a day, then enforce.
- Countries are decided by the address's registration, not by physics. CDNs
  and anycast services (Cloudflare, Google, Akamai) can answer from a nearby
  data centre under a foreign registration, and the reverse. The *Map* page's
  placement engine is the better source for where a specific server really
  is; the country rule is the practical instrument for policy.
- IPv6 is covered the same way; both families go into each country's table.
- The country database refreshes monthly; the tables follow it. Between
  refreshes newly assigned ranges may be missed, which is why monitor mode
  and the Blocked view matter more than the rule text.
- Traffic between two devices inside your network never crosses the gateway
  and is not subject to any of this.
