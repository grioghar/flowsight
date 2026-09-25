# Apply policies to users, not devices

User-based policies allow you to control network access by person rather than machine. A developer's laptop, phone and tablet are all treated as one user for policy purposes, even though they are different devices.

FlowSight identifies users via RADIUS accounting (from FreeRADIUS, OPNsense captive portals, or compatible systems) and optionally resolves group membership via LDAP/Active Directory.

## How it works

User sessions are tracked in FlowSight's database. A session records:
- Username
- Every address the user was assigned (IPv4 and/or IPv6)
- MAC address of the device
- When the session started, last activity, and when it ended
- Source: RADIUS accounting, manual API entry, or (future) LDAP binding

Policies can then target users directly (`user:alice`) or by group (`usergroup:admins`).

## Setup: RADIUS accounting

### OPNsense captive portal

1. **Enable the captive portal** on an interface in OPNsense.
2. **Set up a FreeRADIUS server** on the same network or via a tunnel, or use OPNsense's built-in RADIUS service if accounting is enabled.
3. **Configure FlowSight** to listen for RADIUS accounting:
   - Go to Settings › Users › RADIUS accounting
   - Enable it
   - Set Listen address: `0.0.0.0:1813` (or a specific IP)
   - Enter the shared secret (the one your RADIUS server uses)
   - Optionally whitelist specific RADIUS client CIDR ranges

4. **Configure your captive portal to send accounting** to FlowSight's RADIUS port and use the same shared secret.

Example FreeRADIUS config (on OPNsense):
```
acct_port = 1813
secret = sharedsecret
client 10.0.1.1 {
    secret = sharedsecret
}
```

The accounting packets will now populate FlowSight's user sessions.

### Captive portal with manual API entry

If you cannot set up RADIUS accounting, you can manually post user logins:

```bash
curl -X POST http://127.0.0.1:8080/api/users/session \
  -H "X-Requested-With: Flowsight" \
  -d "user=alice&ipv4=192.168.1.10&mac=aa:bb:cc:dd:ee:ff&nas_ip=10.0.1.1"
```

Parameters:
- `user`: username (required)
- `ipv4`: IPv4 address (optional)
- `ipv6`: IPv6 address or prefix (optional)
- `mac`: MAC address (optional)
- `nas_ip`: NAS IP for reference (optional)
- `nas_id`: NAS identifier for reference (optional)

Useful for custom captive portals, SSO systems, or VPN solutions that track login events.

## Setup: LDAP/AD group lookup (future work)

This feature is planned but not yet implemented in the current version. When available, it will:
1. Query Active Directory or LDAP for group membership
2. Cache groups with a configurable TTL
3. Allow policies to reference groups: `usergroup:Finance`

For now, user targeting is available, but groups are not.

## Using user policies

### Target a single user

In your policy document, use the member form `user:username`:

```yaml
groups:
  alice:
    members: ["user:alice"]
policies:
  - name: alice-strict-dns
    enabled: true
    action: monitor  # or block
    match:
      groups: [alice]
    deny:
      domains: [torrent-site.com, warez.net]
```

All of Alice's devices (wherever she logs in) match this policy.

### Target a group (when LDAP is set up)

```yaml
groups:
  admins:
    members: ["usergroup:admins"]
policies:
  - name: admin-bypass
    enabled: true
    action: block
    match:
      groups: [admins]
    deny:
      apps: []  # Admins bypass all restrictions
    allow:
      domains: ["*"]  # Except any exclusions
```

### Mix user and device targeting

```yaml
groups:
  users:
    members:
      - "user:alice"
      - "user:bob"
      - "10.0.2.0/24"  # Lab network
      - "device:shared-printer"
policies:
  - name: lab-access
    match:
      groups: [users]
    deny:
      internet: true
    allow:
      domains:
        - github.com
        - stackoverflow.com
```

## Monitoring and inspection

### View active users

```bash
GET /api/users
```

Returns all currently logged-in users and their sessions.

### View user details

```bash
GET /api/users/{name}
```

Returns all sessions (current and recent) for a user, plus group membership if LDAP is enabled.

### Policy history

The Policies page in FlowSight shows which users matched each rule in recent logs. The Who tab in the policy editor lists all known users as suggestions for targeting.

## Troubleshooting

### RADIUS packets not arriving

1. **Check firewall rules**: Make sure the FlowSight host can receive UDP 1813 from RADIUS servers.
2. **Verify shared secret**: The secret in FlowSight must match exactly (case-sensitive).
3. **Check client whitelist**: If `allowed_client_ips` is not empty, the RADIUS server's IP must be listed.
4. **Test the server**: Use `radtest` or similar to verify the RADIUS accounting listener is responding.

### Sessions appear but don't match policies

1. **Check the user name**: Session usernames are case-sensitive.
2. **Verify group membership**: If using LDAP (future), test with `POST /api/users/ldap/test?user=alice`.
3. **Inspect the policy**: The Who tab shows exactly what members the policy resolves to.

### Performance with many users

Policies with many user: entries are evaluated at compile time. If you have hundreds of active users, use `usergroup:` instead (when LDAP is available) for faster compilation.

## Future work

- LDAP/AD group lookups with caching
- User session persistence across restarts
- Session activity recording (bytes in/out, duration)
- Per-user audit log
