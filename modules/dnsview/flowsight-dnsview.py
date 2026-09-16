#!/usr/bin/env python3
"""DNS visibility: what this network asked for, who asked, and what came back.

Unbound on OPNsense already records every query it answers into a DuckDB store
- client, domain, type, whether it was passed or blocked and by which list,
where the answer came from, the response code, DNSSEC status and how long
resolution took. That is a better record than anything reconstructable from
syslog, so this module reads it rather than turning on query logging and
parsing text.

It also publishes the resolver's own cache as an address-to-name map. Unbound
knows the forward answers it handed out, which is the only reliable way to name
the far end of a flow: a PTR lookup frequently has no record at all, and where
it does the name often belongs to the hosting provider rather than to the
service anyone actually visited.

Read-only throughout. Nothing here changes resolver behaviour.
"""

import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, "/usr/local/opnsense/site-python")

DB = "/var/unbound/data/unbound.duckdb"
UNBOUND_CONF = "/var/unbound/unbound.conf"

ACTION = {0: "Pass", 1: "Block", 2: "Drop"}
SOURCE = {0: "Recursion", 1: "Local", 2: "Local-data", 3: "Cache"}
RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMPL",
         5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH",
         10: "NOTZONE"}
DNSSEC = {0: "Unchecked", 1: "Bogus", 2: "Indeterminate", 3: "Insecure",
          5: "Secure"}


class NoStore(Exception):
    pass


def client_names():
    """Address to device name, from DHCP and from enrollment.

    Unbound keeps a client table, but it is sparse - it only holds what the
    resolver itself managed to resolve, which on this network named barely a
    tenth of the hosts making queries. DHCP already knows what each device
    called itself, and enrollment knows what it was identified as, so a DNS
    page that shows bare addresses is discarding names the system holds.
    """
    names = {}
    try:
        with open("/var/db/dnsmasq.leases") as fh:
            for line in fh:
                p = line.split()
                if len(p) >= 4 and p[3] != "*":
                    names[p[2]] = p[3]
    except Exception:
        pass
    try:
        # Statically reserved hosts may never appear in the lease file at all,
        # yet they are exactly the infrastructure worth naming on this page.
        # The reservation itself carries the name.
        import glob
        for conf in ["/usr/local/etc/dnsmasq.conf"] + sorted(
                glob.glob("/usr/local/etc/dnsmasq.conf.d/*.conf")):
            try:
                with open(conf) as fh:
                    for line in fh:
                        if not line.startswith("dhcp-host="):
                            continue
                        parts = line.strip().split("=", 1)[1].split(",")
                        ip = next((x for x in parts if x.count(".") == 3), "")
                        label = parts[-1]
                        if ip and label and "." not in label and ":" not in label:
                            names.setdefault(ip, label)
            except OSError:
                continue
    except Exception:
        pass
    try:
        with open("/var/db/flowsight/enroll-registry.json") as fh:
            for d in json.load(fh).get("devices", {}).values():
                ip = d.get("ip")
                if ip and (d.get("hostname") or d.get("guest_name")):
                    names.setdefault(ip, d.get("hostname") or d["guest_name"])
    except Exception:
        pass
    names.setdefault("127.0.0.1", "localhost")
    names.setdefault("::1", "localhost")
    return names


def connect():
    """Open the resolver's query store read-only.

    Read-only matters: unbound is writing to this file continuously, and an
    exclusive handle here would stall the resolver for the whole network.
    """
    if not os.path.exists(DB):
        raise NoStore("no query store at %s - enable Unbound reporting" % DB)
    try:
        from duckdb_helper import DbConnection
    except ImportError as exc:
        raise NoStore("duckdb unavailable: %s" % exc)
    return DbConnection(DB, read_only=True)


def rows(db, sql, params=None):
    return db.connection.execute(sql, params or []).fetchall()


def _since(hours):
    return int(time.time()) - int(hours) * 3600


# --------------------------------------------------------------------------
# aggregates


def summary(db, hours):
    since = _since(hours)
    r = rows(db, """
        SELECT count(*), 
               count(*) FILTER (action = 0),
               count(*) FILTER (action = 1),
               count(*) FILTER (action = 2),
               count(*) FILTER (source = 3),
               count(*) FILTER (source = 0),
               count(DISTINCT client),
               count(DISTINCT domain),
               count(*) FILTER (rcode = 3),
               count(*) FILTER (rcode = 2),
               coalesce(avg(resolve_time_ms) FILTER (source = 0), 0),
               coalesce(max(resolve_time_ms), 0)
        FROM query WHERE time >= ?""", [since])[0]
    total = r[0] or 0
    pct = lambda n: round(100.0 * n / total, 2) if total else 0.0
    return {
        "hours": hours, "total": total,
        "passed": r[1], "blocked": r[2], "dropped": r[3],
        "blocked_pct": pct(r[2]),
        "cached": r[4], "cache_pct": pct(r[4]),
        "recursed": r[5],
        "clients": r[6], "domains": r[7],
        "nxdomain": r[8], "servfail": r[9],
        "avg_resolve_ms": round(float(r[10]), 1),
        "max_resolve_ms": r[11],
    }


def top_domains(db, hours, limit, action=None):
    # "last" is reserved in DuckDB, hence the alias.
    sql = """SELECT domain, count(*) n, count(DISTINCT client) c,
                    max(time) last_seen
             FROM query WHERE time >= ?"""
    params = [_since(hours)]
    if action is not None:
        sql += " AND action = ?"
        params.append(action)
    sql += " GROUP BY domain ORDER BY n DESC LIMIT ?"
    params.append(limit)
    return [{"domain": d.rstrip("."), "queries": n, "clients": c, "last": t}
            for d, n, c, t in rows(db, sql, params)]


def top_blocked(db, hours, limit):
    return [{"domain": d.rstrip("."), "queries": n, "clients": c,
             "blocklist": bl or ""}
            for d, n, c, bl in rows(db, """
        SELECT domain, count(*) n, count(DISTINCT client) c,
               any_value(blocklist)
        FROM query WHERE time >= ? AND action = 1
        GROUP BY domain ORDER BY n DESC LIMIT ?""", [_since(hours), limit])]


def top_clients(db, hours, limit):
    known = client_names()
    return [{"client": ip, "hostname": (hn or known.get(ip, "")), "queries": n,
             "blocked": b, "domains": d}
            for ip, hn, n, b, d in rows(db, """
        SELECT q.client, any_value(c.hostname), count(*) n,
               count(*) FILTER (q.action = 1), count(DISTINCT q.domain)
        FROM query q LEFT JOIN client c ON c.ipaddr = q.client
        WHERE q.time >= ?
        GROUP BY q.client ORDER BY n DESC LIMIT ?""", [_since(hours), limit])]


def breakdown(db, hours, column, mapping):
    out = []
    for val, n in rows(db, """
            SELECT %s, count(*) n FROM query WHERE time >= ?
            GROUP BY 1 ORDER BY n DESC""" % column, [_since(hours)]):
        label = mapping.get(val, str(val)) if mapping else str(val)
        out.append({"label": label, "value": val, "queries": n})
    return out


def blocklists(db, hours):
    return [{"blocklist": bl or "(unnamed)", "queries": n}
            for bl, n in rows(db, """
        SELECT blocklist, count(*) n FROM query
        WHERE time >= ? AND action = 1 AND blocklist IS NOT NULL
        GROUP BY 1 ORDER BY n DESC LIMIT 25""", [_since(hours)])]


def timeseries(db, hours, interval=10):
    """Query rate over time, from the resolver's own bucketed views."""
    view = "v_time_series_%dmin" % (interval if interval in (1, 5, 10) else 10)
    return [{"t": s, "total": tot, "passed": p, "blocked": b, "cached": c}
            for s, tot, p, b, c in rows(db, """
        SELECT v.start_timestamp, count(q.time),
               count(*) FILTER (q.action = 0),
               count(*) FILTER (q.action = 1),
               count(*) FILTER (q.source = 3)
        FROM {v} v LEFT JOIN query q
          ON q.time >= v.start_timestamp AND q.time <= v.end_timestamp
        WHERE v.start_timestamp >= ?
        GROUP BY v.start_timestamp ORDER BY v.start_timestamp""".format(v=view),
        [_since(hours)])]


def recent(db, limit, client=None, domain=None, only_blocked=False):
    sql = """SELECT q.time, q.client, any_value(c.hostname), q.domain, q.type,
                    q.action, q.source, q.rcode, q.resolve_time_ms,
                    q.dnssec_status, q.blocklist
             FROM query q LEFT JOIN client c ON c.ipaddr = q.client
             WHERE 1=1"""
    params = []
    if client:
        sql += " AND q.client = ?"
        params.append(client)
    if domain:
        sql += " AND q.domain ILIKE ?"
        params.append("%" + domain.rstrip(".") + "%")
    if only_blocked:
        sql += " AND q.action = 1"
    sql += """ GROUP BY q.time, q.client, q.domain, q.type, q.action, q.source,
                        q.rcode, q.resolve_time_ms, q.dnssec_status, q.blocklist
               ORDER BY q.time DESC LIMIT ?"""
    params.append(limit)
    known = client_names()
    return [{"time": t, "client": ip, "hostname": hn or known.get(ip, ""),
             "domain": d.rstrip("."), "type": ty,
             "action": ACTION.get(a, a), "source": SOURCE.get(s, s),
             "rcode": RCODE.get(rc, rc), "resolve_ms": ms,
             "dnssec": DNSSEC.get(ds, ds), "blocklist": bl or ""}
            for t, ip, hn, d, ty, a, s, rc, ms, ds, bl
            in rows(db, sql, params)]


# --------------------------------------------------------------------------
# address -> name, from the resolver cache


def resolutions():
    """Address to name, built from unbound's own cache.

    This is forward-resolution data: the names clients asked for and the
    addresses they were given. It names the far end of a flow far more often,
    and far more usefully, than a reverse PTR lookup - most CDN and cloud
    addresses either have no PTR at all or carry one naming the provider rather
    than the service the user was actually reaching.

    When several names map to one address, all are kept: that is genuinely what
    a shared address means, and collapsing it to one name invents precision.
    """
    try:
        out = subprocess.run(
            ["/usr/local/sbin/unbound-control", "-c", UNBOUND_CONF, "dump_cache"],
            capture_output=True, text=True, timeout=60).stdout
    except Exception as exc:
        return {"error": str(exc), "map": {}}
    table = {}
    for line in out.splitlines():
        if line.startswith(";") or not line.strip():
            continue
        parts = line.split()
        if len(parts) < 5 or parts[3] not in ("A", "AAAA"):
            continue
        name, addr = parts[0].rstrip("."), parts[4]
        table.setdefault(addr, [])
        if name not in table[addr]:
            table[addr].append(name)
    return {"map": table, "addresses": len(table)}


# --------------------------------------------------------------------------
# commands


def cmd_overview(args):
    """Everything the DNS page needs, in one process start.

    Importing duckdb costs about a second, so the page is served from a single
    invocation rather than one per panel.
    """
    with connect() as db:
        out = {
            "summary": summary(db, args.hours),
            "top_domains": top_domains(db, args.hours, args.limit),
            "top_blocked": top_blocked(db, args.hours, args.limit),
            "top_clients": top_clients(db, args.hours, args.limit),
            "types": breakdown(db, args.hours, "type", None),
            "rcodes": breakdown(db, args.hours, "rcode", RCODE),
            "sources": breakdown(db, args.hours, "source", SOURCE),
            "dnssec": breakdown(db, args.hours, "dnssec_status", DNSSEC),
            "blocklists": blocklists(db, args.hours),
            "timeseries": timeseries(db, args.hours, args.interval),
        }
    print(json.dumps(out))
    return 0


def cmd_recent(args):
    with connect() as db:
        print(json.dumps({"queries": recent(db, args.limit, args.client,
                                            args.domain, args.blocked)}))
    return 0


def cmd_resolutions(args):
    print(json.dumps(resolutions()))
    return 0


def cmd_lookup(args):
    """Name an address from the resolver cache."""
    table = resolutions().get("map", {})
    print(json.dumps({"address": args.address,
                      "names": table.get(args.address, [])}))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("overview")
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--limit", type=int, default=25)
    p.add_argument("--interval", type=int, default=10)
    p.set_defaults(fn=cmd_overview)

    p = sub.add_parser("recent")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--client")
    p.add_argument("--domain")
    p.add_argument("--blocked", action="store_true")
    p.set_defaults(fn=cmd_recent)

    sub.add_parser("resolutions").set_defaults(fn=cmd_resolutions)

    p = sub.add_parser("lookup")
    p.add_argument("address")
    p.set_defaults(fn=cmd_lookup)

    args = ap.parse_args()
    try:
        return args.fn(args)
    except NoStore as exc:
        print(json.dumps({"error": str(exc)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
