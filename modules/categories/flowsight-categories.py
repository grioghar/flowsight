#!/usr/bin/env python3
"""Flowsight category feeds.

Maps a category name to a domain list, so policy can say `deny.categories:
[gambling]` instead of enumerating domains.

nDPI categorises *flows* (by IP and SNI); DNS blocking needs *domains*. They are
different problems, so this uses open domain feeds rather than nDPI's category
ids - and keeps them cached on disk so a policy compile never depends on the
network being up.

Sizes are the thing to respect here. Some categories are millions of domains,
which is fine for a resolver-level blocklist and emphatically not fine compiled
into a per-view local-zone. This module reports counts honestly and the policy
compiler refuses oversized categories rather than degrading DNS for everyone.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.request

CACHE_DIR = "/usr/local/share/flowsight/categories"
FEEDS_FILE = "/usr/local/etc/flowsight/categories.json"

# Open, per-category domain feeds. Deliberately hosts-format so one parser
# handles all of them.
DEFAULT_FEEDS = {
    "ads":       "https://raw.githubusercontent.com/blocklistproject/Lists/master/ads.txt",
    "tracking":  "https://raw.githubusercontent.com/blocklistproject/Lists/master/tracking.txt",
    "gambling":  "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt",
    "phishing":  "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt",
    "crypto":    "https://raw.githubusercontent.com/blocklistproject/Lists/master/crypto.txt",
    "adult":     "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
    "malware":   "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt",
    "scam":      "https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt",
}

_HOSTS_LINE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)")
_DOMAIN = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))+$")


def load_feeds():
    feeds = dict(DEFAULT_FEEDS)
    if os.path.isfile(FEEDS_FILE):
        try:
            with open(FEEDS_FILE) as fh:
                feeds.update(json.load(fh) or {})
        except Exception as exc:
            sys.stderr.write("categories: bad %s: %s\n" % (FEEDS_FILE, exc))
    return feeds


def cache_path(name):
    return os.path.join(CACHE_DIR, "%s.list" % name)


def parse_hosts(text):
    """Extract domains from a hosts-format feed, deduped and sorted."""
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _HOSTS_LINE.match(line)
        domain = m.group(1) if m else line
        domain = domain.strip().lower().rstrip(".")
        if domain in ("localhost", "localhost.localdomain", "0.0.0.0", ""):
            continue
        if _DOMAIN.match(domain):
            out.add(domain)
    return sorted(out)


def update(names=None, timeout=120):
    feeds = load_feeds()
    todo = names or sorted(feeds)
    os.makedirs(CACHE_DIR, exist_ok=True)
    results = []
    for name in todo:
        url = feeds.get(name)
        if not url:
            results.append((name, None, "no feed configured"))
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "flowsight"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text = resp.read().decode("utf-8", "replace")
            domains = parse_hosts(text)
            if not domains:
                # A feed that parses to nothing is almost always a fetch that
                # returned an error page. Never overwrite a good cache with it.
                results.append((name, None, "feed parsed to 0 domains; cache kept"))
                continue
            tmp = cache_path(name) + ".tmp"
            with open(tmp, "w") as fh:
                fh.write("\n".join(domains) + "\n")
            os.replace(tmp, cache_path(name))
            results.append((name, len(domains), None))
        except Exception as exc:
            results.append((name, None, str(exc)[:160]))
    return results


def read_category(name):
    """Domains for one category, from cache. Never hits the network."""
    path = cache_path(name)
    if not os.path.isfile(path):
        raise FileNotFoundError(
            "category %r has no cached feed. Run 'flowsight-categories update %s'."
            % (name, name))
    with open(path) as fh:
        return [ln.strip() for ln in fh if ln.strip()]


def status():
    feeds = load_feeds()
    rows = []
    for name in sorted(feeds):
        path = cache_path(name)
        if os.path.isfile(path):
            with open(path) as fh:
                count = sum(1 for _ in fh)
            rows.append((name, count, int(os.path.getmtime(path))))
        else:
            rows.append((name, None, None))
    return rows


def main():
    ap = argparse.ArgumentParser(description="Flowsight category feeds")
    ap.add_argument("command", choices=["status", "update"], nargs="?",
                    default="status")
    ap.add_argument("names", nargs="*", help="categories (default: all)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.command == "update":
        results = update(args.names or None)
        if args.json:
            print(json.dumps([{"category": n, "domains": c, "error": e}
                              for n, c, e in results], indent=2))
            return 0
        for name, count, err in results:
            if err:
                print("  %-10s FAILED  %s" % (name, err))
            else:
                print("  %-10s %s domains" % (name, f"{count:,}"))
        return 0

    rows = status()
    if args.json:
        print(json.dumps([{"category": n, "domains": c, "updated": t}
                          for n, c, t in rows], indent=2))
        return 0
    print("  %-10s %12s  %s" % ("CATEGORY", "DOMAINS", "UPDATED"))
    for name, count, mtime in rows:
        if count is None:
            print("  %-10s %12s  %s" % (name, "-", "not cached"))
        else:
            print("  %-10s %12s  %s" % (
                name, f"{count:,}",
                time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
