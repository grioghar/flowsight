#!/bin/bash
# Build a MAC -> guest identity map from Proxmox and publish it to the firewall.
#
# Virtual NICs all share the Proxmox OUI, so MAC-vendor lookup says
# "Proxmox Server Solutions GmbH" for every VM and container and tells you
# nothing. Proxmox itself knows exactly which MAC belongs to which guest, and
# what that guest is called - this exports that so Flowsight can name them.
set -euo pipefail

OUT="${1:-/tmp/flowsight-hostmap.json}"

{
  echo '{'
  first=1
  for id in $(qm list 2>/dev/null | awk 'NR>1{print $1}'); do
    name=$(qm config "$id" 2>/dev/null | awk -F': ' '/^name:/{print $2}')
    status=$(qm status "$id" 2>/dev/null | awk '{print $2}')
    qm config "$id" 2>/dev/null | grep -oE '^net[0-9]+: [^,]*' | while read -r line; do
      mac=$(echo "$line" | grep -oE '[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}')
      [ -n "$mac" ] || continue
      printf '%s"%s":{"kind":"vm","id":"%s","name":"%s","status":"%s"}\n' \
        "$( [ $first -eq 1 ] && echo '' || echo ',' )" \
        "$(echo "$mac" | tr 'a-z' 'A-Z')" "$id" "${name:-vm-$id}" "${status:-unknown}"
      first=0
    done
  done
  for id in $(pct list 2>/dev/null | awk 'NR>1{print $1}'); do
    name=$(pct config "$id" 2>/dev/null | awk -F': ' '/^hostname:/{print $2}')
    status=$(pct status "$id" 2>/dev/null | awk '{print $2}')
    pct config "$id" 2>/dev/null | grep -oE '^net[0-9]+: .*' | while read -r line; do
      mac=$(echo "$line" | grep -oE '[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}')
      [ -n "$mac" ] || continue
      printf ',"%s":{"kind":"ct","id":"%s","name":"%s","status":"%s"}\n' \
        "$(echo "$mac" | tr 'a-z' 'A-Z')" "$id" "${name:-ct-$id}" "${status:-unknown}"
    done
  done
  echo '}'
} | python3 -c "
import sys,json,re
raw=sys.stdin.read()
# The shell loop emits one object per line with leading commas; normalise here
# rather than fighting quoting in bash.
entries={}
for m in re.finditer(r'\"([0-9A-F:]{17})\":(\{[^}]*\})', raw):
    entries[m.group(1)]=json.loads(m.group(2))
print(json.dumps(entries, indent=1, sort_keys=True))
" > "$OUT"

echo "wrote $(python3 -c "import json;print(len(json.load(open('$OUT'))))" ) entries to $OUT"
