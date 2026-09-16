#!/bin/sh
# Flowsight installer.
#
# Detects the platform, installs the components, and wires up services. It does
# NOT enable enforcement: policy is applied deliberately, by hand, afterwards.
#
#   ./install.sh --check     verify prerequisites, install nothing
#   ./install.sh             install
#
set -eu

SRC="$(cd "$(dirname "$0")" && pwd)"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

say()  { printf '  %s\n' "$*"; }
fail() { printf '  ERROR: %s\n' "$*" >&2; exit 1; }
warn() { printf '  WARN:  %s\n' "$*" >&2; }

# ---------------------------------------------------------------- platform
OS="$(uname -s)"
if [ -x /usr/local/sbin/opnsense-version ]; then
    PLATFORM="opnsense"; CONFDIR="/usr/local/etc/flowsight"; SVC="rc"
elif [ "$OS" = "FreeBSD" ]; then
    PLATFORM="freebsd";  CONFDIR="/usr/local/etc/flowsight"; SVC="rc"
elif [ -d /run/systemd/system ]; then
    PLATFORM="systemd";  CONFDIR="/etc/flowsight";           SVC="systemd"
else
    fail "unsupported platform: $OS (no OPNsense, FreeBSD rc, or systemd found)"
fi
BINDIR="/usr/local/sbin"
say "platform : $PLATFORM  (config $CONFDIR, services $SVC)"

# ------------------------------------------------------------ prerequisites
PY=""
for c in /usr/local/bin/python3 /usr/bin/python3 python3; do
    command -v "$c" >/dev/null 2>&1 && { PY="$(command -v "$c")"; break; }
done
[ -n "$PY" ] || fail "python3 not found"
say "python   : $PY"

"$PY" - <<'EOP' || fail "PyYAML is required by flowsight-policy (pkg install py311-yaml / apt install python3-yaml)"
import yaml  # noqa
EOP
say "pyyaml   : present"

MISSING=""
for b in unbound-control; do
    command -v "$b" >/dev/null 2>&1 || MISSING="$MISSING $b"
done
[ -n "$MISSING" ] && warn "not found:$MISSING - the matching source will report as failing until installed"

if [ "$CHECK_ONLY" = "1" ]; then
    say "check only - nothing installed"
    exit 0
fi
[ "$(id -u)" = "0" ] || fail "install must run as root"

# ------------------------------------------------------------------ install
install -d -m 755 "$CONFDIR"
install -m 755 "$SRC/collector/flowsight-collector.py"        "$BINDIR/flowsight-collector"
install -m 755 "$SRC/policy/flowsight-policy.py"              "$BINDIR/flowsight-policy"
install -m 755 "$SRC/ui/flowsight-ui.py"                      "$BINDIR/flowsight-ui"
say "installed: flowsight-collector, flowsight-policy, flowsight-ui"

if [ "$PLATFORM" = "opnsense" ] || [ "$PLATFORM" = "freebsd" ]; then
    install -m 755 "$SRC/modules/rulehygiene/flowsight-rulehygiene.py" \
                   "$BINDIR/flowsight-rulehygiene"
    say "installed: flowsight-rulehygiene (pf only)"
fi

# Never clobber an existing config - it is the operator's, not ours.
for f in collector ui; do
    if [ ! -f "$CONFDIR/$f.json" ]; then
        case "$f" in
          collector) src="$SRC/collector/collector.json.example" ;;
          ui)        src="" ;;
        esac
        [ -n "$src" ] && [ -f "$src" ] && install -m 640 "$src" "$CONFDIR/$f.json" \
            && say "config   : wrote $CONFDIR/$f.json from example"
    else
        say "config   : kept existing $CONFDIR/$f.json"
    fi
done
[ -f "$CONFDIR/policy.example.yaml" ] || \
    install -m 640 "$SRC/policy/policy.example.yaml" "$CONFDIR/policy.example.yaml"

# ------------------------------------------------------------------ services
if [ "$SVC" = "rc" ]; then
    install -m 555 "$SRC/adapters/opnsense/flowsight_collector" /usr/local/etc/rc.d/flowsight_collector
    install -m 555 "$SRC/adapters/opnsense/flowsight_ui"        /usr/local/etc/rc.d/flowsight_ui
    say "services : rc.d scripts installed (service flowsight_collector start)"
    if [ "$PLATFORM" = "opnsense" ]; then
        install -m 644 "$SRC/adapters/opnsense/www/flowsight.php" /usr/local/www/flowsight.php
        install -d -m 755 /usr/local/opnsense/mvc/app/models/OPNsense/Flowsight/Menu
        install -m 644 "$SRC/adapters/opnsense/menu/Menu.xml" \
            /usr/local/opnsense/mvc/app/models/OPNsense/Flowsight/Menu/Menu.xml
        # Editing Menu.xml alone does nothing: the menu is cached and a GUI
        # restart does not clear it.
        rm -f /var/lib/php/tmp/opnsense_menu_cache.xml
        say "opnsense : menu entry installed, menu cache invalidated"
    fi
else
    install -m 644 "$SRC/adapters/systemd/flowsight-collector.service" /etc/systemd/system/
    install -m 644 "$SRC/adapters/systemd/flowsight-ui.service"        /etc/systemd/system/
    systemctl daemon-reload
    say "services : systemd units installed (systemctl enable --now flowsight-collector)"
fi

cat <<EOT

  Installed. Nothing is running or enforcing yet.

  1. Edit $CONFDIR/collector.json - point otlp_* at your OTLP endpoint.
  2. Start the collector, then the UI.
  3. Policy is opt-in: copy policy.example.yaml to policy.yaml, run
     'flowsight-policy plan', and only then 'apply'.
EOT
