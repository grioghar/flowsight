#!/bin/sh
# Flowsight installer for machines that are not OPNsense (OPNsense uses the pkg).
#
#   curl -fsSL https://github.com/grioghar/flowsight/releases/latest/download/install.sh | sh
#   FLOWSIGHT_VERSION=1.0.0 ./install.sh          pin a version
#   ./install.sh --binary ./flowsightd            install a local build
#
set -eu
REPO="grioghar/flowsight"
VERSION="${FLOWSIGHT_VERSION:-latest}"
BIN_SRC=""
[ "${1:-}" = "--binary" ] && BIN_SRC="$2"

say() { printf '  %s\n' "$*"; }
fail() { printf '  ERROR: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = "0" ] || fail "run as root"

OS="$(uname -s | tr 'A-Z' 'a-z')"; ARCH="$(uname -m)"
case "$ARCH" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) fail "unsupported architecture $ARCH" ;; esac
case "$OS" in linux|freebsd) ;; *) fail "unsupported OS $OS" ;; esac
[ -x /usr/local/sbin/opnsense-version ] && fail "this is OPNsense: install the os-flowsight package instead"

if [ -z "$BIN_SRC" ]; then
    if [ "$VERSION" = "latest" ]; then URL="https://github.com/$REPO/releases/latest/download/flowsightd-$OS-$ARCH"
    else URL="https://github.com/$REPO/releases/download/v$VERSION/flowsightd-$OS-$ARCH"; fi
    say "downloading $URL"
    TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
    if command -v curl >/dev/null; then curl -fsSL -o "$TMP" "$URL"; else fetch -qo "$TMP" "$URL"; fi
    BIN_SRC="$TMP"
fi
install -m 755 "$BIN_SRC" /usr/local/sbin/flowsightd
say "installed /usr/local/sbin/flowsightd ($(/usr/local/sbin/flowsightd -version))"

if [ "$OS" = "freebsd" ]; then
    ETC=/usr/local/etc/flowsight
    install -d -m 755 "$ETC" /var/db/flowsight /var/log/flowsight /var/run/flowsight
    cat > /usr/local/etc/rc.d/flowsight <<'RC'
#!/bin/sh
# PROVIDE: flowsight
# REQUIRE: LOGIN
# KEYWORD: shutdown
. /etc/rc.subr
name=flowsight
rcvar=flowsight_enable
load_rc_config $name
: ${flowsight_enable:=NO}
pidfile=/var/run/flowsight/flowsightd.pid
command=/usr/sbin/daemon
command_args="-S -T flowsightd -R 5 -P /var/run/flowsight/daemon.pid -p ${pidfile} /usr/local/sbin/flowsightd -config /usr/local/etc/flowsight/flowsight.json"
run_rc_command "$1"
RC
    chmod 755 /usr/local/etc/rc.d/flowsight
else
    ETC=/etc/flowsight
    install -d -m 755 "$ETC" /var/lib/flowsight /var/log/flowsight
    cat > /lib/systemd/system/flowsight.service <<'UNIT'
[Unit]
Description=Flowsight: L7 visibility, policy and enforcement
After=network-online.target unbound.service
Wants=network-online.target
[Service]
ExecStart=/usr/local/sbin/flowsightd -config /etc/flowsight/flowsight.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
UNIT
fi

if [ ! -f "$ETC/flowsight.json" ]; then
    TOKEN="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
    printf '{\n  "api_token": "%s"\n}\n' "$TOKEN" > "$ETC/flowsight.json"
    chmod 600 "$ETC/flowsight.json"
    say "API token: $TOKEN   (kept in $ETC/flowsight.json)"
else
    say "kept existing $ETC/flowsight.json"
fi

if [ "$OS" = "freebsd" ]; then
    sysrc -q flowsight_enable=YES >/dev/null; service flowsight restart >/dev/null 2>&1 || service flowsight start
else
    systemctl daemon-reload; systemctl enable --now flowsight; systemctl restart flowsight
fi
say "running. UI: http://127.0.0.1:8080  (tunnel with: ssh -L 8080:127.0.0.1:8080 $(hostname))"
say "to reach it from the LAN, set \"bind\" in $ETC/flowsight.json; the token protects it."
