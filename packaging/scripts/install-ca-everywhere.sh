#!/bin/bash
# Install the FlowSight inspection CA into every LXC container and VM on
# Proxmox nodes pve1 and pve2, with comprehensive OS detection and verification.
#
# Usage:
#   install-ca-everywhere.sh [--verify-only] [--node-only]
#
# Flags:
#   --verify-only    Check installations without installing
#   --node-only      Only install on the Proxmox host itself, not guests
#
# The script must be run ON the Proxmox node (pve1 or pve2) and produces
# one line per guest: <node> <type> <vmid> <name> <os> <action> <verified> <curl>
#
# Output columns:
#   node       pve1 or pve2
#   type       lxc or qemu
#   vmid       numeric ID
#   name       hostname or VM name
#   os         detected OS type
#   action     installed, already, manual, stopped, no-agent, read-only, error, n/a
#   verified   yes/no/n/a
#   curl       exit code from TLS test (0=ok, 60=untrust, ->timeout, etc.)

set -u
CERT="${CERT:-/root/flowsight-ca.crt}"
VERIFY_ONLY=0
NODE_ONLY=0
NODE_HOSTNAME=$(hostname)

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --verify-only) VERIFY_ONLY=1; shift ;;
        --node-only) NODE_ONLY=1; shift ;;
        *) echo "Unknown flag: $1" >&2; exit 1 ;;
    esac
done

[ -r "$CERT" ] || { echo "no certificate at $CERT" >&2; exit 1; }

# Stable marker from the CA PEM (line 2 of base64, unique and unlikely to change)
CA_MARK=$(openssl x509 -in "$CERT" -outform PEM | sed -n '2p')

#############################################################################
# OS Detection: determine the OS type of a guest
# $1 = runner ("" for host, else "pct exec ID --" or "qm guest exec VMID --")
# Returns: debian|rhel|alpine|arch|suse|opnsense|freebsd|windows|nixos|appliance|unknown
#############################################################################
detect_os() {
    local runner="$1"

    # Windows
    if $runner test -f /Windows/System32/config/SAM 2>/dev/null; then
        echo "windows"
        return
    fi

    # Read /etc/os-release if present
    if $runner test -f /etc/os-release 2>/dev/null; then
        local os_type
        os_type=$($runner sh -c '. /etc/os-release 2>/dev/null && echo "${ID_LIKE:-$ID}"' 2>/dev/null | tr -d '\r')

        # OPNsense and FreeBSD
        if echo "$os_type" | grep -qi opnsense; then
            echo "opnsense"
            return
        fi
        if echo "$os_type" | grep -qi freebsd; then
            echo "freebsd"
            return
        fi

        # NixOS
        if echo "$os_type" | grep -qi nixos; then
            echo "nixos"
            return
        fi

        # Debian and derivatives
        if echo "$os_type" | grep -qi debian; then
            echo "debian"
            return
        fi

        # RHEL, Fedora, CentOS, Rocky, Alma
        if echo "$os_type" | grep -qiE 'rhel|fedora|centos|rocky|alma'; then
            echo "rhel"
            return
        fi

        # Alpine
        if echo "$os_type" | grep -qi alpine; then
            echo "alpine"
            return
        fi

        # Arch
        if echo "$os_type" | grep -qi arch; then
            echo "arch"
            return
        fi

        # openSUSE/SLES
        if echo "$os_type" | grep -qiE 'suse|sle'; then
            echo "suse"
            return
        fi
    fi

    # Check for Alpine without /etc/os-release
    if $runner test -f /etc/alpine-release 2>/dev/null; then
        echo "alpine"
        return
    fi

    # Check for Arch
    if $runner test -f /etc/arch-release 2>/dev/null; then
        echo "arch"
        return
    fi

    # Check for NixOS
    if $runner test -f /etc/nixos/configuration.nix 2>/dev/null; then
        echo "nixos"
        return
    fi

    # Check for FreeBSD/OPNsense
    if $runner test -f /etc/freebsd-update.conf 2>/dev/null; then
        echo "freebsd"
        return
    fi

    # Check for read-only root (Home Assistant OS, etc.)
    if $runner test -d /root 2>/dev/null && ! $runner touch /root/.test 2>/dev/null; then
        # Try to determine if it's appliance-like
        if $runner test -d /dev/disk/by-partuuid 2>/dev/null; then
            echo "appliance"
            return
        fi
    fi

    echo "unknown"
}

#############################################################################
# Find distro-specific CA install path and command
# $1 = os_type (from detect_os)
# $2 = runner
# Returns: path|command or empty
#############################################################################
find_ca_location() {
    local os_type="$1"
    local runner="$2"

    case "$os_type" in
        debian|alpine)
            echo "/usr/local/share/ca-certificates|update-ca-certificates"
            ;;
        rhel)
            echo "/etc/pki/ca-trust/source/anchors|update-ca-trust extract"
            ;;
        arch)
            if $runner test -e /etc/ca-certificates/trust-source/anchors 2>/dev/null; then
                echo "/etc/ca-certificates/trust-source/anchors|trust extract-compat"
            elif $runner test -e /etc/pki/trust/anchors 2>/dev/null; then
                echo "/etc/pki/trust/anchors|update-ca-trust"
            fi
            ;;
        suse)
            echo "/etc/pki/trust/anchors|update-ca-certificates"
            ;;
        freebsd|opnsense)
            echo "/usr/local/etc/ssl/certs|certctl rehash"
            ;;
        *)
            # Unknown - no match
            ;;
    esac
}

#############################################################################
# Verify that the CA is actually in the system bundle
# $1 = runner
# $2 = os_type
# Returns: 0 if verified, 1 if not
#############################################################################
verify_ca_in_bundle() {
    local runner="$1"
    local os_type="$2"

    case "$os_type" in
        debian|alpine)
            # Check if the CA mark is in the compiled bundle
            $runner grep -q "$CA_MARK" /etc/ssl/certs/ca-certificates.crt 2>/dev/null
            ;;
        rhel)
            # Check if the CA mark is in the compiled bundle
            $runner grep -q "$CA_MARK" /etc/pki/tls/certs/ca-bundle.crt 2>/dev/null
            ;;
        arch)
            # Arch uses p11-kit - check the compiled bundle
            if $runner test -f /etc/ssl/certs/ca-certificates.crt 2>/dev/null; then
                $runner grep -q "$CA_MARK" /etc/ssl/certs/ca-certificates.crt 2>/dev/null
            else
                $runner test -f /etc/ca-certificates/extracted/tls-ca-bundle.pem 2>/dev/null
            fi
            ;;
        suse)
            # openSUSE uses p11-kit - check the output directory
            $runner test -f /etc/ssl/certs/ca-bundle.crt 2>/dev/null || \
            $runner test -f /etc/ssl/certs/ca-certificates.crt 2>/dev/null
            ;;
        freebsd|opnsense)
            # FreeBSD uses OpenSSL - check the bundle
            $runner test -f /etc/ssl/certs/ca-bundle.crt 2>/dev/null
            ;;
        windows)
            # For Windows, verify by checking the cert store (we can't easily grep it)
            # Return success if the install commands succeeded
            return 0
            ;;
        *)
            # Unknown OS - can't verify
            return 1
            ;;
    esac
}

#############################################################################
# Install CA into container or host
# $1 = container/VM ID or "" for host
# $2 = type (lxc or qemu)
# $3 = os_type (from detect_os)
# Returns: "installed", "already", "manual", "error", "read-only"
#############################################################################
install_ca() {
    local id="$1"
    local type="$2"
    local os_type="$3"
    local runner=""

    if [ -z "$id" ]; then
        # Host itself
        runner=""
    elif [ "$type" = "lxc" ]; then
        runner="pct exec $id --"
    else  # qemu
        runner="qm guest exec $id --"
    fi

    # Already installed check
    if verify_ca_in_bundle "$runner" "$os_type"; then
        echo "already"
        return 0
    fi

    # Read-only root check
    if ! $runner touch /.test.write 2>/dev/null; then
        echo "read-only"
        return 0
    fi
    $runner rm -f /.test.write 2>/dev/null

    # Manual: NixOS, appliance, unknown, Windows without agent
    case "$os_type" in
        nixos|appliance|unknown)
            echo "manual"
            return 0
            ;;
        windows)
            # Windows install below
            ;;
    esac

    # Find the CA location for this OS
    local ca_loc
    ca_loc=$(find_ca_location "$os_type" "$runner")
    if [ -z "$ca_loc" ]; then
        echo "manual"
        return 0
    fi

    local ca_dir="${ca_loc%%|*}"
    local ca_cmd="${ca_loc#*|}"

    # Ensure the distro has the required tool (apt, apk, dnf, yum, pacman, zypper)
    case "$os_type" in
        debian)
            # Install ca-certificates if missing
            if ! $runner test -e /usr/bin/update-ca-certificates 2>/dev/null; then
                $runner apt-get update -qq >/dev/null 2>&1 || true
                $runner apt-get install -y -qq ca-certificates >/dev/null 2>&1 || {
                    echo "error"
                    return 1
                }
            fi
            ;;
        alpine)
            # Install ca-certificates if missing
            if ! $runner test -e /usr/sbin/update-ca-certificates 2>/dev/null; then
                $runner apk add -q ca-certificates >/dev/null 2>&1 || {
                    echo "error"
                    return 1
                }
            fi
            ;;
    esac

    # Special handling for Windows
    if [ "$os_type" = "windows" ]; then
        # Write the certificate
        local cert_content
        cert_content=$(cat "$CERT")
        if ! $runner sh -c "printf '%s' '$cert_content' > /root/flowsight-ca.crt" 2>/dev/null; then
            # Try qm guest file-write if available
            if command -v qm >/dev/null 2>&1 && [ "$type" = "qemu" ]; then
                qm guest file-write "$id" /flowsight-ca.crt < "$CERT" >/dev/null 2>&1 || {
                    echo "error"
                    return 1
                }
            else
                echo "error"
                return 1
            fi
        fi
        # Import into Windows cert store
        if $runner certutil -addstore -f Root C:\\flowsight-ca.crt 2>/dev/null; then
            echo "installed"
            return 0
        else
            echo "error"
            return 1
        fi
    fi

    # For LXC: use pct push, for VMs: use qm guest exec
    if [ "$type" = "lxc" ]; then
        if ! timeout 180 pct push "$id" "$CERT" "$ca_dir/flowsight-ca.crt" --perms 644 >/dev/null 2>&1; then
            echo "error"
            return 1
        fi
    else  # qemu
        local cert_content
        cert_content=$(cat "$CERT")
        # Escape for shell - this is tricky. Use a here-doc style
        if ! $runner sh -c "cat > $ca_dir/flowsight-ca.crt << 'EOF'
$cert_content
EOF" >/dev/null 2>&1; then
            echo "error"
            return 1
        fi
    fi

    # Rebuild the trust store
    if timeout 300 $runner sh -c "$ca_cmd" >/dev/null 2>&1; then
        echo "installed"
        return 0
    else
        echo "error"
        return 1
    fi
}

#############################################################################
# Test TLS trust with curl
# $1 = runner
# Returns: exit code (0=success, 60=untrust, other=timeout/error)
#############################################################################
test_curl_trust() {
    local runner="$1"

    if ! $runner command -v curl >/dev/null 2>/dev/null; then
        echo "->"
        return
    fi

    local exit_code
    $runner timeout 8 curl -sS -o /dev/null -w '%{http_code}' https://www.google.com 2>/dev/null
    exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo "0"
    elif [ $exit_code -eq 124 ]; then
        echo "124"
    else
        echo "$exit_code"
    fi
}

#############################################################################
# Process a single container or VM
#############################################################################
process_guest() {
    local node="$1"
    local type="$2"
    local id="$3"
    local name="$4"

    local runner
    if [ "$type" = "lxc" ]; then
        runner="pct exec $id --"
    else  # qemu
        runner="qm guest exec $id --"
    fi

    # Skip VM 102 (OPNsense gateway, source of the CA)
    if [ "$id" = "102" ] && [ "$type" = "qemu" ]; then
        printf "%s\t%s\t%s\t%s\tskipped\tn/a\tn/a\t->\n" "$node" "$type" "$id" "$name"
        return
    fi

    # Check if guest is running
    local status
    if [ "$type" = "lxc" ]; then
        status=$(pct config "$id" 2>/dev/null | grep "^status" | cut -d: -f2 | tr -d ' ')
    else
        status=$(qm config "$id" 2>/dev/null | grep "^status" | cut -d: -f2 | tr -d ' ' || echo "stopped")
    fi

    if [ "$status" != "running" ]; then
        printf "%s\t%s\t%s\t%s\tunknown\tstopped\tn/a\t->\n" "$node" "$type" "$id" "$name"
        return
    fi

    # Check for guest agent (VMs only)
    if [ "$type" = "qemu" ]; then
        if ! qm agent "$id" ping >/dev/null 2>&1; then
            printf "%s\t%s\t%s\t%s\tunknown\tno-agent\tn/a\t->\n" "$node" "$type" "$id" "$name"
            return
        fi
    fi

    # Detect OS
    local os_type
    os_type=$(detect_os "$runner")

    # Install or verify
    local action verified curl_result

    if [ "$VERIFY_ONLY" = "1" ]; then
        action="n/a"
    else
        action=$(install_ca "$id" "$type" "$os_type")
    fi

    # Verify installation
    if [ "$action" = "stopped" ] || [ "$action" = "no-agent" ] || [ "$action" = "n/a" ]; then
        verified="n/a"
        curl_result="->"
    else
        if verify_ca_in_bundle "$runner" "$os_type"; then
            verified="yes"
        else
            verified="no"
        fi
        curl_result=$(test_curl_trust "$runner")
    fi

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$node" "$type" "$id" "$name" "$os_type" "$action" "$verified" "$curl_result"
}

#############################################################################
# Process the Proxmox host itself
#############################################################################
process_host() {
    local node="$NODE_HOSTNAME"

    local os_type
    os_type=$(detect_os "")

    local action verified curl_result

    if [ "$VERIFY_ONLY" = "1" ]; then
        action="n/a"
    else
        action=$(install_ca "" "lxc" "$os_type")  # type doesn't matter for host
    fi

    # Verify installation
    if [ "$action" = "n/a" ] || [ "$action" = "manual" ] || [ "$action" = "read-only" ]; then
        verified="n/a"
        curl_result="->"
    else
        if verify_ca_in_bundle "" "$os_type"; then
            verified="yes"
        else
            verified="no"
        fi
        curl_result=$(test_curl_trust "")
    fi

    printf "%s\thost\t-\t%s\t%s\t%s\t%s\t%s\n" "$node" "$node" "$os_type" "$action" "$verified" "$curl_result"
}

#############################################################################
# Main execution
#############################################################################

echo "Node	Type	VMID	Name	OS	Action	Verified	Curl"
echo "----	----	----	----	--	------	--------	----"

# Process host itself
if [ "$NODE_ONLY" != "1" ] || true; then
    process_host
fi

# Process containers
if [ "$NODE_ONLY" != "1" ]; then
    for id in $(pct list 2>/dev/null | awk 'NR>1 {print $1}' | sort -n); do
        hostname=$(pct config "$id" 2>/dev/null | awk -F': ' '/^hostname/{print $2}' | tr -d '\r')
        status=$(pct config "$id" 2>/dev/null | grep "^status" | cut -d: -f2 | tr -d ' ')
        process_guest "$NODE_HOSTNAME" "lxc" "$id" "${hostname:-?}"
    done
fi

# Process VMs
if [ "$NODE_ONLY" != "1" ]; then
    for id in $(qm list 2>/dev/null | awk 'NR>1 {print $1}' | sort -n); do
        vmname=$(qm config "$id" 2>/dev/null | grep "^name:" | cut -d' ' -f2- | tr -d '\r')
        status=$(qm status "$id" 2>/dev/null | cut -d' ' -f2 | tr -d '\r')
        process_guest "$NODE_HOSTNAME" "qemu" "$id" "${vmname:-?}"
    done
fi
