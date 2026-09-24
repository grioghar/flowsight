#!/bin/bash
# Install the FlowSight inspection CA into every LXC container and VM on
# Proxmox nodes pve1 and pve2, with comprehensive OS detection and verification.
#
# Usage:
#   install-ca-everywhere.sh [--verify-only] [--node-only]
#
# Output: one line per guest with columns: node type vmid name os action verified curl

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

# Stable marker from the CA PEM (line 2 of base64)
CA_MARK=$(openssl x509 -in "$CERT" -outform PEM | sed -n '2p')

#############################################################################
# Exec wrapper for containers and VMs
# $1 = type (lxc or qemu)
# $2 = id
# $3 = command to run
# Returns: output of the command
#############################################################################
run_in_guest() {
    local type="$1"
    local id="$2"
    shift 2

    if [ "$type" = "lxc" ]; then
        pct exec "$id" -- "$@" 2>/dev/null
    else
        timeout 120 qm guest exec "$id" -- "$@" 2>/dev/null
    fi
}

#############################################################################
# Detect OS type
#############################################################################
detect_os() {
    local type="$1"
    local id="$2"

    # Windows check
    if run_in_guest "$type" "$id" test -f /Windows/System32/config/SAM >/dev/null 2>&1; then
        echo "windows"
        return
    fi

    # Check /etc/os-release
    if run_in_guest "$type" "$id" test -f /etc/os-release >/dev/null 2>&1; then
        local os_type
        os_type=$(run_in_guest "$type" "$id" sh -c '. /etc/os-release 2>/dev/null && echo "${ID_LIKE:-$ID}"' | tr -d '\r' | head -1)

        # Match patterns
        if echo "$os_type" | grep -qi opnsense; then echo "opnsense"; return; fi
        if echo "$os_type" | grep -qi freebsd; then echo "freebsd"; return; fi
        if echo "$os_type" | grep -qi nixos; then echo "nixos"; return; fi
        if echo "$os_type" | grep -qi debian; then echo "debian"; return; fi
        if echo "$os_type" | grep -qiE 'rhel|fedora|centos|rocky|alma'; then echo "rhel"; return; fi
        if echo "$os_type" | grep -qi alpine; then echo "alpine"; return; fi
        if echo "$os_type" | grep -qi arch; then echo "arch"; return; fi
        if echo "$os_type" | grep -qiE 'suse|sle'; then echo "suse"; return; fi
    fi

    # Specific file checks
    if run_in_guest "$type" "$id" test -f /etc/alpine-release >/dev/null 2>&1; then echo "alpine"; return; fi
    if run_in_guest "$type" "$id" test -f /etc/arch-release >/dev/null 2>&1; then echo "arch"; return; fi
    if run_in_guest "$type" "$id" test -f /etc/nixos/configuration.nix >/dev/null 2>&1; then echo "nixos"; return; fi
    if run_in_guest "$type" "$id" test -f /etc/freebsd-update.conf >/dev/null 2>&1; then echo "freebsd"; return; fi

    echo "unknown"
}

#############################################################################
# Find CA path and rebuild command
#############################################################################
find_ca_info() {
    local os_type="$1"

    case "$os_type" in
        debian|alpine)
            echo "/usr/local/share/ca-certificates|update-ca-certificates"
            ;;
        rhel)
            echo "/etc/pki/ca-trust/source/anchors|update-ca-trust extract"
            ;;
        arch)
            echo "/etc/ca-certificates/trust-source/anchors|trust extract-compat"
            ;;
        suse)
            echo "/etc/pki/trust/anchors|update-ca-certificates"
            ;;
        freebsd|opnsense)
            echo "/usr/local/etc/ssl/certs|certctl rehash"
            ;;
    esac
}

#############################################################################
# Verify CA is in bundle
#############################################################################
verify_installed() {
    local type="$1"
    local id="$2"
    local os_type="$3"

    case "$os_type" in
        debian|alpine)
            run_in_guest "$type" "$id" grep -q "$CA_MARK" /etc/ssl/certs/ca-certificates.crt 2>/dev/null && echo "yes" || echo "no"
            ;;
        rhel)
            run_in_guest "$type" "$id" grep -q "$CA_MARK" /etc/pki/tls/certs/ca-bundle.crt 2>/dev/null && echo "yes" || echo "no"
            ;;
        arch|suse)
            if run_in_guest "$type" "$id" test -f /etc/ssl/certs/ca-bundle.crt >/dev/null 2>&1; then
                run_in_guest "$type" "$id" grep -q "$CA_MARK" /etc/ssl/certs/ca-bundle.crt 2>/dev/null && echo "yes" || echo "no"
            else
                echo "no"
            fi
            ;;
        freebsd|opnsense)
            run_in_guest "$type" "$id" test -f /etc/ssl/certs/ca-bundle.crt >/dev/null 2>&1 && echo "yes" || echo "no"
            ;;
        windows)
            echo "yes"
            ;;
        *)
            echo "n/a"
            ;;
    esac
}

#############################################################################
# Install CA
#############################################################################
install_ca() {
    local type="$1"
    local id="$2"
    local os_type="$3"

    # Check if already installed
    local verify
    verify=$(verify_installed "$type" "$id" "$os_type")
    if [ "$verify" = "yes" ]; then
        echo "already"
        return 0
    fi

    # Read-only check
    if ! run_in_guest "$type" "$id" touch /.test-write 2>/dev/null; then
        run_in_guest "$type" "$id" rm -f /.test-write >/dev/null 2>&1
        echo "read-only"
        return 0
    fi
    run_in_guest "$type" "$id" rm -f /.test-write >/dev/null 2>&1

    # Manual OS types
    case "$os_type" in
        nixos|appliance|unknown)
            echo "manual"
            return 0
            ;;
    esac

    # Get CA path and command
    local ca_info
    ca_info=$(find_ca_info "$os_type")
    if [ -z "$ca_info" ]; then
        echo "manual"
        return 0
    fi

    local ca_dir="${ca_info%%|*}"
    local ca_cmd="${ca_info#*|}"

    # Install dependencies
    case "$os_type" in
        debian)
            run_in_guest "$type" "$id" apt-get update -qq >/dev/null 2>&1 || true
            run_in_guest "$type" "$id" apt-get install -y -qq ca-certificates >/dev/null 2>&1 || true
            ;;
        alpine)
            run_in_guest "$type" "$id" apk add -q ca-certificates >/dev/null 2>&1 || true
            ;;
    esac

    # Windows special handling
    if [ "$os_type" = "windows" ]; then
        local cert_b64
        cert_b64=$(base64 < "$CERT" | tr -d '\n')
        if run_in_guest "$type" "$id" bash -c "echo '$cert_b64' | base64 -d > C:\\flowsight-ca.crt" >/dev/null 2>&1; then
            if run_in_guest "$type" "$id" certutil -addstore -f Root C:\\flowsight-ca.crt >/dev/null 2>&1; then
                echo "installed"
                return 0
            fi
        fi
        echo "error"
        return 1
    fi

    # Copy cert into guest
    if [ "$type" = "lxc" ]; then
        timeout 180 pct push "$id" "$CERT" "$ca_dir/flowsight-ca.crt" --perms 644 >/dev/null 2>&1 || {
            echo "error"
            return 1
        }
    else
        # For VM: write directly
        local cert_content
        cert_content=$(cat "$CERT")
        if ! run_in_guest "$type" "$id" bash -c "cat > '$ca_dir/flowsight-ca.crt'" <<< "$cert_content" >/dev/null 2>&1; then
            echo "error"
            return 1
        fi
    fi

    # Rebuild trust store
    if timeout 300 run_in_guest "$type" "$id" sh -c "$ca_cmd" >/dev/null 2>&1; then
        echo "installed"
        return 0
    else
        echo "error"
        return 1
    fi
}

#############################################################################
# Test curl trust
#############################################################################
test_curl() {
    local type="$1"
    local id="$2"

    # Check if curl exists
    if ! run_in_guest "$type" "$id" command -v curl >/dev/null 2>&1; then
        echo "->"
        return
    fi

    # Run curl and get exit code
    run_in_guest "$type" "$id" timeout 8 curl -sS -o /dev/null https://www.google.com >/dev/null 2>&1
    local code=$?
    echo "$code"
}

#############################################################################
# Process host
#############################################################################
process_host() {
    local os_type
    os_type=$(grep "^ID=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "unknown")

    local action verified curl_result

    if [ "$VERIFY_ONLY" = "1" ]; then
        action="n/a"
    else
        # Simplified install for host
        if grep -q "$CA_MARK" /etc/ssl/certs/ca-certificates.crt 2>/dev/null; then
            action="already"
        else
            action="manual"
        fi
    fi

    if [ "$action" = "n/a" ]; then
        verified="n/a"
        curl_result="->"
    else
        if grep -q "$CA_MARK" /etc/ssl/certs/ca-certificates.crt 2>/dev/null; then
            verified="yes"
        else
            verified="no"
        fi
        if command -v curl >/dev/null 2>&1; then
            timeout 8 curl -sS -o /dev/null https://www.google.com >/dev/null 2>&1
            curl_result=$?
        else
            curl_result="->"
        fi
    fi

    printf "%s\thost\t-\t%s\t%s\t%s\t%s\t%s\n" "$NODE_HOSTNAME" "$NODE_HOSTNAME" "$os_type" "$action" "$verified" "$curl_result"
}

#############################################################################
# Process container or VM
#############################################################################
process_guest() {
    local node="$1"
    local type="$2"
    local id="$3"
    local name="$4"

    # Skip VM 102
    if [ "$id" = "102" ] && [ "$type" = "qemu" ]; then
        printf "%s\t%s\t%s\t%s\tskipped\tn/a\tn/a\t->\n" "$node" "$type" "$id" "$name"
        return
    fi

    # Check if running
    local status
    if [ "$type" = "lxc" ]; then
        status=$(pct config "$id" 2>/dev/null | grep "^status" | cut -d: -f2 | tr -d ' ')
    else
        status=$(qm status "$id" 2>/dev/null | cut -d' ' -f2)
    fi

    if [ "$status" != "running" ]; then
        printf "%s\t%s\t%s\t%s\tunknown\tstopped\tn/a\t->\n" "$node" "$type" "$id" "$name"
        return
    fi

    # Check VM agent
    if [ "$type" = "qemu" ]; then
        if ! qm agent "$id" ping >/dev/null 2>&1; then
            printf "%s\t%s\t%s\t%s\tunknown\tno-agent\tn/a\t->\n" "$node" "$type" "$id" "$name"
            return
        fi
    fi

    # Detect and process
    local os_type action verified curl_result
    os_type=$(detect_os "$type" "$id")

    if [ "$VERIFY_ONLY" = "1" ]; then
        action="n/a"
    else
        action=$(install_ca "$type" "$id" "$os_type")
    fi

    if [ "$action" = "stopped" ] || [ "$action" = "no-agent" ] || [ "$action" = "n/a" ]; then
        verified="n/a"
        curl_result="->"
    else
        verified=$(verify_installed "$type" "$id" "$os_type")
        curl_result=$(test_curl "$type" "$id")
    fi

    printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$node" "$type" "$id" "$name" "$os_type" "$action" "$verified" "$curl_result"
}

#############################################################################
# Main
#############################################################################

echo "Node	Type	VMID	Name	OS	Action	Verified	Curl"
echo "----	----	----	----	--	------	--------	----"

# Host itself
if [ "$NODE_ONLY" != "1" ] || true; then
    process_host
fi

# Containers
if [ "$NODE_ONLY" != "1" ]; then
    for id in $(pct list 2>/dev/null | awk 'NR>1 {print $1}' | sort -n); do
        hostname=$(pct config "$id" 2>/dev/null | awk -F': ' '/^hostname/{print $2}' | tr -d '\r')
        process_guest "$NODE_HOSTNAME" "lxc" "$id" "${hostname:-?}"
    done
fi

# VMs
if [ "$NODE_ONLY" != "1" ]; then
    for id in $(qm list 2>/dev/null | awk 'NR>1 {print $1}' | sort -n); do
        vmname=$(qm config "$id" 2>/dev/null | grep "^name:" | cut -d' ' -f2- | tr -d '\r')
        process_guest "$NODE_HOSTNAME" "qemu" "$id" "${vmname:-?}"
    done
fi
