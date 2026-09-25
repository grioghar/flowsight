#!/bin/bash
# End-to-end regression test: start daemon, walk every page in headless Chrome, fail on errors.
set -eu

cd "$(dirname "$0")/../.."

# Configuration
DATA_DIR="${TMPDIR:-/tmp}/flowsight-e2e-$$"
PORT=8889
TIMEOUT=30
CHROME="${CHROME:-/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome}"
if ! [ -x "$CHROME" ]; then
    CHROME="$(command -v google-chrome chromium chromium-browser 2>/dev/null || echo '')"
fi

if [ -z "$CHROME" ]; then
    echo "Chrome not found. Set CHROME env var or install Chrome/Chromium." >&2
    exit 1
fi

trap 'rm -rf "$DATA_DIR"; kill %1 2>/dev/null || true' EXIT

# Ensure daemon is built
echo "Building flowsightd..."
go build -o /tmp/flowsightd-e2e ./cmd/flowsightd

# Generate minimal test data
echo "Generating test data..."
/tmp/fsload-e2e -devices=10 -days=1 -flows-per-device-per-day=10 -out="$DATA_DIR" || {
    # If fsload doesn't exist, build it
    go build -o /tmp/fsload-e2e ./cmd/fsload
    /tmp/fsload-e2e -devices=10 -days=1 -flows-per-device-per-day=10 -out="$DATA_DIR"
}

# Start daemon in background
echo "Starting daemon on port $PORT..."
/tmp/flowsightd-e2e -data-dir="$DATA_DIR" -log-level=warn &
DAEMON_PID=$!

# Wait for daemon to be ready
for i in $(seq 1 30); do
    if nc -z localhost $PORT 2>/dev/null; then
        sleep 0.5
        break
    fi
    sleep 0.5
done

if ! nc -z localhost $PORT 2>/dev/null; then
    echo "Daemon failed to start" >&2
    kill $DAEMON_PID 2>/dev/null || true
    exit 1
fi

# Fetch daemon info
echo "Getting system info..."
SYSTEM_INFO=$(curl -s http://localhost:$PORT/api/system/info || echo '{}')
PANELS=$(curl -s http://localhost:$PORT/api/system/panels 2>/dev/null || echo '[]')

# Extract token or use dummy (depends on daemon's auth mode)
TOKEN="test-token"

# Construct list of pages to test
PAGES=(
    "#findings"
    "#events"
    "#system"
    "#host/192.168.1.2"
    "#policies"
    "#overview"
)

# Add dynamic pages from panels if available
if command -v jq &>/dev/null && [ -n "$PANELS" ]; then
    while IFS= read -r hash; do
        [ -n "$hash" ] && PAGES+=("#$hash")
    done < <(echo "$PANELS" | jq -r '.[]' 2>/dev/null || true)
fi

echo "Testing ${#PAGES[@]} pages..."
PASSED=0
FAILED=0

for page in "${PAGES[@]}"; do
    echo -n "Testing $page... "

    # Use Chrome to load the page in headless mode
    CHROME_OUT=$($CHROME \
        --headless=new \
        --disable-gpu \
        --no-sandbox \
        --virtual-time-budget=8000 \
        --dump-dom \
        "http://localhost:$PORT/?token=$TOKEN$page" 2>&1 | head -5000)

    # Check for common error indicators
    if echo "$CHROME_OUT" | grep -q '<div id="view"'; then
        # Check for empty view
        VIEW=$(echo "$CHROME_OUT" | sed -n '/<div id="view">/,/<\/div>/p' | head -100)
        if [ -z "$VIEW" ] || [ "$(echo "$VIEW" | wc -c)" -lt 50 ]; then
            echo "FAIL (empty view)"
            FAILED=$((FAILED + 1))
            continue
        fi

        # Check for error boxes (class="err") that aren't "needs a license" or expected
        if echo "$CHROME_OUT" | grep -q 'class="err"'; then
            if ! echo "$CHROME_OUT" | grep 'class="err"' | grep -q -i 'license\|feature'; then
                echo "FAIL (error box)"
                FAILED=$((FAILED + 1))
                continue
            fi
        fi

        echo "OK"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL (no view)"
        FAILED=$((FAILED + 1))
    fi
done

# Contract check: ensure /api/openapi.json exists and is valid
echo "Checking OpenAPI contract..."
OPENAPI=$(curl -s http://localhost:$PORT/api/openapi.json)
if ! echo "$OPENAPI" | jq empty 2>/dev/null; then
    echo "FAIL: /api/openapi.json is not valid JSON" >&2
    exit 1
fi

# Test a few key GET endpoints from the OpenAPI spec
echo "Testing OpenAPI endpoints..."
PATHS=$(echo "$OPENAPI" | jq -r '.paths | keys[]' 2>/dev/null || echo "")
for path in $PATHS; do
    # Only test GET (simple test)
    if echo "$OPENAPI" | jq -e ".paths[\"$path\"].get" >/dev/null 2>&1; then
        # Skip paths with required parameters
        if ! echo "$path" | grep -qE '\{.*\}'; then
            HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" \
                "http://localhost:$PORT$path" || echo "000")
            if [ "$HTTP_CODE" = "000" ] || [ "$HTTP_CODE" -ge "500" ]; then
                echo "FAIL: GET $path returned $HTTP_CODE" >&2
                FAILED=$((FAILED + 1))
            fi
        fi
    fi
done

# Summary
echo ""
echo "========================================="
echo "E2E Test Results"
echo "========================================="
echo "Passed: $PASSED"
echo "Failed: $FAILED"

if [ $FAILED -gt 0 ]; then
    exit 1
fi

exit 0
