#!/bin/bash
# End-to-end regression test: build, load data, start daemon, test pages and API.
# Exit non-zero on any failure. Gate before release: `make e2e`.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DATA_DIR="${TMPDIR:-/tmp}/flowsight-e2e-$$"
PORT=8080

trap 'rm -rf "$DATA_DIR"; kill %1 2>/dev/null || true' EXIT

cd "$REPO_ROOT"

# Build tools
echo "[1/5] Building tools..."
go build -o /tmp/fsload-e2e ./cmd/fsload
go build -o /tmp/fsbench-e2e ./cmd/fsbench
go build -o /tmp/flowsightd-e2e ./cmd/flowsightd

# Generate test data
echo "[2/5] Generating test data..."
mkdir -p "$DATA_DIR"
/tmp/fsload-e2e -devices=10 -days=1 -flows-per-device-per-day=10 -out="$DATA_DIR"

# Start daemon
echo "[3/5] Starting daemon on port $PORT..."
/tmp/flowsightd-e2e -data-dir="$DATA_DIR" -log-level=warn >/dev/null 2>&1 &
DAEMON_PID=$!

# Wait for daemon to be ready (use curl instead of nc for better portability)
READY=0
for i in {1..30}; do
    if curl -s http://localhost:$PORT/api/system/info >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.5
done

if [ $READY -eq 0 ]; then
    echo "FAIL: Daemon did not start in time"
    kill $DAEMON_PID 2>/dev/null || true
    exit 1
fi

# Test API routes
echo "[4/5] Testing API contracts..."
FAILED=0

# Test OpenAPI is valid JSON
if ! curl -s http://localhost:$PORT/api/openapi.json | grep -q '"paths"'; then
    echo "FAIL: OpenAPI not accessible or invalid"
    FAILED=1
fi

# Test key endpoints
for route in \
    "/api/system/info" \
    "/api/system/health" \
    "/api/system/panels" \
    "/api/visibility/flows?limit=10" \
    "/api/visibility/top?limit=5" \
    "/api/identity/hosts?limit=5" \
; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$PORT"$route")
    if [ "$HTTP_CODE" != "200" ]; then
        echo "FAIL: GET $route returned HTTP $HTTP_CODE"
        FAILED=1
    fi
done

# Test UI pages (if Chrome is available)
echo "[5/5] Testing UI pages..."
CHROME=""
for candidate in \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "/usr/bin/google-chrome" \
    "/usr/bin/chromium" \
; do
    if [ -x "$candidate" ] 2>/dev/null; then
        CHROME="$candidate"
        break
    fi
done

if [ -n "$CHROME" ]; then
    for page in "#findings" "#events" "#system" "#overview"; do
        URL="http://localhost:$PORT/?token=test-token$page"
        DOM=$("$CHROME" --headless=new --disable-gpu --no-sandbox \
            --virtual-time-budget=5000 --dump-dom "$URL" 2>/dev/null | head -500)

        # Check for view element (can be section or div)
        if ! echo "$DOM" | grep -q 'id="view"'; then
            echo "FAIL: Page $page has no view element"
            FAILED=1
        fi

        # Check for errors (excluding license messages)
        if echo "$DOM" | grep 'class="err"' | grep -qv -i 'license\|feature'; then
            echo "FAIL: Page $page has error box"
            FAILED=1
        fi
    done
else
    echo "  (Chrome not found; skipping page rendering tests)"
fi

# Summary
echo ""
if [ $FAILED -eq 0 ]; then
    echo "=== E2E Test PASSED ==="
    exit 0
else
    echo "=== E2E Test FAILED ==="
    kill $DAEMON_PID 2>/dev/null || true
    exit 1
fi
