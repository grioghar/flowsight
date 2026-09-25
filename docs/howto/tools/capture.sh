#!/bin/bash
# Capture screenshots from FlowSight live instance
# Usage: ./capture.sh [page_hash] [output_name] [window_height]

set -e

CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
BASE_URL="http://127.0.0.1:8099"
OUT_DIR="/Users/grio/flowsight-howto/docs/howto/img"
HEIGHT="${3:-1200}"
WIDTH="${4:-1440}"

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $0 <page_hash> <output_name> [height] [width]"
    echo "Example: $0 'overview' 'overview' 1200 1440"
    exit 1
fi

PAGE_HASH="$1"
OUTPUT_NAME="$2"
SCREENSHOT_PATH="${OUT_DIR}/${OUTPUT_NAME}.png"

echo "Capturing: ${BASE_URL}/#${PAGE_HASH} -> ${SCREENSHOT_PATH} (${WIDTH}x${HEIGHT})"

"$CHROME" \
    --headless=new \
    --disable-gpu \
    --hide-scrollbars \
    --window-size="${WIDTH},${HEIGHT}" \
    --virtual-time-budget=12000 \
    --screenshot="${SCREENSHOT_PATH}" \
    "${BASE_URL}/#${PAGE_HASH}" 2>&1 | grep -v "CVDisplayLinkCreateWithCGDisplay failed" | grep -v "CVReturn:" | grep -v "Trying to load" || true

if [ -f "$SCREENSHOT_PATH" ]; then
    SIZE=$(ls -lh "$SCREENSHOT_PATH" | awk '{print $5}')
    echo "✓ Saved: $SIZE"
else
    echo "✗ Failed to capture"
    exit 1
fi
