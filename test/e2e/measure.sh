#!/bin/bash
# Measure FlowSight performance at three scales.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RESULTS_FILE="$REPO_ROOT/test/e2e/benchmark-results.json"
TEMP_DIR="${TMPDIR:-/tmp}/flowsight-measure-$$"

# Build tools
echo "Building tools..."
go build -o /tmp/fsload "$REPO_ROOT/cmd/fsload"
go build -o /tmp/fsbench "$REPO_ROOT/cmd/fsbench"
go build -o /tmp/flowsightd "$REPO_ROOT/cmd/flowsightd"

trap 'rm -rf "$TEMP_DIR"' EXIT

# Define measurement scales
SCALES=(
    "50:7:100"       # 50 devices, 7 days, 100 flows/device/day
    "500:30:100"     # 500 devices, 30 days, 100 flows/device/day
    "2000:90:50"     # 2000 devices, 90 days, 50 flows/device/day (reduced to avoid timeout)
)

declare -a ALL_RESULTS

for SCALE in "${SCALES[@]}"; do
    IFS=':' read DEVICES DAYS FLOWS_PER_DAY <<< "$SCALE"

    DATA_DIR="$TEMP_DIR/scale-${DEVICES}x${DAYS}d"
    PORT=$((8800 + DEVICES / 100))

    echo ""
    echo "=== Measuring: $DEVICES devices, $DAYS days, $FLOWS_PER_DAY flows/device/day ==="
    echo "Data dir: $DATA_DIR"

    # Generate data
    echo "Generating test data..."
    mkdir -p "$DATA_DIR"
    /tmp/fsload -devices="$DEVICES" -days="$DAYS" -flows-per-device-per-day="$FLOWS_PER_DAY" -out="$DATA_DIR"

    # Get DB size
    DB_SIZE=$(du -sh "$DATA_DIR/flowsight.db" | awk '{print $1}')
    DB_SIZE_BYTES=$(stat -f%z "$DATA_DIR/flowsight.db" 2>/dev/null || stat -c%s "$DATA_DIR/flowsight.db" 2>/dev/null)

    # Run benchmark
    echo "Running benchmarks on port $PORT..."
    /tmp/fsbench -data-dir="$DATA_DIR" -port="$PORT" -mem-limit-mb=256 > "$TEMP_DIR/bench-$DEVICES.txt" 2>&1

    # Parse results
    SCALE_RESULT="$DEVICES devices / $DAYS days / $FLOWS_PER_DAY flows:
    DB size: $DB_SIZE ($DB_SIZE_BYTES bytes)"

    echo "$SCALE_RESULT"
    ALL_RESULTS+=("$SCALE_RESULT")

    # Clean up for next iteration
    rm -rf "$DATA_DIR"
done

# Print summary
echo ""
echo "========================================="
echo "Measurement Summary"
echo "========================================="
for result in "${ALL_RESULTS[@]}"; do
    echo "$result"
done

echo ""
echo "Full benchmark output saved in:"
for f in "$TEMP_DIR"/bench-*.txt; do
    if [ -f "$f" ]; then
        echo "  $f"
        echo "---"
        cat "$f" | head -50
    fi
done
