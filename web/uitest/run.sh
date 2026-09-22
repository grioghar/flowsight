#!/bin/sh
#
# Run the interface checks. The UI has no build step and no framework, so
# these load the real files into a bare JavaScript engine with a few stubs
# and assert on the HTML that comes out. They catch the failure that matters
# most here: a page that throws at render and leaves a blank panel.
#
# Uses JavaScriptCore on macOS (always present) or node anywhere else.
set -eu
cd "$(dirname "$0")/../.."
JSC=/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc
if [ -x "$JSC" ]; then RUN="$JSC"
elif command -v node >/dev/null; then RUN="node --experimental-vm-modules"
else echo "no JavaScript engine found" >&2; exit 1
fi
for t in web/uitest/*.js; do
    echo "== $t"
    "$RUN" "$t"
done
