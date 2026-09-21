#!/bin/sh
#
# Render the FlowSight manual: one PDF with every chapter, one PDF per
# chapter, and a self-contained HTML copy. Markdown in, pandoc + WeasyPrint out.
#
#   build-docs.sh <version> [out dir]      (default out dir: dist/<version>/docs)
#
# Needs pandoc and a python with weasyprint on PATH (or $WEASYPRINT pointing
# at the interpreter, e.g. /opt/docs-venv/bin/python). A Debian host:
#   apt install pandoc fonts-dejavu python3-venv libpango-1.0-0 libpangoft2-1.0-0
#   python3 -m venv /opt/docs-venv && /opt/docs-venv/bin/pip install weasyprint
#
# Output:
#   flowsight-manual-<version>.pdf           the whole manual, chapters in order
#   chapters/<nn>-<name>-<version>.pdf       one file per chapter
#   html/*.html                              the same as HTML (linked, offline)
#   md/*.md                                  the sources, for the package
set -eu
# pandoc and weasyprint read arguments and files in the locale's encoding.
export LC_ALL=C.UTF-8 LANG=C.UTF-8
VERSION="${1:?version}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="${2:-$ROOT/dist/$VERSION/docs}"
DOCS="$ROOT/docs"
PY="${WEASYPRINT:-python3}"
CSS="$HERE/docs.css"

# Chapter order. The file name becomes the chapter slug.
CHAPTERS="README GETTING-STARTED CONCEPTS USER-GUIDE POLICY INTERCEPTION CONFIGURATION API OPERATIONS SECURITY LICENSING ARCHITECTURE RELEASING ROADMAP"

command -v pandoc >/dev/null || { echo "pandoc not found" >&2; exit 1; }
"$PY" -c 'import weasyprint' 2>/dev/null || { echo "weasyprint not importable by $PY (set WEASYPRINT)" >&2; exit 1; }

rm -rf "$OUT"; mkdir -p "$OUT/chapters" "$OUT/html" "$OUT/md"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
DATE="$(date -u +%Y-%m-%d)"

title_of() { sed -n 's/^# //p' "$DOCS/$1.md" | head -1; }

# Rewrite cross links so they resolve inside the HTML set and the merged PDF.
prep() { # file slug -> stdout
    sed -E 's|\]\(([A-Z-]+)\.md(#[^)]*)?\)|](\1.html\2)|g' "$DOCS/$1.md"
}

n=0
ALL="$WORK/all.md"
: > "$ALL"
for c in $CHAPTERS; do
    n=$((n+1)); nn=$(printf '%02d' $n)
    t="$(title_of "$c")"
    cp "$DOCS/$c.md" "$OUT/md/$c.md"
    prep "$c" > "$WORK/$c.md"
    # HTML, standalone, one file per chapter
    pandoc "$WORK/$c.md" -f gfm -t html5 -s --toc --toc-depth=2 --css docs.css \
        -M title="$t" -M subtitle="FlowSight $VERSION" -M date="$DATE" -o "$OUT/html/$c.html"
    # PDF per chapter
    pandoc "$WORK/$c.md" -f gfm -t html5 -s --toc --toc-depth=2 --css "$CSS" \
        -M title="$t" -M subtitle="FlowSight $VERSION · chapter $n" -M date="$DATE" -o "$WORK/$c.html"
    "$PY" -m weasyprint "$WORK/$c.html" "$OUT/chapters/$nn-$(echo "$c" | tr 'A-Z' 'a-z')-$VERSION.pdf" 2>/dev/null
    # merged: demote headings by one level under a chapter heading
    {
        printf '\n\n<div class="chapter"></div>\n\n# %s\n\n' "$t"
        sed -E '1{/^# /d;}; s/^(#+) /\1# /' "$WORK/$c.md" | sed -E 's|\]\(([A-Z-]+)\.html(#[^)]*)?\)|](\2)|g' | sed -E 's|\]\(\)|](#)|g'
    } >> "$ALL"
done
cp "$CSS" "$OUT/html/docs.css"

pandoc "$ALL" -f gfm -t html5 -s --toc --toc-depth=2 --css "$CSS" \
    -M title="FlowSight" -M subtitle="The manual · version $VERSION" -M date="$DATE" -o "$WORK/all.html"
"$PY" -m weasyprint "$WORK/all.html" "$OUT/flowsight-manual-$VERSION.pdf" 2>/dev/null

ls -la "$OUT" "$OUT/chapters" | sed 's/^/  /'
