#!/usr/bin/env bash
# Record the cellrun demo transcript from REAL runs.
# Usage: bash scripts/record-demo.sh
# Writes demo/transcript.txt - the source of truth for scripts/make-gif.py.
# Each screen in the transcript starts with "$ " (the typed command);
# following lines are that command's real output. Title/end cards start
# with "### ".
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# Short `cellrun` shim so the transcript shows clean commands, not a path.
mkdir -p "$ROOT/demo/bin"
ln -sf "$ROOT/dist/cli.js" "$ROOT/demo/bin/cellrun"
chmod +x "$ROOT/dist/cli.js"
export PATH="$ROOT/demo/bin:$PATH"
BIN="cellrun"
OUT="$ROOT/demo/transcript.txt"
: > "$OUT"

# A temp CELLRUN_HOME keeps the demo out of the author's real audit log.
export CELLRUN_HOME="$ROOT/demo/.cellrun-home"
rm -rf "$CELLRUN_HOME"

run_screen() {
  # $1 = command line to print and run (evaluated by bash)
  echo "\$ $1" >> "$OUT"
  eval "$1" >> "$OUT" 2>&1 || true
  echo "" >> "$OUT"
}

{
  echo "### TITLE: cellrun - one task, one fresh cell"
  echo ""
} >> "$OUT"

run_screen "$BIN run -- node -e \"console.log('hello from a cell')\""
run_screen "$BIN run -- sh -c \"echo HOME=\\\$HOME; env | grep -i -E 'key|token|secret' || echo no-secrets-visible\""
run_screen "$BIN run -- sh -c \"curl -m 3 -s https://example.com >/dev/null && echo reachable || echo no-network\""
run_screen "$BIN sanitize fixtures/tool-output-injection.json"
run_screen "$BIN run --sanitize fixtures/tool-output-injection.json -- node -e \"console.log('never runs')\""
run_screen "$BIN cells"

{
  echo "### END: cellrun 0.1.0 - MIT - github.com/techdevfun/cellrun"
  echo ""
} >> "$OUT"

echo "transcript written to $OUT"
wc -l "$OUT"
