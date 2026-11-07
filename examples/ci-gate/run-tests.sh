#!/usr/bin/env bash
# Run a project's test suite inside a fresh cell.
# Usage: examples/ci-gate/run-tests.sh [project-dir] [test-command...]
# Defaults: current directory, "npm test".
set -u

DIR="${1:-.}"
shift || true
TEST_CMD=("$@")
if [ "${#TEST_CMD[@]}" -eq 0 ]; then
  TEST_CMD=(npm test)
fi

cellrun run --copy "$DIR" -- "${TEST_CMD[@]}"
echo "cell exit code: $?"
