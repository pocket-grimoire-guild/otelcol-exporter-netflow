#!/usr/bin/env bash
# Reject a selected `go test -v` log that skipped or selected no tests.
set -euo pipefail

if [[ $# != 1 && $# != 2 ]]; then
  echo 'usage: assert-go-tests.sh LOG [EXPECTED_TOP_LEVEL_TESTS]' >&2
  exit 2
fi
log=$1
expected=${2:-1}
[[ -f $log && ! -L $log ]] || { echo "test log is not a regular file: $log" >&2; exit 1; }
[[ $expected =~ ^[1-9][0-9]*$ ]] || { echo 'expected test count must be a positive integer' >&2; exit 2; }
passed=$(grep -c '^--- PASS:' "$log" || true)
all_passed=$(grep -c '^[[:space:]]*--- PASS:' "$log" || true)
skipped=$(grep -c '^[[:space:]]*--- SKIP:' "$log" || true)
failed=$(grep -c '^[[:space:]]*--- FAIL:' "$log" || true)
printf 'tests=%d subtests=%d skipped=%d failed=%d expected=%d\n' "$passed" "$((all_passed - passed))" "$skipped" "$failed" "$expected"
if (( passed != expected || skipped != 0 || failed != 0 )); then
  echo "selected test output rejected: top_level_pass=$passed skip=$skipped fail=$failed expected=$expected" >&2
  exit 1
fi
