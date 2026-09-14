#!/usr/bin/env bash
# Focused fail-closed checks for the tier runner's selection guards.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"
tmp=$(mktemp -d /tmp/netflow-ci-runner-test.XXXXXX)
trap 'rm -rf -- "$tmp"' EXIT

printf '%s\n' '=== RUN TestPass' '--- PASS: TestPass (0.00s)' >"$tmp/pass.log"
scripts/ci/assert-go-tests.sh "$tmp/pass.log" 1 >/dev/null

printf '%s\n' '--- PASS: TestPass (0.00s)' '    --- SKIP: TestPass/opt-in (0.00s)' >"$tmp/skip.log"
if scripts/ci/assert-go-tests.sh "$tmp/skip.log" 1 >/dev/null 2>&1; then
  echo 'skip fixture unexpectedly passed' >&2
  exit 1
fi

printf '%s\n' 'ok' 'PASS' >"$tmp/empty.log"
if scripts/ci/assert-go-tests.sh "$tmp/empty.log" 1 >/dev/null 2>&1; then
  echo 'zero-test fixture unexpectedly passed' >&2
  exit 1
fi

term_pid=$tmp/term.pid
set +e
TERM_PID_FILE="$term_pid" python3 scripts/ci/capture.py --output "$tmp/term.log" --max-bytes 64 -- python3 -c 'import os,subprocess,time; child=subprocess.Popen(["python3","-c","import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)"]); open(os.environ["TERM_PID_FILE"],"w").write(str(child.pid)); print("x"*4096,flush=True); time.sleep(60)'
capture_status=$?
set -e
[[ $capture_status == 125 ]] || {
  echo "TERM-resistant capture fixture returned $capture_status, want 125" >&2
  exit 1
}
child_pid=$(<"$term_pid")
for _ in {1..30}; do
  if ! kill -0 "$child_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
if kill -0 "$child_pid" 2>/dev/null; then
  echo "TERM-resistant descendant survived capture cleanup: $child_pid" >&2
  exit 1
fi

if NETFLOW_INTEROP_LANES=pmacct env -u NFACCTD_BINARY scripts/ci/run-tier.sh interop >/dev/null 2>&1; then
  echo 'missing selected consumer unexpectedly passed' >&2
  exit 1
fi

echo 'PASS: runner rejects missing selected tools, zero-test output, and skipped tests'
