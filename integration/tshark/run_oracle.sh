#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"
work=$(mktemp -d /tmp/netflow-oracle.XXXXXXXXXX)
oracle_pid=
# Invoked indirectly by the EXIT trap.
# shellcheck disable=SC2317
cleanup() {
  trap '' INT TERM
  if [[ -n $oracle_pid ]]; then
    kill -TERM "$oracle_pid" 2>/dev/null || true
    wait "$oracle_pid" || true
  fi
  rm -rf -- "$work"
}
trap 'cleanup' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# go run does not forward a signal addressed only to its own PID. Build first
# and explicitly forward termination to the decoder owner, waiting for cleanup.
go build -mod=readonly -o "$work/oracle" ./integration/tshark/run_oracle.go
"$work/oracle" "$@" &
oracle_pid=$!
if wait "$oracle_pid"; then status=0; else status=$?; fi
oracle_pid=
exit "$status"
