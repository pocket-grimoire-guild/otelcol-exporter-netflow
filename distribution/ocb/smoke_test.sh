#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 4 || $1 != --binary || $3 != --fixture ]]; then
  echo 'usage: smoke_test.sh --binary /path/to/otel-netflow-collector --fixture integration/testdata/ocb/canonical.yaml' >&2
  exit 2
fi
[[ $(uname -s) == Linux ]]
export NETFLOW_OCB_BINARY
export NETFLOW_OCB_FIXTURE
NETFLOW_OCB_BINARY=$(realpath -e -- "$2")
NETFLOW_OCB_FIXTURE=$(realpath -e -- "$4")
[[ -x $NETFLOW_OCB_BINARY && -f $NETFLOW_OCB_FIXTURE ]]
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"
exec go test -mod=readonly ./integration/ocb -run '^TestCollector(Smoke|TransportIsolation)$' -count=1 -timeout=5m -v
