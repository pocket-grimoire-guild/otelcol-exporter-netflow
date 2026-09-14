#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

go_args=()
if [[ "${1:-}" == "--race" ]]; then
	go_args=(-race)
	shift
fi
if (($# != 0)); then
	echo "usage: $0 [--race]" >&2
	exit 2
fi

# The integration tag keeps the 300-cycle process check out of ordinary
# package tests. This runner deliberately names only the leak package and a
# finite timeout; it never runs the full repository suite.
go test -v "${go_args[@]}" -tags=integration ./integration/leak \
	-run '^TestProcessLeakAcceptance$' -count=1 -timeout=15m -v
