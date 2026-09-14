#!/usr/bin/env bash
# Build the actual distribution with the pinned public Collector Builder.
set -euo pipefail
if [[ $# != 4 || $1 != --go || $2 != 1.26.8 || $3 != --out || -z $4 ]]; then
  echo 'usage: build.sh --go 1.26.8 --out /path/to/otel-netflow-collector' >&2
  exit 2
fi
[[ $(go env GOVERSION) == "go$2" ]]
output=$(realpath -m -- "$4")
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"
mkdir -p dist
go run go.opentelemetry.io/collector/cmd/builder@v0.160.0 --config distribution/ocb/manifest.yaml --skip-strict-versioning=false
# OCB v0.160.0 writes unformatted templates. Keep its ignored generated Go
# source compatible with the repository-wide formatting check.
gofmt -w dist/ocb/*.go
if [[ $output != "$repo/dist/ocb/otel-netflow-collector" ]]; then
  install -m 0755 -- dist/ocb/otel-netflow-collector "$output"
fi
"$output" --version
