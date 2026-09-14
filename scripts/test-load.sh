#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/.." && pwd)
cd "$repo_dir"

PATH="/usr/local/go/bin:$PATH" go test -tags=integration . ./internal/testpdata \
  -run '^TestLoad' -count=1 -timeout=10m "$@"
