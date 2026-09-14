#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
go_bin=${GO_BIN:-$(command -v go || true)}
if [[ -z "$go_bin" ]]; then
  printf 'go is not available on PATH (or set GO_BIN): %s\n' "$go_bin" >&2
  exit 2
fi
gomodcache=${GOMODCACHE:-$("$go_bin" env GOMODCACHE)}

if [[ ! -x "$go_bin" ]]; then
  printf 'pinned Go binary is missing or not executable: %s\n' "$go_bin" >&2
  exit 2
fi
go_version=$($go_bin version)
if [[ "$go_version" != *'go1.26.8 '* ]]; then
  printf 'expected Go 1.26.8, got: %s\n' "$go_version" >&2
  exit 2
fi
if [[ ! -s "$repo_root/config.schema.json" ]]; then
  printf 'generated schema is missing: %s\n' "$repo_root/config.schema.json" >&2
  exit 2
fi

cd "$repo_root/integration/configschema"
GOMODCACHE="$gomodcache" "$go_bin" test -mod=readonly . -count=1 -timeout=2m -v
