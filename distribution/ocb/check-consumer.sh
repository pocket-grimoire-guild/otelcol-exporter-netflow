#!/usr/bin/env bash
# Build and exercise the explicitly unpublished versioned consumer path.
set -euo pipefail

usage() {
  echo 'usage: check-consumer.sh [--revision COMMIT]' >&2
  exit 2
}

revision_arg=
while (($#)); do
  case $1 in
    --revision)
      (($# >= 2)) || usage
      revision_arg=$2
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
if command -v go >/dev/null 2>&1; then
  go_bin=$(command -v go)
elif [[ -x /usr/local/go/bin/go ]]; then
  go_bin=/usr/local/go/bin/go
else
  echo 'Go 1.26.8 is required (looked for /usr/local/go/bin/go and PATH)' >&2
  exit 1
fi
[[ $($go_bin version) == 'go version go1.26.8 linux/amd64' ]] || {
  echo "check-consumer.sh requires Go 1.26.8 linux/amd64: $($go_bin version)" >&2
  exit 1
}

if [[ -n $revision_arg ]]; then
  revision=$(git -C "$repo" rev-parse --verify "${revision_arg}^{commit}")
else
  revision=$(git -C "$repo" rev-parse --verify 'HEAD^{commit}')
fi
version=v0.1.0-alpha.1
module=github.com/pocket-grimoire-guild/otelcol-exporter-netflow

scratch=$(mktemp -d /tmp/otel-netflow-consumer.XXXXXX)
cleanup() {
  chmod -R u+w -- "$scratch" 2>/dev/null || true
  rm -rf -- "$scratch" 2>/dev/null || true
}
trap cleanup EXIT

proxy=$scratch/proxy
workspace=$scratch/workspace
source=$scratch/source
artifacts=$scratch/artifacts
modcache=$scratch/modcache
gocache=$scratch/gocache
mkdir -p "$proxy/$module/@v" "$workspace" "$source" "$artifacts" "$modcache/cache/download" "$gocache"

git -C "$repo" archive --format=tar "$revision" | tar -x -C "$source"

git -C "$repo" show "$revision:go.mod" > "$proxy/$module/@v/$version.mod"
commit_time=$(git -C "$repo" show -s --format=%cI "$revision")
printf '{"Version":"%s","Time":"%s"}\n' "$version" "$commit_time" > "$proxy/$module/@v/$version.info"

cp -- "$source/distribution/ocb/consumer/manifest.yaml" "$workspace/manifest.yaml"
cp -- "$source/distribution/ocb/config-consumer-30s.yaml" "$workspace/config-consumer-30s.yaml"

# Seed an isolated module cache with the prefilled public cache when one is
# available. The staged exporter is always served by the file proxy above.
prefilled_cache=${GOMODCACHE:-}
if [[ -z $prefilled_cache ]]; then
  prefilled_cache=$repo/../cache/go-mod
fi
cache_mode='public proxy fallback (no prefilled cache found)'
if [[ -d $prefilled_cache/cache/download ]]; then
  cp -a -- "$prefilled_cache/cache/download/." "$modcache/cache/download/"
  # A prefilled cache may contain another revision of this module. Remove its
  # proxy entries before the staged zip is used so the selected revision is
  # the only possible exporter source.
  rm -rf -- "$modcache/cache/download/$module"
  cache_mode='prefilled public module cache seeded; public proxy fallback permitted'
fi
go_dir=$(dirname -- "$go_bin")
export PATH="$go_dir:$PATH"
export GOTOOLCHAIN=local
export GOENV=off
export GOWORK=off
unset GOFLAGS GOPRIVATE GONOPROXY
export GOPATH="$scratch/gopath"
export GOMODCACHE="$modcache"
export GOCACHE="$gocache"
export GOPROXY="file://$proxy,https://proxy.golang.org,direct"
export GOSUMDB=sum.golang.org
export GONOSUMDB="$module"

# Use the Go module zip implementation so nested modules, such as the
# receiver-only test module, are excluded with the same rules as a public Go
# proxy. A plain git archive is not a valid module zip for this repository.
zipper=$scratch/zipper
mkdir -p "$zipper"
printf '%s\n' 'module local/zipper' 'go 1.26.0' '' 'require golang.org/x/mod v0.41.0' > "$zipper/go.mod"
cat > "$zipper/main.go" <<'EOF'
package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"
)

func main() {
	repo := flag.String("repo", "", "Git repository root")
	revision := flag.String("revision", "", "Git revision")
	path := flag.String("module", "", "module path")
	version := flag.String("version", "", "module version")
	out := flag.String("out", "", "output zip")
	flag.Parse()
	file, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	if err := modzip.CreateFromVCS(file, module.Version{Path: *path, Version: *version}, *repo, *revision, ""); err != nil {
		_ = file.Close()
		panic(err)
	}
	if err := file.Close(); err != nil {
		panic(err)
	}
	fmt.Println(*out)
}
EOF
(
  cd "$zipper"
  "$go_bin" mod download golang.org/x/mod@v0.41.0
  "$go_bin" run . --repo "$repo" --revision "$revision" --module "$module" --version "$version" \
    --out "$proxy/$module/@v/$version.zip"
)

printf 'versioned consumer check\n'
printf 'source revision: %s\n' "$revision"
printf 'staged module: %s %s\n' "$module" "$version"
printf 'toolchain: %s\n' "$($go_bin version)"
printf 'OCB: v0.160.0 (strict version checks)\n'
printf 'dependency mode: %s\n' "$cache_mode"
printf 'workspace/cache: %s / %s\n' "$workspace" "$modcache"
printf 'archived source tree: %s\n' "$source"
printf 'staged exporter zip sha256: %s\n' "$(sha256sum "$proxy/$module/@v/$version.zip" | awk '{print $1}')"
printf 'consumer manifest sha256: %s\n' "$(sha256sum "$workspace/manifest.yaml" | awk '{print $1}')"
printf 'standard config sha256: %s\n' "$(sha256sum "$source/distribution/ocb/config.yaml" | awk '{print $1}')"
printf '30s config sha256: %s\n' "$(sha256sum "$source/distribution/ocb/config-consumer-30s.yaml" | awk '{print $1}')"
for relative in \
  integration/ocb/smoke_linux_test.go \
  integration/ocb/validation_linux_test.go \
  integration/ocb/operator_example_linux_test.go; do
  printf 'archived test %s sha256: %s\n' "$relative" "$(sha256sum "$source/$relative" | awk '{print $1}')"
done

(
  cd "$workspace"
  mkdir -p dist
  "$go_bin" run go.opentelemetry.io/collector/cmd/builder@v0.160.0 \
    --config manifest.yaml --skip-strict-versioning=false
)

generated=$workspace/dist/ocb
binary=$generated/otel-netflow-collector
[[ -x $binary ]] || {
  echo "OCB did not produce executable: $binary" >&2
  exit 1
}
gofmt -w "$generated"/*.go
grep -Fq "${module} ${version}" "$generated/go.mod"
if grep -Eq '^replace[[:space:]]|=>[[:space:]]*(\.\.|/)' "$generated/go.mod"; then
  echo 'versioned consumer generated an unexpected replacement' >&2
  exit 1
fi
"$binary" --version

(
  cd "$source"
  export NETFLOW_OCB_BINARY=$binary
  export NETFLOW_OCB_BUILD=versioned
  export NETFLOW_OCB_ARTIFACTS=$artifacts
  export NETFLOW_OCB_FIXTURE=$source/integration/testdata/ocb/canonical.yaml
  "$go_bin" test -mod=readonly ./integration/ocb \
    -run '^TestCollector(Smoke|TransportIsolation|OperatorExample|OperatorExampleRejectsQueue|Consumer30sRefreshConfig)$' \
    -count=1 -timeout=5m -v
)

printf 'dependency resolution policy: exporter from staged file proxy; %s (not anonymous installation evidence)\n' "$cache_mode"
printf 'versioned consumer PASS: %s at %s\n' "$version" "$revision"
