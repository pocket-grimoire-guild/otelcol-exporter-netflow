#!/usr/bin/env bash
# Verify the component's pinned generated metadata without installing tools globally.
set -euo pipefail
[[ $# == 4 && $1 == --go && $3 == --mdatagen ]] || {
  echo 'usage: check-generated.sh --go 1.26.8 --mdatagen go.opentelemetry.io/collector/cmd/mdatagen@v0.160.0' >&2
  exit 2
}
[[ $2 == 1.26.8 && $4 == go.opentelemetry.io/collector/cmd/mdatagen@v0.160.0 ]]
[[ $(go env GOVERSION) == "go$2" ]]
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
task_tmp=$(mktemp -d)
trap 'rm -rf -- "$task_tmp"' EXIT
mkdir -p "$task_tmp/tool" "$task_tmp/bin" "$task_tmp/before" "$task_tmp/after" "$task_tmp/generation"
# Installing module@version directly rejects upstream's monorepo replacements.
# As a dependency those replacements are ignored and the released requirements
# resolve normally. The repository's own module is never used to build the tool.
cat > "$task_tmp/tool/go.mod" <<'MOD'
module local/netflow-metadata-tool

go 1.26.0

require go.opentelemetry.io/collector/cmd/mdatagen v0.160.0
MOD
(cd "$task_tmp/tool" && go build -mod=mod -o mdatagen go.opentelemetry.io/collector/cmd/mdatagen)
# v0.160.0 generates root test package names from the directory basename.
# A temporary alias preserves netflowexporter for any checkout directory name.
ln -s "$repo" "$task_tmp/netflowexporter"
cat > "$task_tmp/bin/mdatagen" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 && $1 == metadata.yaml ]]
stage="$NETFLOW_METADATA_STAGE"
rm -rf -- "$stage"
mkdir -p "$stage"
cp -- "$NETFLOW_METADATA_ALIAS/metadata.yaml" "$stage/metadata.yaml"
# RootPackage searches parent directories for go.mod. A symlink keeps the
# staged source outside the checkout while preserving the real module path.
ln -s -- "$NETFLOW_METADATA_ALIAS/go.mod" "$stage/go.mod"
if [[ -e "$NETFLOW_METADATA_ALIAS/go.sum" ]]; then
  ln -s -- "$NETFLOW_METADATA_ALIAS/go.sum" "$stage/go.sum"
fi
ln -s -- "$NETFLOW_METADATA_ALIAS/doc.go" "$stage/doc.go"
"$NETFLOW_METADATA_BINARY" "$stage/metadata.yaml"
# mdatagen v0.160.0 emits generated_config.go and generated_config_test.go
# whenever config is present. The exporter owns a handwritten Config, so
# retain only the generated files that belong to this repository's allowlist.
cp -- "$stage/config.schema.json" "$NETFLOW_METADATA_ALIAS/config.schema.json"
cp -- "$stage/generated_component_test.go" "$NETFLOW_METADATA_ALIAS/generated_component_test.go"
cp -- "$stage/generated_package_test.go" "$NETFLOW_METADATA_ALIAS/generated_package_test.go"
cp -- "$stage/documentation.md" "$NETFLOW_METADATA_ALIAS/documentation.md"
# These are fully generated directories. Removing them first catches stale
# generated files while leaving every handwritten package directory untouched.
rm -rf -- "$NETFLOW_METADATA_ALIAS/internal/metadata" "$NETFLOW_METADATA_ALIAS/internal/metadatatest"
mkdir -p "$NETFLOW_METADATA_ALIAS/internal/metadata" "$NETFLOW_METADATA_ALIAS/internal/metadatatest"
cp -a -- "$stage/internal/metadata/." "$NETFLOW_METADATA_ALIAS/internal/metadata/"
cp -a -- "$stage/internal/metadatatest/." "$NETFLOW_METADATA_ALIAS/internal/metadatatest/"
WRAPPER
chmod +x "$task_tmp/bin/mdatagen"
export NETFLOW_METADATA_BINARY="$task_tmp/tool/mdatagen"
export NETFLOW_METADATA_ALIAS="$task_tmp/netflowexporter"
export NETFLOW_METADATA_STAGE="$task_tmp/generation/netflowexporter"
cd "$repo"
outputs=(config.schema.json generated_component_test.go generated_package_test.go documentation.md internal/metadata internal/metadatatest)
for output in "${outputs[@]}"; do
  if [[ -e "$output" ]]; then
    cp -a --parents -- "$output" "$task_tmp/before/"
  fi
done
PATH="$task_tmp/bin:$PATH" go generate .
cp -a --parents -- "${outputs[@]}" "$task_tmp/after/"
diff -ru "$task_tmp/before" "$task_tmp/after"
