#!/usr/bin/env bash
# Run the portable, pinned semantic-conventions conformance slice.
set -eEuo pipefail

readonly MAX_LOG_BYTES=1048576
readonly MAX_ARTIFACT_BYTES=$((64 * 1024 * 1024))
readonly RUNNER_REPOSITORY=https://github.com/open-telemetry/semantic-conventions-conformance.git
readonly RUNNER_COMMIT=17df55b24316a12b1921a6873b24437b52f9f81f
readonly SEMCONV_REPOSITORY=https://github.com/open-telemetry/semantic-conventions.git
readonly SEMCONV_COMMIT=e10a930844c6951757a43b849d364f7d056ac32b
readonly WEAVER_VERSION=0.26.1
readonly WEAVER_ARCHIVE_URL=https://github.com/open-telemetry/weaver/releases/download/v0.26.1/weaver-x86_64-unknown-linux-gnu.tar.xz
readonly WEAVER_ARCHIVE_SHA256=1be79cca68925c09b6da04ef8a3875b563cf7c1dcd51cc5b7eff7d2edbb1a5dc
readonly WEAVER_BINARY_SHA256=40cc3889e273c8dd54501827fb310bfed61539efd514ea042ed8563d18b3bafc
readonly GO_VERSION='go version go1.26.8 linux/amd64'
readonly PYTHON_VERSION='Python 3.13.5'
readonly PIP_VERSION='25.1.1'

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$script_dir/../.." && pwd)
output_parent=$repo/artifacts/conformance

usage() {
	cat >&2 <<'EOF'
usage: scripts/conformance/run.sh [--output PATH]

PATH selects a fresh output parent. Prerequisite checkouts and caches stay in
a temporary directory and are removed when this command exits.
EOF
}

if (( $# > 0 )); then
	if [[ $# -ne 2 || $1 != --output ]]; then
		usage
		exit 2
	fi
	output_parent=$2
fi

# Reject missing retained inputs before network setup or output creation.
for input in integration/conformance/registry/netflow-extension.yaml \
	integration/conformance/scenarios/{custom,upstream}/conformance.yaml \
	integration/conformance/telemetry_snapshot_test.go.in \
	scripts/conformance/{replay.py,verify.py,test_harness.py,requirements-py3.13.txt,go-module-graph.sha256} \
	scripts/ci/capture.py telemetry_conditional_test.go; do
	if [[ ! -f "$repo/$input" || -L "$repo/$input" ]]; then
		echo "required harness input is missing or not regular: $input" >&2
		exit 2
	fi
done

for ambient in \
	NETFLOW_CONFORMANCE_CORE \
	NETFLOW_CONFORMANCE_OUTPUT \
	NETFLOW_CONFORMANCE_GO \
	NETFLOW_CONFORMANCE_RUN_ID \
	NETFLOW_CONFORMANCE_CAPTURE \
	OTEL_EXPORTER_OTLP_ENDPOINT \
	OTEL_EXPORTER_OTLP_PROTOCOL; do
	if [[ ${!ambient+x} ]]; then
		echo "ambient $ambient would shadow a harness control" >&2
		exit 2
	fi
done

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
	echo "this pinned slice requires Linux x86_64" >&2
	exit 2
fi

for tool in git curl tar sha256sum mktemp find wc date awk cmp xargs sort grep uname basename dirname install cp mkdir chmod cat; do
	command -v "$tool" >/dev/null || {
		echo "required tool is missing: $tool" >&2
		exit 2
	}
done
git_bin=$(command -v git)

if [[ -x /usr/local/go/bin/go ]]; then
	go_bin=/usr/local/go/bin/go
else
	go_bin=$(command -v go || true)
fi
if [[ -z "$go_bin" ]]; then
	echo "Go 1.26.8 is missing" >&2
	exit 2
fi
if [[ $($go_bin version) != "$GO_VERSION" ]]; then
	echo "expected $GO_VERSION, got $($go_bin version)" >&2
	exit 2
fi

if command -v python3.13 >/dev/null; then
	python_bin=$(command -v python3.13)
else
	python_bin=$(command -v python3 || true)
fi
if [[ -z "$python_bin" || $($python_bin --version 2>&1) != "$PYTHON_VERSION" ]]; then
	echo "expected $PYTHON_VERSION" >&2
	exit 2
fi

mkdir -p "$output_parent"
output_parent=$(cd -- "$output_parent" && pwd)
run_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
output_root=$output_parent/$run_id
if [[ -e "$output_root" ]]; then
	echo "output run directory already exists: $output_root" >&2
	exit 2
fi
mkdir -p "$output_root/logs" "$output_root/reports" "$output_root/data" \
	"$output_root/captures" "$output_root/pins"
setup_log=$output_root/logs/setup.log
: > "$setup_log"

log_line() {
	printf '%s\n' "$*" >> "$setup_log"
}

run_setup() {
	local label=$1
	shift
	log_line "setup: $label: $*"
	local used remaining
	used=$(wc -c < "$setup_log")
	remaining=$((MAX_LOG_BYTES - used))
	if (( remaining <= 0 )); then
		echo "setup log exceeded 1 MiB before $label" >&2
		exit 1
	fi
	if ! "$python_bin" "$repo/scripts/ci/capture.py" \
		--output "$setup_log" --max-bytes "$remaining" -- "$@"; then
		echo "setup failed: $label" >&2
		exit 1
	fi
}

work=$(mktemp -d "${TMPDIR:-/tmp}/netflow-conformance.XXXXXX")
cleanup() {
	local status=$?
	if [[ -n ${work:-} && -d "$work" ]]; then
		rm -rf -- "$work"
	fi
	exit "$status"
}
trap cleanup EXIT

export PYTHONDONTWRITEBYTECODE=1
export GOTOOLCHAIN=local
export GOWORK=off
unset GOFLAGS

log_line "harness run: $run_id"
log_line "repository commit: $($git_bin -C "$repo" rev-parse HEAD)"

mkdir -p "$work/src" "$work/registry" "$work/bin" "$work/download"
runner_checkout=$work/src/semantic-conventions-conformance
semconv_checkout=$work/registry/semantic-conventions
run_setup clone-runner git clone --filter=blob:none --no-checkout "$RUNNER_REPOSITORY" "$runner_checkout"
run_setup checkout-runner git -C "$runner_checkout" checkout --detach "$RUNNER_COMMIT"
if [[ $($git_bin -C "$runner_checkout" rev-parse HEAD) != "$RUNNER_COMMIT" ]]; then
	echo "runner checkout did not resolve to the pinned commit" >&2
	exit 1
fi
run_setup clone-semantic-conventions git clone --filter=blob:none --no-checkout "$SEMCONV_REPOSITORY" "$semconv_checkout"
run_setup checkout-semantic-conventions git -C "$semconv_checkout" checkout --detach "$SEMCONV_COMMIT"
if [[ $($git_bin -C "$semconv_checkout" rev-parse HEAD) != "$SEMCONV_COMMIT" ]]; then
	echo "semantic-conventions checkout did not resolve to the pinned commit" >&2
	exit 1
fi

archive=$work/download/weaver-x86_64-unknown-linux-gnu.tar.xz
run_setup download-weaver curl -fsSLo "$archive" "$WEAVER_ARCHIVE_URL"
archive_hash=$(sha256sum "$archive" | awk '{print $1}')
if [[ "$archive_hash" != "$WEAVER_ARCHIVE_SHA256" ]]; then
	echo "Weaver archive hash mismatch" >&2
	exit 1
fi
run_setup extract-weaver tar -xJf "$archive" -C "$work/bin"
weaver_source=$work/bin/weaver-x86_64-unknown-linux-gnu/weaver
if [[ ! -f "$weaver_source" || -L "$weaver_source" ]]; then
	echo "Weaver release did not contain a regular executable" >&2
	exit 1
fi
weaver=$work/bin/weaver
run_setup install-weaver install -m 0755 "$weaver_source" "$weaver"
weaver_hash=$(sha256sum "$weaver" | awk '{print $1}')
if [[ "$weaver_hash" != "$WEAVER_BINARY_SHA256" ]]; then
	echo "Weaver binary hash mismatch" >&2
	exit 1
fi

custom_registry=$work/registry/custom/model
mkdir -p "$work/registry/custom"
cp -a "$semconv_checkout/model" "$custom_registry"
mkdir -p "$custom_registry/netflow"
cp "$repo/integration/conformance/registry/netflow-extension.yaml" \
	"$custom_registry/netflow/registry.yaml"
if find "$semconv_checkout/model" "$custom_registry" -type l -print -quit | grep -q .; then
	echo "registry model contains an unexpected symlink" >&2
	exit 1
fi
run_setup check-upstream-registry env PATH="$work/bin:$PATH" NO_COLOR=1 \
	"$weaver" registry check --registry "$semconv_checkout/model"
run_setup check-custom-registry env PATH="$work/bin:$PATH" NO_COLOR=1 \
	"$weaver" registry check --registry "$custom_registry"

venv=$work/venv
run_setup create-python-venv "$python_bin" -m venv "$venv"
run_setup pin-pip "$venv/bin/python" -m pip install --disable-pip-version-check \
	--no-input --no-cache-dir "pip==$PIP_VERSION"
run_setup install-python-deps "$venv/bin/python" -m pip install \
	--disable-pip-version-check --no-input --no-cache-dir \
	-r "$repo/scripts/conformance/requirements-py3.13.txt"
if [[ $("$venv/bin/python" -m pip --version) != pip\ $PIP_VERSION\ * ]]; then
	echo "pip runtime is not pinned to $PIP_VERSION" >&2
	exit 1
fi
python_freeze=$work/python-freeze.txt
if ! "$venv/bin/python" -m pip freeze --local | sort > "$python_freeze"; then
	echo "unable to capture the Python dependency graph" >&2
	exit 1
fi
if ! "$venv/bin/python" - "$repo/scripts/conformance/requirements-py3.13.txt" "$python_freeze" <<'PY'
from pathlib import Path
import sys

requirements = {
    line.split("==", 1)[0].strip().lower(): line.split("==", 1)[1].strip()
    for line in Path(sys.argv[1]).read_text().splitlines()
    if line.strip() and not line.lstrip().startswith("#")
}
freeze = {}
for line in Path(sys.argv[2]).read_text().splitlines():
    if line.startswith("-e "):
        raise SystemExit("editable Python package is not permitted")
    if "==" not in line:
        raise SystemExit(f"unbounded Python package: {line}")
    name, version = line.split("==", 1)
    freeze[name.strip().lower()] = version.strip()
if freeze != requirements:
    raise SystemExit(f"Python graph mismatch: expected={requirements} got={freeze}")
PY
then
	echo "Python dependency graph differs from the complete pin file" >&2
	exit 1
fi

graph=$work/go-module-graph.txt
if ! (cd "$repo" && "$go_bin" list -mod=readonly -m -f '{{if not .Main}}{{.Path}}={{.Version}}{{if .Replace}} replacement={{.Replace.Path}}@{{.Replace.Version}}{{end}}{{end}}' all | sort > "$graph"); then
	echo "unable to resolve the read-only Go module graph" >&2
	exit 1
fi
graph_hash=$(sha256sum "$graph" | awk '{print $1}')
expected_graph_hash=$(awk '!/^#/ && NF {print $1; exit}' "$repo/scripts/conformance/go-module-graph.sha256")
if [[ "$graph_hash" != "$expected_graph_hash" ]]; then
	echo "Go module graph hash mismatch: expected $expected_graph_hash got $graph_hash" >&2
	exit 1
fi
cp "$graph" "$output_root/pins/go-module-graph.txt"
cp "$python_freeze" "$output_root/pins/python-freeze.txt"

runner_src=$runner_checkout/tools/runner/src
scenario_upstream=$work/scenarios/upstream
scenario_custom=$work/scenarios/custom
mkdir -p "$scenario_upstream" "$scenario_custom"
for scenario in upstream custom; do
	destination=$scenario_upstream
if [[ "$scenario" == custom ]]; then destination=$scenario_custom; fi
	cp "$repo/integration/conformance/scenarios/$scenario/conformance.yaml" "$destination/conformance.yaml"
	cp "$repo/scripts/conformance/replay.py" "$destination/replay.py"
	chmod 0755 "$destination/replay.py"
done

source_hashes=$output_root/pins/source-sha256.txt
(cd "$repo" && sha256sum \
	go.mod go.sum telemetry_conditional_test.go \
	integration/conformance/registry/netflow-extension.yaml \
	integration/conformance/scenarios/upstream/conformance.yaml \
	integration/conformance/scenarios/custom/conformance.yaml \
	integration/conformance/telemetry_snapshot_test.go.in \
	scripts/ci/capture.py \
	scripts/conformance/replay.py scripts/conformance/verify.py scripts/conformance/test_harness.py \
	scripts/conformance/requirements-py3.13.txt scripts/conformance/run.sh \
	scripts/conformance/go-module-graph.sha256) > "$source_hashes"

old_path=$PATH
run_runner() {
	local label=$1 scenario=$2 registry=$3 report_dir=$4 data_file=$5 expected=$6 report_only=$7
	local log=$output_root/logs/$label.log
	if [[ -e "$log" ]]; then
		echo "runner log already exists: $label" >&2
		exit 1
	fi
	local -a flags=(
		"$scenario"
		--registry "$registry"
		--report-dir "$report_dir"
		--data-file "$data_file"
	)
	if [[ "$report_only" == 1 ]]; then flags+=(--report-only); fi
	local -a environment=(
		env
		"PATH=$work/bin:$venv/bin:$old_path"
		"PYTHONPATH=$runner_src"
		"NO_COLOR=1"
		"NETFLOW_CONFORMANCE_CORE=$repo"
		"NETFLOW_CONFORMANCE_OUTPUT=$output_root"
		"NETFLOW_CONFORMANCE_GO=$go_bin"
		"NETFLOW_CONFORMANCE_RUN_ID=$label"
	)
	local status=0
	"$venv/bin/python" "$repo/scripts/ci/capture.py" \
		--output "$log" --max-bytes "$MAX_LOG_BYTES" -- \
		"${environment[@]}" "$venv/bin/python" -m opentelemetry.conformance \
		"${flags[@]}" || status=$?
	if [[ "$status" -ne "$expected" ]]; then
		echo "$label returned $status; expected $expected" >&2
		exit 1
	fi
}

run_runner upstream-strict "$scenario_upstream" "$semconv_checkout/model" \
	"$output_root/reports/upstream-strict" "$output_root/data/upstream-strict.json" 1 0
run_runner upstream-report-only "$scenario_upstream" "$semconv_checkout/model" \
	"$output_root/reports/upstream-report-only" "$output_root/data/upstream-report-only.json" 0 1
run_runner custom-strict "$scenario_custom" "$custom_registry" \
	"$output_root/reports/custom-strict" "$output_root/data/custom-strict.json" 1 0
run_runner custom-report-only "$scenario_custom" "$custom_registry" \
	"$output_root/reports/custom-report-only" "$output_root/data/custom-report-only.json" 0 1

for label in upstream-strict upstream-report-only custom-strict custom-report-only; do
	"$venv/bin/python" "$repo/scripts/conformance/verify.py" \
		--capture-dir "$output_root/captures" --run-id "$label" \
		--data "$output_root/data/$label.json" \
		--report-dir "$output_root/reports/$label" \
		--log "$output_root/logs/$label.log" --mode "$label"
done

"$venv/bin/python" "$repo/scripts/ci/capture.py" \
	--output "$output_root/logs/harness-guards.log" --max-bytes "$MAX_LOG_BYTES" -- \
	"$venv/bin/python" "$repo/scripts/conformance/test_harness.py" "$output_root"

source_hashes_after=$work/source-sha256.after.txt
(cd "$repo" && sha256sum \
	go.mod go.sum telemetry_conditional_test.go \
	integration/conformance/registry/netflow-extension.yaml \
	integration/conformance/scenarios/upstream/conformance.yaml \
	integration/conformance/scenarios/custom/conformance.yaml \
	integration/conformance/telemetry_snapshot_test.go.in \
	scripts/ci/capture.py \
	scripts/conformance/replay.py scripts/conformance/verify.py scripts/conformance/test_harness.py \
	scripts/conformance/requirements-py3.13.txt scripts/conformance/run.sh \
	scripts/conformance/go-module-graph.sha256) > "$source_hashes_after"
if ! cmp -s "$source_hashes" "$source_hashes_after"; then
	echo "source hashes changed during the harness run" >&2
	exit 1
fi

cat > "$output_root/report.md" <<EOF
# NetFlow semantic-conventions harness run

- Run ID: \`$run_id\`
- Root checkout commit: \`$($git_bin -C "$repo" rev-parse HEAD)\`
- Conformance runner: \`$RUNNER_COMMIT\`
- Semantic conventions registry: \`$SEMCONV_COMMIT\`
- Weaver: \`$WEAVER_VERSION\` (archive \`$WEAVER_ARCHIVE_SHA256\`, binary \`$WEAVER_BINARY_SHA256\`)
- Go: \`$GO_VERSION\`
- Python: \`$PYTHON_VERSION\`; pip \`$PIP_VERSION\`

The command exercised the existing package-local \`TestTelemetryConditionalProbe\`
through a temporary Go overlay. The SDK snapshot retained resource attribute
values, scope identity and all 11 declared signals. The Python bridge replayed
that snapshot over OTLP/gRPC, then applied one exact mutation for each custom
control after capture. Custom strict mode failed both controls; custom
report-only mode emitted WARN for both. Upstream strict failed on the pinned
upstream registry findings; upstream report-only retained those findings as
WARN. The four invocations remain separate in \`reports/\`, \`data/\`, and
\`logs/\`.

Every log is bounded to 1 MiB and the complete dynamic output tree is bounded
to 64 MiB.
The bound excludes prerequisite source checkouts, the temporary Python
environment, downloaded Weaver, Go module/build caches, and the system tools;
temporary tool checkouts and the Python environment are removed on exit.
Go module/build caches and system tools remain caller-managed. The
artifact hash manifest covers every final file except the manifest itself.

This evidence is limited to exporter self-telemetry against the custom and
pinned upstream registries. It does not claim upstream standardization,
NetFlow/IPFIX wire interoperability, UDP receipt, appliance ingestion, or
capacity.
EOF

manifest=$output_root/pins/artifact-sha256.txt
(
	cd "$output_root"
	find report.md captures data reports logs pins -type f ! -path 'pins/artifact-sha256.txt' -print0 |
		sort -z |
		xargs -0 sha256sum
) > "$manifest"

if find "$output_root" -type l -print -quit | grep -q .; then
	echo "artifact tree contains a symlink" >&2
	exit 1
fi
artifact_files=0
artifact_bytes=0
while IFS= read -r -d '' file; do
	if [[ -L "$file" || ! -f "$file" ]]; then
		echo "artifact tree contains a non-regular file: $file" >&2
		exit 1
	fi
	size=$(wc -c < "$file")
	if [[ "$file" == "$output_root/logs/"* && "$size" -gt "$MAX_LOG_BYTES" ]]; then
		echo "log exceeds 1 MiB: $file" >&2
		exit 1
	fi
	artifact_files=$((artifact_files + 1))
	artifact_bytes=$((artifact_bytes + size))
done < <(find "$output_root" -mindepth 1 -type f -print0)
if (( artifact_bytes > MAX_ARTIFACT_BYTES )); then
	echo "dynamic artifacts exceed 64 MiB: $artifact_bytes" >&2
	exit 1
fi
echo "conformance harness passed: $output_root"
