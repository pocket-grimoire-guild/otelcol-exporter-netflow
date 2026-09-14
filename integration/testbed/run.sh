#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)
cd "$script_dir"
go_bin=${GO_BIN_DIR:-/usr/local/go/bin}
collector=${COLLECTOR:-"$repo_root/dist/testbed/otel-netflow-testbed-collector"}
artifact_parent=${ARTIFACT_PARENT:-"$repo_root/../artifacts"}
tshark_bin=${TSHARK_BIN:-tshark}
expected_tshark_version=${EXPECTED_TSHARK_VERSION:-4.4.18}
scenario=${TESTBED_SCENARIO:-baseline}
case "$scenario" in
  baseline) repetitions=3; records_per_case=100; pacing_ms=10; concurrency=1 ;;
  sustained) repetitions=1; records_per_case=1000; pacing_ms=10; concurrency=1 ;;
  overload) repetitions=1; records_per_case=1000; pacing_ms=0; concurrency=4 ;;
  recovery) repetitions=1; records_per_case=40; pacing_ms=10; concurrency=1 ;;
  *) printf 'TESTBED_SCENARIO must be baseline, sustained, overload, or recovery\n' >&2; exit 2 ;;
esac

if [[ ! -x "$collector" ]]; then
  printf 'collector binary is missing or not executable: %s\n' "$collector" >&2
  exit 2
fi
if ! command -v "$tshark_bin" >/dev/null 2>&1 && [[ ! -x "$tshark_bin" ]]; then
  printf 'TShark is required\n' >&2
  exit 2
fi
if [[ ! -x "$go_bin/go" ]]; then
  printf 'pinned Go binary is missing: %s/go\n' "$go_bin" >&2
  exit 2
fi
go_version=$("$go_bin/go" version)
if [[ "$go_version" != *'go1.26.8 '* ]]; then
  printf 'expected Go 1.26.8, got: %s\n' "$go_version" >&2
  exit 2
fi
tshark_version=$(timeout --kill-after=1s 5s "$tshark_bin" --version | sed -n '1p')
if [[ "$tshark_version" != *"$expected_tshark_version"* ]]; then
  printf 'expected TShark %s, got: %s\n' "$expected_tshark_version" "$tshark_version" >&2
  exit 2
fi

mkdir -p "$artifact_parent"
run_id=${TESTBED_RUN_ID:-"testbed-${scenario}-$(date -u +%Y%m%dT%H%M%SZ)-$$"}
artifact_root="$artifact_parent/$run_id"
if [[ -e "$artifact_root" ]]; then
  printf 'artifact root already exists; choose TESTBED_RUN_ID: %s\n' "$artifact_root" >&2
  exit 2
fi
mkdir "$artifact_root"
chmod 700 "$artifact_root"

runner="$artifact_root/testbed-runner"
PATH="$go_bin:$PATH" GOMAXPROCS=2 GOFLAGS=-p=2 timeout --kill-after=5s 120s \
  go build -mod=readonly -o "$runner" .
chmod 700 "$runner"
timeout --kill-after=5s 5s "$go_bin/go" version -m "$collector" >"$artifact_root/collector.buildinfo"
chmod 600 "$artifact_root/collector.buildinfo"
printf 'sha256=%s\n' "$(sha256sum "$collector" | awk '{print $1}')" >"$artifact_root/collector.sha256"
chmod 600 "$artifact_root/collector.sha256"
printf '%s\n' "$tshark_version" >"$artifact_root/tshark.version"
tshark_path=$(command -v "$tshark_bin" 2>/dev/null || printf '%s' "$tshark_bin")
printf 'sha256=%s\n' "$(sha256sum "$tshark_path" | awk '{print $1}')" >>"$artifact_root/tshark.version"
chmod 600 "$artifact_root/tshark.version"

printf 'collector=%s\n' "$collector"
printf 'artifacts=%s\n' "$artifact_root"
{
  uname -srvmo
  cat /etc/os-release
  printf 'go=%s\n' "$go_version"
  printf 'cpu_count=%s\n' "$(getconf _NPROCESSORS_ONLN)"
  cat /proc/loadavg
  free -b
  df -B1 "$artifact_root"
  printf 'scenario=%s repetitions=%d records_per_case=%d pacing_ms=%d concurrency=%d case_deadline_s=30\n' \
    "$scenario" "$repetitions" "$records_per_case" "$pacing_ms" "$concurrency"
} >"$artifact_root/environment.txt"
for ((repetition=1; repetition<=repetitions; repetition++)); do
  for protocol in v5 v9 ipfix; do
    case_name="$protocol-$repetition"
    printf '\n== %s ==\n' "$case_name"
    PATH="$go_bin:$PATH" timeout --kill-after=5s 40s \
      "$runner" \
        --collector "$collector" \
        --protocol "$protocol" \
        --scenario "$scenario" \
        --artifacts "$artifact_root/$case_name"
    cat "$artifact_root/$case_name/result.txt"
  done
done
(
  cd "$artifact_root"
  # The output manifest is explicitly excluded from its input list.
  # shellcheck disable=SC2094
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS
)
artifact_bytes=$(du -sb "$artifact_root" | awk '{print $1}')
if (( artifact_bytes > 67108864 )); then
  printf 'aggregate artifact cap exceeded: %s bytes\n' "$artifact_bytes" >&2
  exit 1
fi
printf '\nPASS: all %d bounded %s protocol child processes completed\n' "$((repetitions * 3))" "$scenario"
