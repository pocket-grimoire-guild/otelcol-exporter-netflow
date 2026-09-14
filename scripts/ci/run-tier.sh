#!/usr/bin/env bash
# Run one bounded qualification tier.  Tool-dependent tiers are deliberately
# opt-in: a selected lane fails at preflight when its contract is incomplete.
set -euo pipefail
umask 077

usage() {
  cat >&2 <<'EOF'
usage: run-tier.sh generated|ocb|receiver|conformance|interop

interop requires NETFLOW_INTEROP_LANES (comma-separated tshark,pmacct,ipfixcol2,nfdump)
and the environment described in docs/ci.md.
EOF
  exit 2
}

[[ $# == 1 ]] || usage
tier=$1
case $tier in
  generated|ocb|receiver|conformance|interop) ;;
  *) usage ;;
esac

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"

MAX_LOG_BYTES=${NETFLOW_CI_MAX_LOG_BYTES:-1048576}
[[ $MAX_LOG_BYTES =~ ^[1-9][0-9]{0,6}$ && $MAX_LOG_BYTES -le 1048576 ]] || {
  echo "NETFLOW_CI_MAX_LOG_BYTES must be a positive integer" >&2
  exit 2
}
MAX_ARTIFACT_BYTES=${NETFLOW_CI_MAX_ARTIFACT_BYTES:-67108864}
[[ $MAX_ARTIFACT_BYTES =~ ^[1-9][0-9]{0,7}$ && $MAX_ARTIFACT_BYTES -le 67108864 ]] || {
  echo "NETFLOW_CI_MAX_ARTIFACT_BYTES must be a positive integer" >&2
  exit 2
}
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "preflight: required command is missing: $1" >&2
    exit 1
  }
}
require_file() {
  [[ -f $1 && ! -L $1 ]] || {
    echo "preflight: required regular file is missing: $1" >&2
    exit 1
  }
}
require_dir() {
  [[ -d $1 && ! -L $1 ]] || {
    echo "preflight: required directory is missing: $1" >&2
    exit 1
  }
}
require_executable() {
  [[ -f $1 && ! -L $1 && -x $1 ]] || {
    echo "preflight: selected executable is missing or not executable: $1" >&2
    exit 1
  }
}
require_linux_go() {
  require_cmd go
  local version
  version=$(go version)
  [[ $version == 'go version go1.26.8 linux/amd64' ]] || {
    echo "preflight: this tier requires Go 1.26.8 linux/amd64; got: $version" >&2
    exit 1
  }
}

require_cmd timeout
require_cmd awk
require_cmd grep
require_cmd wc
require_cmd mktemp
require_cmd find
require_cmd python3
require_cmd date
require_cmd stat
require_file scripts/ci/capture.py
require_file scripts/ci/assert-go-tests.sh

artifact_base=${NETFLOW_CI_ARTIFACTS:-$repo/dist/ci}
mkdir -p -- "$artifact_base"
artifact_dir=$(mktemp -d "$artifact_base/${tier}.XXXXXX")
summary=$artifact_dir/summary.txt
printf 'tier=%s\nstarted_utc=%s\n' "$tier" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$summary"
binary_dir=

artifact_gate() {
  local files=0 bytes=0 path size
  local listing gate_status=0
  listing=$(mktemp "${TMPDIR:-/tmp}/netflow-ci-artifacts.XXXXXX")
  if ! find "$artifact_dir" -mindepth 1 -print0 >"$listing"; then
    rm -f -- "$listing"
    echo "artifact gate: could not enumerate $artifact_dir" >&2
    return 1
  fi
  while IFS= read -r -d '' path; do
    if [[ -L $path ]]; then
      echo "artifact gate: non-regular or symlink entry: $path" >&2
      gate_status=1
      break
    fi
    [[ -d $path ]] && continue
    if [[ ! -f $path ]]; then
      echo "artifact gate: non-regular artifact entry: $path" >&2
      gate_status=1
      break
    fi
    size=$(wc -c <"$path")
    files=$((files + 1))
    bytes=$((bytes + size))
    if (( files > 640 )); then
      echo "artifact gate: too many files in $artifact_dir" >&2
      gate_status=1
      break
    fi
    if (( bytes > MAX_ARTIFACT_BYTES )); then
      echo "artifact gate: total size exceeds $MAX_ARTIFACT_BYTES bytes" >&2
      gate_status=1
      break
    fi
  done <"$listing"
  rm -f -- "$listing"
  if (( gate_status != 0 )); then
    return 1
  fi
  printf 'artifact_files=%d\nartifact_bytes=%d\n' "$files" "$bytes"
}

on_exit() {
  local status=$?
  if [[ -n $binary_dir ]]; then
    rm -rf -- "$binary_dir"
  fi
  printf 'status=%s\nfinished_utc=%s\n' "$([[ $status == 0 ]] && echo PASS || echo FAIL)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$summary"
  printf 'tier=%s\nsummary=%s\n' "$tier" "$summary" >"$artifact_dir/UPLOAD_READY"
  if ! artifact_gate; then
    rm -f -- "$artifact_dir/UPLOAD_READY"
    status=1
    echo 'status=FAIL artifact_gate=FAIL' >>"$summary"
  fi
  echo "ci tier=$tier status=$([[ $status == 0 ]] && echo PASS || echo FAIL) artifacts=$artifact_dir upload_ready=$([[ -f $artifact_dir/UPLOAD_READY ]] && echo yes || echo no)" >&2
  exit "$status"
}
trap on_exit EXIT

step=0
run_step() {
  local name=$1 timeout_seconds=$2
  shift 2
  step=$((step + 1))
  local log
  log=$artifact_dir/$(printf '%02d-%s.log' "$step" "$name")
  local display
  printf -v display '%q ' "$@"
  {
    printf 'step=%s\ncommand=%s\ntimeout=%ss\n' "$name" "$display" "$timeout_seconds"
  } >"$log"
  set +e
  local capture_max=$((MAX_LOG_BYTES - 1024))
  (( capture_max > 0 )) || capture_max=1
  timeout --kill-after=10s "${timeout_seconds}s" python3 scripts/ci/capture.py --output "$log" --max-bytes "$capture_max" -- "$@"
  local status=$?
  set -e
  local bytes
  bytes=$(wc -c <"$log")
  if (( status == 125 || bytes > MAX_LOG_BYTES )); then
    echo "step=$name exceeded bounded log size (${bytes} bytes)" >&2
    echo "step=$name status=FAIL bytes=$bytes command=$display" >>"$summary"
    return 1
  fi
  cat "$log"
  if (( status != 0 )); then
    echo "step=$name status=FAIL bytes=$bytes command=$display" >>"$summary"
    return "$status"
  fi
  echo "step=$name status=PASS bytes=$bytes command=$display" >>"$summary"
}

go_test_step() {
  local name=$1 timeout_seconds=$2 expected=$3
  shift 3
  run_step "$name" "$timeout_seconds" "$@"
  local log
  log=$(find "$artifact_dir" -maxdepth 1 -type f -name "*-""$name".log -print -quit)
  local counts
  if ! counts=$(scripts/ci/assert-go-tests.sh "$log" "$expected"); then
    echo "step=$name selected tests invalid: $counts" >&2
    echo "step=$name test_counts=$counts status=FAIL" >>"$summary"
    return 1
  fi
  echo "step=$name test_counts=$counts" >>"$summary"
}

run_generated() {
  require_linux_go
  require_cmd python3
  require_file scripts/check-generated.sh
  require_file scripts/check-config-schema.sh
  require_file scripts/check-canonical-fixtures.py
  require_file scripts/check-generated-fixtures.py
  require_file scripts/check-golden-manifest.py
  require_file scripts/check-fuzz-manifest.py
  require_file scripts/check-mapping-manifest.py
  require_file integration/testdata/canonical/fixtures.json
  require_file integration/testdata/golden/manifest.json
  require_file integration/testdata/fuzz/manifest.json
  require_file integration/testdata/mapping/manifest.yaml
  require_file integration/testdata/pcap/payload-manifest.yaml
  run_step generated-drift 900 scripts/check-generated.sh --go 1.26.8 --mdatagen go.opentelemetry.io/collector/cmd/mdatagen@v0.160.0
  run_step config-schema 300 scripts/check-config-schema.sh
  run_step canonical-fixtures 60 python3 scripts/check-canonical-fixtures.py integration/testdata/canonical/fixtures.json
  run_step generated-fixtures 60 python3 scripts/check-generated-fixtures.py integration/testdata/canonical/fixtures.json
  run_step golden-manifest 60 python3 scripts/check-golden-manifest.py integration/testdata/golden/manifest.json
  run_step fuzz-manifest 60 python3 scripts/check-fuzz-manifest.py
  run_step mapping-manifest 60 python3 scripts/check-mapping-manifest.py integration/testdata/mapping/manifest.yaml
  run_step pcap-wrap 120 go run -mod=readonly ./integration/tshark/wrap_pcaps.go --golden-manifest integration/testdata/golden/manifest.json --manifest integration/testdata/pcap/payload-manifest.yaml --out integration/testdata/pcap
  run_step pcap-manifest 120 go run -mod=readonly ./integration/tshark/verify_payloads.go --manifest integration/testdata/pcap/payload-manifest.yaml --pcap-root integration/testdata/pcap --golden-manifest integration/testdata/golden/manifest.json
}

run_ocb() {
  require_linux_go
  require_file distribution/ocb/build.sh
  require_file distribution/ocb/smoke_test.sh
  require_file distribution/ocb/manifest.yaml
  require_file distribution/ocb/config.yaml
  require_file integration/testdata/ocb/canonical.yaml
  mkdir -p -- "$repo/dist/ci-bin"
  binary_dir=$(mktemp -d "$repo/dist/ci-bin/ocb.XXXXXX")
  local binary=$binary_dir/otel-netflow-collector
  run_step ocb-build 900 distribution/ocb/build.sh --go 1.26.8 --out "$binary"
  require_executable "$binary"
  [[ $(stat -c '%s' "$binary") -gt 0 ]] || {
    echo 'preflight: OCB build produced an empty binary' >&2
    return 1
  }
  run_step ocb-version 30 "$binary" --version
  local smoke_artifacts=$artifact_dir/ocb-smoke
  local operator_artifacts=$artifact_dir/ocb-operator
  mkdir -p -- "$smoke_artifacts" "$operator_artifacts"
  go_test_step ocb-smoke 600 2 env NETFLOW_OCB_ARTIFACTS="$smoke_artifacts" distribution/ocb/smoke_test.sh --binary "$binary" --fixture integration/testdata/ocb/canonical.yaml
  go_test_step ocb-operator 600 3 env -u NETFLOW_OCB_NETNS NETFLOW_OCB_BINARY="$binary" NETFLOW_OCB_ARTIFACTS="$operator_artifacts" go test -mod=readonly ./integration/ocb -run '^TestCollector(OperatorExample|OperatorExampleRejectsQueue|Consumer30sRefreshConfig)$' -count=1 -timeout=5m -v
}

run_receiver() {
  require_linux_go
  require_file integration/receiver/go.mod
  require_file integration/receiver/go.sum
  go_test_step receiver 900 2 bash -c 'cd integration/receiver && go test -mod=readonly . -run '\''^Test(SemanticRoundTrip|LargePinnedReceiverPacketization)$'\'' -count=1 -timeout=10m -v'
}

run_conformance() {
  require_linux_go
  require_executable scripts/conformance/run.sh

  local conformance_parent=$artifact_dir/conformance
  [[ ! -e $conformance_parent ]] || {
    echo "preflight: conformance output parent already exists: $conformance_parent" >&2
    return 1
  }

  # The harness owns its pins, scenarios, controls, and semantic checks.  Keep
  # this tier's wrapper focused on the exact command and its bounded evidence.
  run_step conformance 1500 scripts/conformance/run.sh --output "$conformance_parent"

  require_dir "$conformance_parent"
  local -a runs=()
  local candidate
  while IFS= read -r -d '' candidate; do
    runs+=("$candidate")
  done < <(find "$conformance_parent" -mindepth 1 -maxdepth 1 -type d -print0)
  ((${#runs[@]} == 1)) || {
    echo "conformance output must contain exactly one fresh run directory: $conformance_parent" >&2
    return 1
  }

  local output_root=${runs[0]}
  [[ ! -L $output_root ]] || {
    echo "conformance output run directory must not be a symlink: $output_root" >&2
    return 1
  }
  local required
  for required in \
    "$output_root/report.md" \
    "$output_root/pins/artifact-sha256.txt" \
    "$output_root/logs/harness-guards.log"; do
    [[ -f $required && ! -L $required && -s $required ]] || {
      echo "conformance output is missing a nonempty required file: $required" >&2
      return 1
    }
  done
  printf 'step=conformance-output status=PASS output=%s\n' "$output_root" >>"$summary"
}

require_selected_lanes() {
  local raw=${NETFLOW_INTEROP_LANES:-}
  [[ -n $raw ]] || {
    echo 'preflight: NETFLOW_INTEROP_LANES is required when interop is selected' >&2
    return 1
  }
  local lane
  IFS=',' read -r -a lanes <<<"$raw"
  ((${#lanes[@]} > 0 && ${#lanes[@]} <= 4)) || return 1
  local seen=,
  for lane in "${lanes[@]}"; do
    [[ $seen != *",$lane,"* ]] || { echo "duplicate lane: $lane" >&2; return 1; }
    seen+="$lane,"
    case $lane in
      tshark|pmacct|ipfixcol2|nfdump) ;;
      *) echo "preflight: unsupported interop lane: $lane" >&2; return 1 ;;
    esac
  done
}

run_interop() {
  require_linux_go
  require_selected_lanes
  local lane
  IFS=',' read -r -a lanes <<<"$NETFLOW_INTEROP_LANES"
  for lane in "${lanes[@]}"; do
    case $lane in
      tshark)
        require_cmd podman
        require_file integration/tshark/IMAGE_DIGEST
        require_file integration/tshark/run_oracle.sh
        require_file integration/tshark/wrap_pcaps.go
        require_file integration/testdata/pcap/payload-manifest.yaml
        require_file integration/testdata/golden/manifest.json
        [[ -n ${NETFLOW_TSHARK_IMAGE:-} ]] || {
          echo 'preflight: NETFLOW_TSHARK_IMAGE is required for the tshark lane' >&2
          return 1
        }
        [[ $NETFLOW_TSHARK_IMAGE == *@sha256:* ]] || {
          echo 'preflight: NETFLOW_TSHARK_IMAGE must be an immutable digest reference' >&2
          return 1
        }
        local pinned_image
        pinned_image=$(<integration/tshark/IMAGE_DIGEST)
        [[ $NETFLOW_TSHARK_IMAGE == "$pinned_image" ]] || {
          echo "preflight: TShark image differs from integration/tshark/IMAGE_DIGEST" >&2
          return 1
        }
        podman image exists "$NETFLOW_TSHARK_IMAGE" || {
          echo "preflight: pinned TShark image is not present locally: $NETFLOW_TSHARK_IMAGE" >&2
          return 1
        }
        run_step tshark-pcap-wrap 120 go run -mod=readonly ./integration/tshark/wrap_pcaps.go --golden-manifest integration/testdata/golden/manifest.json --manifest integration/testdata/pcap/payload-manifest.yaml --out integration/testdata/pcap
        local tshark_artifacts=${NETFLOW_TSHARK_ARTIFACTS:-$artifact_dir/tshark}
        mkdir -p -- "$tshark_artifacts"
        run_step tshark-oracle 420 env NETFLOW_TSHARK_ARTIFACTS="$tshark_artifacts" ./integration/tshark/run_oracle.sh --pull=never --image "$NETFLOW_TSHARK_IMAGE"
        grep -q '^PASS: pinned TShark independently decoded seven immutable' "$artifact_dir"/*-tshark-oracle.log || {
          echo 'TShark oracle did not report the seven-case PASS' >&2
          return 1
        }
        echo 'step=tshark-oracle test_counts=pass:7,skip:0,fail:0' >>"$summary"
        ;;
      pmacct)
        require_executable "${NFACCTD_BINARY:-}"
        run_independent pmacct '^TestNfacctd$' NFACCTD_BINARY="$NFACCTD_BINARY" NFACCTD_ARTIFACTS="$artifact_dir/pmacct"
        ;;
      ipfixcol2)
        require_executable "${IPFIXCOL2_BINARY:-}"
        local ipfix_env=(IPFIXCOL2_BINARY="$IPFIXCOL2_BINARY" IPFIXCOL2_ARTIFACTS="$artifact_dir/ipfixcol2")
        [[ -n ${IPFIXCOL2_PLUGINS:-} ]] && ipfix_env+=(IPFIXCOL2_PLUGINS="$IPFIXCOL2_PLUGINS")
        [[ -n ${IPFIXCOL2_DEFINITIONS:-} ]] && ipfix_env+=(IPFIXCOL2_DEFINITIONS="$IPFIXCOL2_DEFINITIONS")
        run_independent ipfixcol2 '^TestIPFIXcol2$' "${ipfix_env[@]}"
        ;;
      nfdump)
        require_executable "${NFCAPD_BINARY:-}"
        require_executable "${NFDUMP_BINARY:-}"
        run_independent nfdump '^TestNfcapd$' NFCAPD_BINARY="$NFCAPD_BINARY" NFDUMP_BINARY="$NFDUMP_BINARY" NFCAPD_ARTIFACTS="$artifact_dir/nfdump"
        ;;
    esac
  done
}

run_independent() {
  local name=$1 regex=$2
  shift 2
  go_test_step "independent-$name" 900 1 env "$@" go test -mod=readonly ./integration/independent -run "$regex" -count=1 -timeout=10m -v
}

case $tier in
  generated) run_generated ;;
  ocb) run_ocb ;;
  receiver) run_receiver ;;
  conformance) run_conformance ;;
  interop) run_interop ;;
esac
