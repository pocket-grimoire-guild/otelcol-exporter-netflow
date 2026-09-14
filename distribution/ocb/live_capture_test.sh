#!/usr/bin/env bash
# Actual OCB traffic over an isolated rootless veth; generated files stay untracked.
set -euo pipefail
umask 077
if [[ $# != 4 || $1 != --binary || $3 != --capture-image || $4 != *@sha256:* ]]; then
  echo 'usage: live_capture_test.sh --binary /path/to/collector --capture-image local-image@sha256:digest' >&2
  exit 2
fi
[[ $(uname -sm) == 'Linux x86_64' && $(id -u) != 0 ]]
[[ -z ${CONTAINER_CONNECTION:-} ]]
engine=(podman --remote=false)
if [[ -n ${CONTAINER_HOST:-} ]]; then
  [[ $CONTAINER_HOST == unix:///* && $CONTAINER_HOST != *[\?,]* ]]
  socket=${CONTAINER_HOST#unix://}
  [[ $(realpath -m -- "$socket") == "$socket" ]]
  engine=(podman --url "$CONTAINER_HOST")
fi
[[ $("${engine[@]}" info --format '{{.Host.Security.Rootless}}') == true ]]
binary=$(realpath -e -- "$2")
capture_image=$4
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"
mkdir -p dist
parent=${NETFLOW_OCB_LIVE_ARTIFACTS:-$repo/dist}
parent=$(realpath -e -- "$parent")
[[ -d $parent && -O $parent && $parent != *[,:]* ]]
stage=$(mktemp -d "$parent/ocb-live-XXXXXXXX")
name=netflow-$(basename "$stage")
cleanup() {
  result=$?
  trap - EXIT
  if ! timeout 12s "${engine[@]}" rm --force --ignore --time=2 "$name" >/dev/null; then result=1; fi
  if [[ -z ${NETFLOW_OCB_LIVE_ARTIFACTS:-} ]]; then rm -rf -- "$stage"; fi
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$stage/input/integration/ocb" "$stage/input/integration/testdata" "$stage/input/distribution/ocb" "$stage/output"
cp -R integration/testdata/golden integration/testdata/ocb "$stage/input/integration/testdata/"
cp distribution/ocb/config.yaml "$stage/input/distribution/ocb/"
cp integration/ocb/live_capture.py "$stage/input/"
cp -- "$binary" "$stage/input/collector"
python3 -B -m unittest discover -s integration/ocb -p 'test_live_capture.py'
CGO_ENABLED=0 go test -mod=readonly -c -o "$stage/input/driver" ./integration/ocb
"${engine[@]}" image inspect "$capture_image" --format '{{.Id}} {{.Digest}} {{.Os}}/{{.Architecture}}' >"$stage/capture-image.txt"
read -r image_id image_digest image_platform <"$stage/capture-image.txt"
[[ $image_digest == "${capture_image##*@}" && $image_platform == linux/amd64 && ${#image_id} == 64 ]]
# SYS_ADMIN creates/enters a second network namespace within the rootless user
# namespace; NET_ADMIN creates only its disposable veth and finalizes checksums.
# No host namespace, device, socket, credentials or repository is mounted.
timeout --signal=TERM --kill-after=5s 90s "${engine[@]}" run --name "$name" --pull=never \
  --network=none --user=0:0 --read-only --read-only-tmpfs=false \
  --cap-drop=all --cap-add=SYS_ADMIN --cap-add=NET_ADMIN --cap-add=NET_RAW \
  --security-opt=no-new-privileges --memory=512m --memory-swap=512m \
  --pids-limit=128 --cpus=2 --ulimit=nofile=128:128 --log-driver=none \
  --tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m,notmpcopyup \
  --env=HOME=/nonexistent --env=TMPDIR=/tmp \
  --mount "type=bind,src=$stage/input,dst=/input,ro=true" \
  --mount "type=bind,src=$stage/output,dst=/output,rw=true" \
  --entrypoint /usr/bin/python3 "$capture_image" /input/live_capture.py
"${engine[@]}" inspect "$name" --format '{{.Id}} {{.Image}} {{.HostConfig.NetworkMode}} {{.State.ExitCode}}' >"$stage/container.txt"
read -r container_id actual_image network_mode exit_code <"$stage/container.txt"
[[ ${#container_id} == 64 && $actual_image == "$image_id" && $network_mode == none && $exit_code == 0 ]]
"${engine[@]}" rm "$name" >/dev/null
captures=("$stage"/output/ocb-*)
[[ ${#captures[@]} == 1 && -d ${captures[0]} ]]
./integration/tshark/run_oracle.sh --pull=never --image "$(cat integration/tshark/IMAGE_DIGEST)" --live-capture "${captures[0]}"
echo "Live capture artifacts: $stage"
