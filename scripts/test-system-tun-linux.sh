#!/usr/bin/env bash
set -euo pipefail

app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/easyconnect-system-tun.XXXXXX")
trap 'rm -rf -- "$test_dir"' EXIT
cd "$app_root"
if [[ ! -c /dev/net/tun ]]; then
  printf '/dev/net/tun is required\n' >&2
  exit 1
fi
namespace=(--net)
if (( EUID != 0 )); then
  namespace=(--user --map-root-user --net)
fi
GOWORK=off go test -mod=readonly -c -o "$test_dir/capture.test" ./internal/capture
export EASYCONNECT_SYSTEM_TUN_HOST_NETNS
EASYCONNECT_SYSTEM_TUN_HOST_NETNS=$(readlink /proc/self/ns/net)
unshare "${namespace[@]}" env EASYCONNECT_SYSTEM_TUN_NAMESPACE=1 "$test_dir/capture.test" -test.run '^TestSystem' -test.v
