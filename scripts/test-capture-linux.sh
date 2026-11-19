#!/usr/bin/env bash
set -euo pipefail

app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
probe_tmp=$(mktemp -d "${TMPDIR:-/tmp}/easyconnect-capture-test.XXXXXX")
trap 'rm -rf -- "$probe_tmp"' EXIT
cd "$app_root"
go test -mod=readonly -c -o "$probe_tmp/capture.test" ./internal/capture
EASYCONNECT_CAPTURE_HOST_NETNS=$(readlink /proc/self/ns/net) EASYCONNECT_CAPTURE_NETNS=1 unshare --user --map-root-user --net \
  "$probe_tmp/capture.test" -test.run '^TestCaptureNamespace$' -test.v -test.timeout=45s
EASYCONNECT_CAPTURE_HOST_NETNS=$(readlink /proc/self/ns/net) EASYCONNECT_HELPER_NAMESPACE=1 unshare --user --map-current-user --keep-caps --net \
  "$probe_tmp/capture.test" -test.run '^TestHelperNamespace$' -test.v -test.timeout=90s
