#!/usr/bin/env bash
set -euo pipefail
app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
probe_tmp=$(mktemp -d "${TMPDIR:-/tmp}/easyconnect-alias-test.XXXXXX")
trap 'rm -rf -- "$probe_tmp"' EXIT
cd "$app_root"
go test -mod=readonly -c -o "$probe_tmp/capture.test" ./internal/capture
cd "$app_root/third_party/zju-connect"
go test -mod=readonly -c -o "$probe_tmp/worker.test" ./internal/desktop
EASYCONNECT_CAPTURE_HOST_NETNS=$(readlink /proc/self/ns/net) EASYCONNECT_HELPER_NAMESPACE=1 ECH_ALIAS_WORKER="$probe_tmp/worker.test" \
  unshare --user --map-current-user --keep-caps --net "$probe_tmp/capture.test" -test.run '^TestAliasNamespace$' -test.v -test.timeout=45s
cd "$app_root"
ECH_ALIAS_WORKER="$probe_tmp/worker.test" ECH_DNS_CURRENT_USER=1 ECH_DNS_TEST_EXEC="$probe_tmp/capture.test" ECH_DNS_TEST_PATTERN='^TestAliasServiceNamespace$' python3 scripts/probe-resolved-namespace.py
