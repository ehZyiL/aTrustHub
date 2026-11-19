#!/usr/bin/env bash
set -euo pipefail
app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
probe_tmp=$(mktemp -d "${TMPDIR:-/tmp}/easyconnect-capture-dns.XXXXXX")
trap 'rm -rf -- "$probe_tmp"' EXIT
cd "$app_root"
go test -mod=readonly -c -o "$probe_tmp/capture.test" ./internal/capture
ECH_DNS_CURRENT_USER=1 ECH_DNS_TEST_EXEC="$probe_tmp/capture.test" ECH_DNS_TEST_PATTERN='^TestHelperNamespace$' python3 scripts/probe-resolved-namespace.py
