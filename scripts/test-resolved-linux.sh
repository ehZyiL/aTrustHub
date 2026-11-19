#!/usr/bin/env bash
set -euo pipefail
app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
probe_tmp=$(mktemp -d "${TMPDIR:-/tmp}/easyconnect-dns-test.XXXXXX")
trap 'rm -rf -- "$probe_tmp"' EXIT
cd "$app_root"
go test -mod=readonly -c -o "$probe_tmp/resolved.test" ./internal/resolved
ECH_DNS_TEST_EXEC="$probe_tmp/resolved.test" python3 scripts/probe-resolved-namespace.py
