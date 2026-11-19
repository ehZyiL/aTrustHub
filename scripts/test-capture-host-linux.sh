#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
  printf 'Usage: bash scripts/test-capture-host-linux.sh LOCAL_NON_LOOPBACK_IPV4\n' >&2
  exit 2
fi
app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$app_root"
# Deliberate host test: requires the already installed helper. No sudo, VPN
# credentials, network reconfiguration outside owned helper leases, or remote
# endpoints. The test rejects addresses not assigned to this computer.
EASYCONNECT_CAPTURE_HOST_TEST=1 EASYCONNECT_CAPTURE_HOST_ADDRESS="$1" \
  go test -mod=readonly ./internal/capture -run '^TestCaptureHostLifecycle$' -count=1 -v -timeout=2m
