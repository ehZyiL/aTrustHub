#!/usr/bin/env bash
set -euo pipefail

worker=${1:-"$(dirname -- "${BASH_SOURCE[0]}")/easyconnect-worker"}
test -x "$worker" || { printf 'Worker binary not found: %s\n' "$worker" >&2; exit 1; }
set +e
reply=$(printf '%s\n' '{"version":6,"session":"bundle-check","type":"start","config":{}}' | "$worker" 2>/dev/null)
status=$?
set -e
if (( status != 1 )) || [[ "$reply" != *'"version":6'* || "$reply" != *'"session":"bundle-check"'* || "$reply" != *'"type":"error"'* ]]; then
  printf 'Worker IPC v6 mismatch or invalid configuration reached the network.\n' >&2
  exit 1
fi
printf 'Worker IPC v6 verified; invalid configuration rejected before network access.\n'
