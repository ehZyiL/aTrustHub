#!/usr/bin/env bash
set -euo pipefail

bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
worker=${1:-}
if [[ -z "$worker" ]]; then
  # 内部程序在 core/ 里；平铺位置留给拆分前的包。
  worker="$bundle_dir/core/easyconnect-worker"
  if [[ ! -x "$worker" ]]; then
    worker="$bundle_dir/easyconnect-worker"
  fi
fi
test -x "$worker" || { printf 'Worker binary not found: %s\n' "$worker" >&2; exit 1; }
set +e
reply=$(printf '%s\n' '{"version":7,"session":"bundle-check","type":"start","config":{}}' | "$worker" 2>/dev/null)
status=$?
set -e
if (( status != 1 )) || [[ "$reply" != *'"version":7'* || "$reply" != *'"session":"bundle-check"'* || "$reply" != *'"type":"error"'* ]]; then
  printf 'Worker IPC v7 mismatch or invalid configuration reached the network.\n' >&2
  exit 1
fi
printf 'Worker IPC v7 verified; invalid configuration rejected before network access.\n'
