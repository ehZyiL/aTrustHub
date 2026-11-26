#!/usr/bin/env bash
set -euo pipefail
app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec env GOWORK=off GOFLAGS=-mod=readonly GOOS= GOARCH= GOTOOLCHAIN=local \
  "${GO:-go}" -C "$app_root" run ./scripts/buildtool -root "$app_root" "$@"
