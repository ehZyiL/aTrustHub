#!/usr/bin/env bash
set -euo pipefail

app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
worker_root=$(cd -- "$app_root/../zju-connect" && pwd)
diff -u --strip-trailing-cr <(sed 's/^package desktop$/package workeripc/' "$worker_root/internal/desktop/protocol.go") "$app_root/internal/workeripc/protocol.go"
go_tool=${GO:-go}
target_arch=${GOARCH:-amd64}
if [[ "$target_arch" != "amd64" ]]; then
  printf 'Windows capture test bundle currently supports amd64 only\n' >&2
  exit 1
fi
bundle_name=${EASYCONNECT_BUNDLE_NAME:-easyconnect-hub-windows-amd64-capture}
if [[ ! "$bundle_name" =~ ^[a-zA-Z0-9._-]+$ || "$bundle_name" == "." || "$bundle_name" == ".." ]]; then
  printf 'Invalid bundle name\n' >&2
  exit 1
fi
bundle="$app_root/build/$bundle_name"
mkdir -p "$bundle/resources" "$bundle/LICENSES"

cd "$app_root"
env GOOS=windows GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -ldflags=-H=windowsgui -o "$bundle/easyconnect-hub.exe" .
env GOOS=windows GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -ldflags=-H=windowsgui -o "$bundle/easyconnect-hub-capture.exe" ./cmd/app-helper
env GOOS=windows GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" test -mod=readonly -trimpath -c -o "$bundle/windows-capture-tests.exe" ./internal/wincapture
"$go_tool" list -m all > "$bundle/desktop-modules.txt"
cd "$worker_root"
env GOOS=windows GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -ldflags=-H=windowsgui -o "$bundle/easyconnect-worker.exe" ./cmd/easyconnect-worker
"$go_tool" list -m all > "$bundle/worker-modules.txt"

install -m 0644 "$app_root/resources/icon.png" "$bundle/resources/icon.png"
install -m 0644 "$app_root/LICENSE" "$bundle/LICENSES/aTrustHub-AGPL-3.0.txt"
install -m 0644 "$worker_root/LICENSE" "$bundle/LICENSES/ZJU-Connect-AGPL-3.0.txt"
install -m 0644 "$worker_root/third_party/utls/LICENSE" "$bundle/LICENSES/uTLS.txt"
install -m 0644 "$worker_root/third_party/utls/dicttls/LICENSE" "$bundle/LICENSES/uTLS-dicttls.txt"
install -m 0644 "$worker_root/third_party/utls/EASYCONNECT_PATCH.md" "$bundle/LICENSES/uTLS-PATCH.md"
for module in github.com/egoist/mygo github.com/mythologyli/sing-tun github.com/metacubex/gvisor github.com/sagernet/sing golang.org/x/sys; do
  module_dir=$(cd "$app_root" && "$go_tool" list -m -f '{{.Dir}}' "$module")
  module_name=${module##*/}
  install -m 0644 "$module_dir/LICENSE" "$bundle/LICENSES/$module_name.txt"
done
install -m 0644 "$app_root/packaging/windows/Wintun-LICENSE.txt" "$bundle/LICENSES/Wintun-LICENSE.txt"
install -m 0644 "$app_root/WINDOWS-QUICKSTART.md" "$bundle/README.md"
install -m 0644 "$app_root/packaging/windows/test-capture.ps1" "$bundle/test-capture.ps1"

cd "$bundle"
sha256sum easyconnect-hub.exe easyconnect-worker.exe easyconnect-hub-capture.exe windows-capture-tests.exe test-capture.ps1 > SHA256SUMS
python_bin=python3
if ! command -v python3 >/dev/null 2>&1 || ! python3 -c "" 2>/dev/null; then
  python_bin=python
fi
"$python_bin" - "$bundle" <<'PY'
import pathlib, sys, zipfile
bundle = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(str(bundle) + '.zip', 'w', zipfile.ZIP_DEFLATED) as output:
    for file in sorted(bundle.rglob('*')):
        if file.is_file():
            output.write(file, file.relative_to(bundle.parent))
PY
printf 'Windows bundle: %s\n' "$bundle"
