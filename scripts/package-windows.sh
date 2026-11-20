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
mkdir -p "$app_root/build"
bundle=$(mktemp -d "$app_root/build/.${bundle_name}.staging.XXXXXXXX")
trap 'rm -rf -- "$bundle"' EXIT
mkdir -p "$bundle/resources" "$bundle/LICENSES"

cd "$app_root"
env GOOS=windows GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -ldflags=-H=windowsgui -o "$bundle/easyconnect-hub.exe" .
env GOOS=windows GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -ldflags=-H=windowsgui -o "$bundle/easyconnect-hub-capture.exe" ./cmd/app-helper
helper_protocol=$("$bundle/easyconnect-hub-capture.exe" --protocol-version)
if [[ "$helper_protocol" != 6 ]]; then
  printf 'Windows capture helper protocol mismatch: expected 6, got %s\n' "$helper_protocol" >&2
  exit 1
fi
env GOOS=windows GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" test -mod=readonly -trimpath -c -o "$bundle/windows-capture-tests.exe" ./internal/wincapture
"$go_tool" list -m all > "$bundle/desktop-modules.txt"
cd "$worker_root"
env GOWORK=off GOOS=windows GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -ldflags=-H=windowsgui -o "$bundle/easyconnect-worker.exe" ./cmd/easyconnect-worker
env GOWORK=off "$go_tool" list -m all > "$bundle/worker-modules.txt"

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
cat > "$bundle/COMPONENTS.txt" <<EOF
EasyConnect Hub Windows bundle
Architecture: $target_arch
Worker IPC protocol: 6
Windows capture helper protocol: $helper_protocol
Scope: IPv4 TCP and DNS. Business UDP and IPv6 capture are not supported.
GUI, worker and helper are a matched build from this bundle; do not mix files from other bundles.
EOF
install -m 0644 "$app_root/packaging/windows/test-capture.ps1" "$bundle/test-capture.ps1"
install -m 0644 "$app_root/packaging/windows/test-worker.ps1" "$bundle/test-worker.ps1"

cd "$bundle"
find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
python_bin=python3
if ! command -v python3 >/dev/null 2>&1 || ! python3 -c "" 2>/dev/null; then
  python_bin=python
fi
cd "$app_root/build"
final_bundle="$app_root/build/$bundle_name"
if [[ -e "$final_bundle" || -L "$final_bundle" ]]; then
  rm -rf -- "$final_bundle"
fi
mv -- "$bundle" "$final_bundle"
trap - EXIT
bundle="$final_bundle"
# PowerShell/worker execution can hold directory handles on Windows. Run the
# process check after the directory rename, before replacing the archive.
pwsh -NoProfile -ExecutionPolicy Bypass -File "$bundle/test-worker.ps1"
archive_tmp="$app_root/build/.${bundle_name}.zip.tmp.$$"
trap 'rm -f -- "$archive_tmp"' EXIT
"$python_bin" - "$bundle" "$archive_tmp" <<'PY'
import pathlib, sys, zipfile
bundle = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(sys.argv[2], 'w', zipfile.ZIP_DEFLATED) as output:
    for file in sorted(bundle.rglob('*')):
        if file.is_file():
            output.write(file, file.relative_to(bundle.parent))
PY
mv -f -- "$archive_tmp" "$final_bundle.zip"
trap - EXIT
printf 'Windows bundle: %s\n' "$bundle"
