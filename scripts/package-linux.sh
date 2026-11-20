#!/usr/bin/env bash
set -euo pipefail

app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
worker_root=$(cd -- "$app_root/../zju-connect" && pwd)
# The two independently built modules must agree before bundling their IPC.
diff -u --strip-trailing-cr <(sed 's/^package desktop$/package workeripc/' "$worker_root/internal/desktop/protocol.go") "$app_root/internal/workeripc/protocol.go"
go_tool=${GO:-go}
target_arch=${GOARCH:-$($go_tool env GOARCH)}
bundle_name=${EASYCONNECT_BUNDLE_NAME:-easyconnect-hub-linux-$target_arch}
if [[ ! "$bundle_name" =~ ^[a-zA-Z0-9._-]+$ || "$bundle_name" == "." || "$bundle_name" == ".." ]]; then
  printf 'Invalid bundle name\n' >&2
  exit 1
fi
mkdir -p "$app_root/build"
bundle=$(mktemp -d "$app_root/build/.${bundle_name}.staging.XXXXXXXX")
trap 'rm -rf -- "$bundle"' EXIT
mkdir -p "$bundle/resources" "$bundle/LICENSES"

cd "$app_root"
env GOOS=linux GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -o "$bundle/easyconnect-hub" .
env GOOS=linux GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -o "$bundle/easyconnect-hub-capture" ./cmd/app-helper
helper_protocol=$("$bundle/easyconnect-hub-capture" --protocol-version)
if [[ "$helper_protocol" != 9 ]]; then
  printf 'Linux capture helper protocol mismatch: expected 9, got %s\n' "$helper_protocol" >&2
  exit 1
fi
"$go_tool" list -m all > "$bundle/desktop-modules.txt"
cd "$worker_root"
env GOWORK=off GOOS=linux GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -o "$bundle/easyconnect-worker" ./cmd/easyconnect-worker
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
install -m 0644 "$app_root/LINUX-QUICKSTART.md" "$bundle/README.md"
install -m 0644 "$app_root/scripts/measure-tun-performance.py" "$bundle/measure-tun-performance.py"
cat > "$bundle/COMPONENTS.txt" <<EOF
EasyConnect Hub Linux bundle
Architecture: $target_arch
Worker IPC protocol: 6
Linux capture helper protocol: $helper_protocol
Scope: IPv4 TCP and DNS. System IPv4 UDP for eligible L3 sessions is experimental; IPv6 is unsupported.
GUI, worker and helper are a matched build from this bundle; do not mix files from other bundles.
EOF
install -m 0644 "$app_root/packaging/linux/easyconnect-hub-capture@.service" "$bundle/easyconnect-hub-capture@.service"
install -m 0755 "$app_root/packaging/linux/install-capture-helper.sh" "$bundle/install-capture-helper.sh"
install -m 0755 "$app_root/packaging/linux/uninstall-capture-helper.sh" "$bundle/uninstall-capture-helper.sh"
install -m 0755 "$app_root/packaging/linux/test-worker.sh" "$bundle/test-worker.sh"
"$bundle/test-worker.sh"

printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)' 'cd "$bundle_dir"' 'exec "$bundle_dir/easyconnect-hub" "$@"' > "$bundle/start.sh"
chmod +x "$bundle/start.sh"
chmod +x "$bundle/easyconnect-hub" "$bundle/easyconnect-worker" "$bundle/easyconnect-hub-capture" "$bundle/test-worker.sh" "$bundle/install-capture-helper.sh" "$bundle/uninstall-capture-helper.sh"

cd "$bundle"
find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
cd "$app_root/build"
final_bundle="$app_root/build/$bundle_name"
if [[ -e "$final_bundle" || -L "$final_bundle" ]]; then
  rm -rf -- "$final_bundle"
fi
mv -- "$bundle" "$final_bundle"
trap - EXIT
archive_tmp="$app_root/build/.${bundle_name}.tar.gz.$$"
trap 'rm -f -- "$archive_tmp"' EXIT
tar -czf "$archive_tmp" "$bundle_name"
mv -f -- "$archive_tmp" "$bundle_name.tar.gz"
trap - EXIT
printf 'Linux bundle: %s\n' "$final_bundle"
