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
bundle="$app_root/build/$bundle_name"
mkdir -p "$bundle/resources" "$bundle/LICENSES"

cd "$app_root"
env GOOS=linux GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -o "$bundle/easyconnect-hub" .
env GOOS=linux GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -o "$bundle/easyconnect-hub-capture" ./cmd/app-helper
helper_protocol=$("$bundle/easyconnect-hub-capture" --protocol-version)
if [[ "$helper_protocol" != 7 ]]; then
  printf 'Linux capture helper protocol mismatch: expected 7, got %s\n' "$helper_protocol" >&2
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
mygo_dir=$(cd "$app_root" && "$go_tool" list -m -f '{{.Dir}}' github.com/egoist/mygo)
install -m 0644 "$mygo_dir/LICENSE" "$bundle/LICENSES/MyGo-MIT.txt"
install -m 0644 "$app_root/LINUX-QUICKSTART.md" "$bundle/README.md"
install -m 0644 "$app_root/packaging/linux/easyconnect-hub-capture@.service" "$bundle/easyconnect-hub-capture@.service"
install -m 0755 "$app_root/packaging/linux/install-capture-helper.sh" "$bundle/install-capture-helper.sh"
install -m 0755 "$app_root/packaging/linux/uninstall-capture-helper.sh" "$bundle/uninstall-capture-helper.sh"
install -m 0755 "$app_root/packaging/linux/test-worker.sh" "$bundle/test-worker.sh"

printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)' 'cd "$bundle_dir"' 'exec "$bundle_dir/easyconnect-hub" "$@"' > "$bundle/start.sh"
chmod +x "$bundle/start.sh"
chmod +x "$bundle/easyconnect-hub" "$bundle/easyconnect-worker" "$bundle/easyconnect-hub-capture" "$bundle/test-worker.sh" "$bundle/install-capture-helper.sh" "$bundle/uninstall-capture-helper.sh"

cd "$bundle"
sha256sum easyconnect-hub easyconnect-worker easyconnect-hub-capture easyconnect-hub-capture@.service install-capture-helper.sh uninstall-capture-helper.sh test-worker.sh > SHA256SUMS
cd "$app_root/build"
tar -czf "$bundle_name.tar.gz" "$bundle_name"
printf 'Linux bundle: %s\n' "$bundle"
