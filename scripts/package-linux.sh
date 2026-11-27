#!/usr/bin/env bash
set -euo pipefail

export GOPROXY=${GOPROXY:-https://goproxy.cn,direct}
export GOWORK=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local

app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
worker_root=${ZJU_CONNECT_ROOT:-"$app_root/third_party/zju-connect"}
# The two independently built modules must agree before bundling their IPC.
worker_commit=$(git -C "$worker_root" rev-parse --short HEAD 2>/dev/null || echo unknown)
go_tool=${GO:-go}
target_arch=${GOARCH:-$($go_tool env GOARCH)}
bundle_name=${EASYCONNECT_BUNDLE_NAME:-connect-hub-linux-$target_arch}
if [[ ! "$bundle_name" =~ ^[a-zA-Z0-9._-]+$ || "$bundle_name" == "." || "$bundle_name" == ".." ]]; then
  printf 'Invalid bundle name\n' >&2
  exit 1
fi
mkdir -p "$app_root/build"
bundle=$(mktemp -d "$app_root/build/.${bundle_name}.staging.XXXXXXXX")
trap 'rm -rf -- "$bundle"' EXIT
mkdir -p "$bundle/resources" "$bundle/LICENSES" "$bundle/core"

cd "$app_root"
# ELF 不能像 EXE 那样内嵌图标：窗口和托盘图标由程序自己读 resources/icon.png，
# 应用菜单、Dock 则需要 hicolor 图标；这里把它们按尺寸放进包里。
env "$go_tool" run ./cmd/appicon -icon resources/icon.png -png-dir "$bundle/share/icons/hicolor" -png-name connect-hub
build_args=(-worker "$worker_root" -out "$bundle" -os linux -arch "$target_arch")
if [[ "${EASYCONNECT_DEVELOPMENT_BUILD:-0}" == 1 ]]; then build_args+=(-development); fi
bash "$app_root/scripts/build.sh" "${build_args[@]}"
helper_protocol=$("$bundle/core/connect-hub-capture" --protocol-version)
if [[ "$helper_protocol" != 11 ]]; then
  printf 'Linux capture helper protocol mismatch: expected 11, got %s\n' "$helper_protocol" >&2
  exit 1
fi
relay_protocol=$("$bundle/core/connect-hub-relay" --protocol-version)
if [[ "$relay_protocol" != relay-process-v1 ]]; then
  printf 'Relay component protocol mismatch: expected relay-process-v1, got %s\n' "$relay_protocol" >&2
  exit 1
fi
"$go_tool" list -m all > "$bundle/desktop-modules.txt"
cd "$worker_root"
env GOWORK=off "$go_tool" list -m all > "$bundle/worker-modules.txt"

install -m 0644 "$app_root/resources/icon.png" "$bundle/resources/icon.png"
install -m 0644 "$app_root/LICENSE" "$bundle/LICENSES/aTrustHub-AGPL-3.0.txt"
install -m 0644 "$worker_root/LICENSE" "$bundle/LICENSES/ZJU-Connect-AGPL-3.0.txt"
install -m 0644 "$worker_root/third_party/utls/LICENSE" "$bundle/LICENSES/uTLS.txt"
install -m 0644 "$worker_root/third_party/utls/dicttls/LICENSE" "$bundle/LICENSES/uTLS-dicttls.txt"
install -m 0644 "$worker_root/third_party/utls/EASYCONNECT_PATCH.md" "$bundle/LICENSES/uTLS-PATCH.md"
for module in github.com/egoist/mygo github.com/mythologyli/sing-tun github.com/metacubex/gvisor github.com/sagernet/sing golang.org/x/sys github.com/bytemare/opaque github.com/bytemare/ecc github.com/bytemare/hash github.com/bytemare/hash2curve github.com/bytemare/ksf github.com/bytemare/secp256k1 github.com/gtank/ristretto255 filippo.io/edwards25519 filippo.io/nistec; do
  module_dir=$(cd "$app_root" && "$go_tool" list -m -f '{{.Dir}}' "$module")
  module_name=${module##*/}
  install -m 0644 "$module_dir/LICENSE" "$bundle/LICENSES/$module_name.txt"
done
install -m 0644 "$app_root/docs/LINUX-QUICKSTART.md" "$bundle/README.md"
# 性能对照脚本只用于受控 HTTP 对照测试，需要 Python 3 和 curl；
# 发布包不携带，脚本保留在仓库 scripts/ 目录。
cat > "$bundle/COMPONENTS.txt" <<EOF
Connect Hub Linux bundle
Architecture: $target_arch
Worker IPC protocol: 7
Worker source commit: $worker_commit
Linux capture helper protocol: $helper_protocol
Relay process protocol: $relay_protocol
Scope: IPv4 TCP and DNS. System IPv4 UDP for eligible L3 sessions is experimental; IPv6 is unsupported.
Layout: connect-hub at the bundle root; worker, capture helper and relay under core/.
Launch only connect-hub (or start.sh); programs in core/ start on demand.
The helper's installed name, systemd unit and /run/connect-hub-capture-<uid>
runtime directory all use the product name; install-capture-helper.sh stops and
removes the pre-rename easyconnect-hub-capture unit and binary first, so an
upgrade cannot leave two privileged helpers behind.
GUI, worker, helper and relay are a matched build from this bundle; do not mix files.
EOF
install -m 0644 "$app_root/packaging/linux/connect-hub-capture@.service" "$bundle/connect-hub-capture@.service"
install -m 0755 "$app_root/packaging/linux/install-capture-helper.sh" "$bundle/install-capture-helper.sh"
install -m 0755 "$app_root/packaging/linux/uninstall-capture-helper.sh" "$bundle/uninstall-capture-helper.sh"
install -m 0755 "$app_root/packaging/linux/install-desktop-entry.sh" "$bundle/install-desktop-entry.sh"
install -m 0755 "$app_root/packaging/linux/test-worker.sh" "$bundle/test-worker.sh"
"$bundle/test-worker.sh"

printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)' 'cd "$bundle_dir"' 'exec "$bundle_dir/connect-hub" "$@"' > "$bundle/start.sh"
chmod +x "$bundle/start.sh"
chmod +x "$bundle/connect-hub" "$bundle/core/connect-hub-worker" "$bundle/core/connect-hub-capture" "$bundle/core/connect-hub-relay" "$bundle/test-worker.sh" "$bundle/install-capture-helper.sh" "$bundle/uninstall-capture-helper.sh" "$bundle/install-desktop-entry.sh"

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
