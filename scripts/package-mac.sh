#!/usr/bin/env bash
set -euo pipefail

export GOPROXY=${GOPROXY:-https://goproxy.cn,direct}
export GOWORK=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local

app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
worker_root=${ZJU_CONNECT_ROOT:-"$app_root/third_party/zju-connect"}


worker_commit=$(git -C "$worker_root" rev-parse --short HEAD 2>/dev/null || echo unknown)
go_tool=${GO:-go}


target_arch=${GOARCH:-$($go_tool env GOARCH)}
bundle_name=${EASYCONNECT_BUNDLE_NAME:-connect-hub-macos-$target_arch}

if [[ ! "$bundle_name" =~ ^[a-zA-Z0-9._-]+$ || "$bundle_name" == "." || "$bundle_name" == ".." ]]; then
  printf 'Invalid bundle name\n' >&2
  exit 1
fi

mkdir -p "$app_root/build"
bundle=$(mktemp -d "$app_root/build/.${bundle_name}.staging.XXXXXXXX")
trap 'rm -rf -- "$bundle"' EXIT

app_bundle="$bundle/Connect Hub.app"
contents="$app_bundle/Contents"
macos_bin="$contents/MacOS"
resources="$contents/Resources"
mkdir -p "$macos_bin/core" "$resources" "$bundle/LICENSES"

cd "$app_root"
app_version=$(sed -n 's/^const version = "\(.*\)"$/\1/p' "$app_root/internal/desktop/app.go" | head -n1)
app_version=${app_version:-0.1.0}

# 1–2. Shared binary builder, including locked inputs and module manifests.
build_args=(-worker "$worker_root" -out "$macos_bin" -os darwin -arch "$target_arch")
if [[ "${EASYCONNECT_DEVELOPMENT_BUILD:-0}" == 1 ]]; then build_args+=(-development); fi
bash "$app_root/scripts/build.sh" "${build_args[@]}"

# 3. 部署资源与图标
install -m 0644 "$app_root/resources/icon.png" "$resources/icon.png"
if [[ -f "$app_root/resources/icon.icns" ]]; then
  install -m 0644 "$app_root/resources/icon.icns" "$resources/icon.icns"
fi

# 4. 生成 Info.plist
cat > "$contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>zh_CN</string>
	<key>CFBundleDisplayName</key>
	<string>Connect Hub</string>
	<key>CFBundleExecutable</key>
	<string>connect-hub</string>
	<key>CFBundleIconFile</key>
	<string>icon</string>
	<key>CFBundleIdentifier</key>
	<string>app.connect.hub</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>Connect Hub</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>$app_version</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>LSMinimumSystemVersion</key>
	<string>11.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
	<!-- 局域网分享: macOS 15 asks for local network access before an app may
	     talk to devices on the same network. Discovery uses DNS-SD, so the
	     service type is declared here as well. Keep both in sync with
	     internal/relay/discovery.ServiceType; a test enforces it. -->
	<key>NSLocalNetworkUsageDescription</key>
	<string>用于发现同一局域网内同事开启的分享，以及连接这些分享。</string>
	<key>NSBonjourServices</key>
	<array>
		<string>_connecthub._tcp</string>
	</array>
	<key>NSAppTransportSecurity</key>
	<dict>
		<key>NSAllowsArbitraryLoads</key>
		<true/>
		<key>NSAllowsArbitraryLoadsInWebContent</key>
		<true/>
	</dict>
</dict>
</plist>
EOF

# 5. 许可文件与元数据
install -m 0644 "$app_root/LICENSE" "$bundle/LICENSES/aTrustHub-AGPL-3.0.txt"
install -m 0644 "$worker_root/LICENSE" "$bundle/LICENSES/ZJU-Connect-AGPL-3.0.txt"
install -m 0644 "$worker_root/third_party/utls/LICENSE" "$bundle/LICENSES/uTLS.txt"
for module in github.com/bytemare/opaque github.com/bytemare/ecc github.com/bytemare/hash github.com/bytemare/hash2curve github.com/bytemare/ksf github.com/bytemare/secp256k1 github.com/gtank/ristretto255 filippo.io/edwards25519 filippo.io/nistec; do
  module_dir=$(cd "$app_root" && "$go_tool" list -m -f '{{.Dir}}' "$module")
  module_name=${module##*/}
  install -m 0644 "$module_dir/LICENSE" "$bundle/LICENSES/$module_name.txt"
done

cat > "$bundle/COMPONENTS.txt" <<EOF
Connect Hub macOS bundle
Architecture: $target_arch
Worker IPC protocol: 7
Worker source commit: $worker_commit
Relay process protocol: relay-process-v1
Scope: VPN tunnel, proxy and browser login on macOS.
Layout: Connect Hub.app/Contents/MacOS/connect-hub with core/connect-hub-worker and core/connect-hub-relay.
EOF

chmod +x "$macos_bin/connect-hub" "$macos_bin/core/connect-hub-worker" "$macos_bin/core/connect-hub-relay"

# 如果在 macOS 环境且具备 codesign 工具，应用 Ad-hoc 自签名以兼容 Apple Silicon
if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep -s - "$app_bundle" || true
fi

cd "$bundle"
find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS

cd "$app_root/build"
final_bundle="$app_root/build/$bundle_name"
if [[ -e "$final_bundle" || -L "$final_bundle" ]]; then
  rm -rf -- "$final_bundle"
fi
mv -- "$bundle" "$final_bundle"
trap - EXIT

# 生成 .tar.gz 便携分发包
archive_tar="$app_root/build/$bundle_name.tar.gz"
tar -czf "$archive_tar" -C "$app_root/build" "$bundle_name"

# 如果处于 macOS 环境且存在 hdiutil 命令，生成包含 Applications 快捷方式的标准 DMG 安装镜像
if command -v hdiutil >/dev/null 2>&1; then
  dmg_out="$app_root/build/$bundle_name.dmg"
  dmg_staging=$(mktemp -d "$app_root/build/.dmg_staging.XXXXXXXX")
  trap 'rm -rf -- "$dmg_staging"' EXIT

  cp -R "$final_bundle/Connect Hub.app" "$dmg_staging/"
  ln -s /Applications "$dmg_staging/Applications"

  rm -f "$dmg_out"
  hdiutil create -volname "Connect Hub" -srcfolder "$dmg_staging" -ov -format UDZO "$dmg_out"
  rm -rf -- "$dmg_staging"
  trap - EXIT
  printf 'Created DMG: %s\n' "$dmg_out"
fi

printf 'macOS bundle created: %s (%s)\n' "$final_bundle" "$archive_tar"
