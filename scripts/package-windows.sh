#!/usr/bin/env bash
set -euo pipefail

export GOPROXY=${GOPROXY:-https://goproxy.cn,direct}

app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# 工作树里没有 zju-connect 兄弟目录，允许用环境变量指过去；
# 默认仍是同级的 ../zju-connect。
worker_root=${ZJU_CONNECT_ROOT:-$(cd -- "$app_root/../zju-connect" && pwd)}
# worker 的源码目录改名过（cmd/easyconnect-worker）；固定的 WORKER_REF 可能还停在
# 旧 commit 上，所以按存在的路径选，产物名始终是新的。
worker_cmd=./cmd/connect-hub-worker
if [[ ! -d "$worker_root/cmd/connect-hub-worker" ]]; then
  worker_cmd=./cmd/easyconnect-worker
fi
# 把来源写进包里：否则"这个包是哪份代码打的"只能靠猜。
repo_branch=$(git -C "$app_root" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
repo_commit=$(git -C "$app_root" rev-parse --short HEAD 2>/dev/null || echo unknown)
repo_dirty=""
if [[ -n "$(git -C "$app_root" status --porcelain --untracked-files=no 2>/dev/null || true)" ]]; then
  repo_dirty=" (dirty)"
fi
app_build=$(sed -n 's/^const appBuild = "\(.*\)"$/\1/p' "$app_root/app.go" | head -n1)
worker_commit=$(git -C "$worker_root" rev-parse --short HEAD 2>/dev/null || echo unknown)
printf 'Packaging %s@%s%s (appBuild %s, worker %s)\n' "$repo_branch" "$repo_commit" "$repo_dirty" "${app_build:-unknown}" "$worker_commit"
go_tool=${GO:-go}
# 协议单源化：内部 workeripc/protocol.go 由 worker 仓库的 protocol.go 生成；
# 两边不一致时打包直接失败（提示重新生成，而不是让人手抄）。
(cd "$app_root" && env "$go_tool" run ./internal/workeripc/cmd/protogen -check -src "$worker_root/internal/desktop/protocol.go" -out ./internal/workeripc/protocol.go)
target_arch=${GOARCH:-amd64}
if [[ "$target_arch" != "amd64" ]]; then
  printf 'Windows capture test bundle currently supports amd64 only\n' >&2
  exit 1
fi
# 两种包：release 只放运行必需的文件；test 额外带抓包自测程序和 test-*.ps1，
# 供验收在普通用户 Windows 上跑。
bundle_profile=${EASYCONNECT_BUNDLE_PROFILE:-release}
case "$bundle_profile" in
  release) default_bundle_name="connect-hub-windows-$target_arch" ;;
  test) default_bundle_name="connect-hub-windows-$target_arch-capture" ;;
  *)
    printf 'Invalid bundle profile: %s (use release or test)\n' "$bundle_profile" >&2
    exit 1
    ;;
esac
bundle_name=${EASYCONNECT_BUNDLE_NAME:-$default_bundle_name}
if [[ ! "$bundle_name" =~ ^[a-zA-Z0-9._-]+$ || "$bundle_name" == "." || "$bundle_name" == ".." ]]; then
  printf 'Invalid bundle name\n' >&2
  exit 1
fi
mkdir -p "$app_root/build"
bundle=$(mktemp -d "$app_root/build/.${bundle_name}.staging.XXXXXXXX")
trap 'rm -rf -- "$bundle"' EXIT
mkdir -p "$bundle/resources" "$bundle/LICENSES" "$bundle/core"

cd "$app_root"
# go build 自己不写 Windows 资源，没有 .syso 时 EXE 会顶着 Go 的默认图标。
# 先生成带应用图标的资源对象，链接进 GUI 后再删除，免得留在工作树里。
icon_syso="$app_root/appicon_windows_${target_arch}.syso"
trap 'rm -rf -- "$bundle"; rm -f -- "$icon_syso"' EXIT
env "$go_tool" run ./cmd/appicon -icon resources/icon.png -arch "$target_arch" -out "$icon_syso"
env GOOS=windows GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -ldflags='-H=windowsgui -s -w' -o "$bundle/connect-hub.exe" .
rm -f -- "$icon_syso"
# 残留清理器（控制台子系统），放进 core/，由 GUI 提权调用或供命令行进阶使用
env GOOS=windows GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -ldflags='-s -w' -o "$bundle/core/connect-hub-cleanup.exe" ./cmd/app-cleanup
cleanup_protocol=$("$bundle/core/connect-hub-cleanup.exe" --protocol-version)
if [[ "$cleanup_protocol" != 2 ]]; then
  printf 'Windows cleanup helper protocol mismatch: expected 2, got %s\n' "$cleanup_protocol" >&2
  exit 1
fi
# worker 和抓包助手是内部程序，放进 core/，避免用户打开目录时误双击。
env GOOS=windows GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -ldflags='-H=windowsgui -s -w' -o "$bundle/core/connect-hub-capture.exe" ./cmd/app-helper
helper_protocol=$("$bundle/core/connect-hub-capture.exe" --protocol-version)
if [[ "$helper_protocol" != 7 ]]; then
  printf 'Windows capture helper protocol mismatch: expected 7, got %s\n' "$helper_protocol" >&2
  exit 1
fi
if [[ "$bundle_profile" == test ]]; then
  env GOOS=windows GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" test -mod=readonly -trimpath -c -o "$bundle/windows-capture-tests.exe" ./internal/wincapture
  "$go_tool" list -m all > "$bundle/desktop-modules.txt"
fi
cd "$worker_root"
env GOWORK=off GOOS=windows GOARCH="$target_arch" CGO_ENABLED=0 "$go_tool" build -mod=readonly -trimpath -ldflags='-H=windowsgui -s -w' -o "$bundle/core/connect-hub-worker.exe" "$worker_cmd"
if [[ "$bundle_profile" == test ]]; then
  env GOWORK=off "$go_tool" list -m all > "$bundle/worker-modules.txt"
fi

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
# 性能对照脚本只用于受控 HTTP 对照测试，需要 Python 3 和 curl；
# 发布包不携带，只在 test 包里放一份。
if [[ "$bundle_profile" == test ]]; then
  install -m 0644 "$app_root/scripts/measure-tun-performance.py" "$bundle/measure-tun-performance.py"
fi
cat > "$bundle/COMPONENTS.txt" <<EOF
Connect Hub Windows bundle
Bundle profile: $bundle_profile
Architecture: $target_arch
Worker IPC protocol: 7
Windows capture helper protocol: $helper_protocol
Source branch: $repo_branch
Source commit: $repo_commit$repo_dirty
Worker source commit: $worker_commit
App build: ${app_build:-unknown}
Scope: IPv4 TCP and DNS. System IPv4 UDP for eligible L3 sessions is experimental; IPv6 is unsupported.
Layout: connect-hub.exe at the bundle root; connect-hub-worker.exe,
connect-hub-capture.exe and connect-hub-cleanup.exe under core/. Launch only connect-hub.exe;
the programs in core/ are internal and start on demand.
GUI, worker and helper are a matched build from this bundle; do not mix files from other bundles.
EOF
if [[ "$bundle_profile" == test ]]; then
  install -m 0644 "$app_root/packaging/windows/test-capture.ps1" "$bundle/test-capture.ps1"
  install -m 0644 "$app_root/packaging/windows/test-worker.ps1" "$bundle/test-worker.ps1"
fi

cd "$bundle"
find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
python_bin=python3
if command -v python3 >/dev/null 2>&1 && python3 -c "" 2>/dev/null; then
  python_bin=python3
elif command -v python >/dev/null 2>&1 && python -c "" 2>/dev/null; then
  python_bin=python
elif command -v python.exe >/dev/null 2>&1; then
  python_bin=python.exe
elif command -v py.exe >/dev/null 2>&1; then
  python_bin=py.exe
fi
cd "$app_root/build"
final_bundle="$app_root/build/$bundle_name"
if [[ -e "$final_bundle" || -L "$final_bundle" ]]; then
  rm -rf -- "$final_bundle"
fi
mv -- "$bundle" "$final_bundle"
trap - EXIT
bundle="$final_bundle"
powershell_cmd=pwsh
if ! command -v "$powershell_cmd" >/dev/null 2>&1; then
  if command -v pwsh.exe >/dev/null 2>&1; then
    powershell_cmd=pwsh.exe
  elif command -v powershell.exe >/dev/null 2>&1; then
    powershell_cmd=powershell.exe
  elif command -v powershell >/dev/null 2>&1; then
    powershell_cmd=powershell
  fi
fi

to_win_path() {
  if command -v wslpath >/dev/null 2>&1; then
    wslpath -w "$1"
  else
    echo "$1"
  fi
}

# PowerShell/worker execution can hold directory handles on Windows. Run the
# process check after the directory rename, before replacing the archive.
# release 包里不放自测脚本，直接用打包目录中的那份跑同一个检查。
# worker 已移到 core/；test-worker.ps1 的默认路径同时兼容 core/ 与平铺位置。
if [[ "$bundle_profile" == test ]]; then
  "$powershell_cmd" -NoProfile -ExecutionPolicy Bypass -File "$(to_win_path "$bundle/test-worker.ps1")"
else
  "$powershell_cmd" -NoProfile -ExecutionPolicy Bypass -File "$(to_win_path "$app_root/packaging/windows/test-worker.ps1")" -WorkerPath "$(to_win_path "$bundle/core/connect-hub-worker.exe")"
fi
archive_tmp="$app_root/build/.${bundle_name}.zip.tmp.$$"
trap 'rm -f -- "$archive_tmp"' EXIT
"$python_bin" - "$(to_win_path "$bundle")" "$(to_win_path "$archive_tmp")" <<'PY'
import pathlib, sys, zipfile
bundle = pathlib.Path(sys.argv[1])
# compresslevel 需要 Python 3.7；旧解释器回落到默认级别。
try:
    archive = zipfile.ZipFile(sys.argv[2], 'w', zipfile.ZIP_DEFLATED, compresslevel=9)
except TypeError:
    archive = zipfile.ZipFile(sys.argv[2], 'w', zipfile.ZIP_DEFLATED)
with archive as output:
    for file in sorted(bundle.rglob('*')):
        if file.is_file():
            output.write(file, file.relative_to(bundle.parent))
PY
mv -f -- "$archive_tmp" "$final_bundle.zip"
trap - EXIT
printf 'Windows bundle: %s\n' "$bundle"
