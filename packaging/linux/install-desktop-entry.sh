#!/usr/bin/env bash
# 把当前解压目录注册（或用 --remove 注销）成本用户的桌面应用。
#
# Linux 的可执行文件不能像 Windows EXE 那样把图标带在身上：窗口和托盘图标由
# 程序启动后自己设置，应用菜单、Dock、任务栏则靠 .desktop 文件加 hicolor
# 图标目录。这个脚本只在用户目录写一份 .desktop 并装入随包的图标，不碰系统
# 目录，也不需要 root；移动或删除解压目录后重新运行一次即可。
set -euo pipefail

bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
data_dir=${XDG_DATA_HOME:-$HOME/.local/share}
app_id=easyconnect-hub
entry="$data_dir/applications/$app_id.desktop"
icons_root="$data_dir/icons/hicolor"
icon_sizes=(16 24 32 48 64 128 256)

refresh() {
  if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$data_dir/applications" >/dev/null 2>&1 || true
  fi
  if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$icons_root" >/dev/null 2>&1 || true
  fi
}

if [[ ${1:-} == --remove ]]; then
  rm -f -- "$entry"
  for size in "${icon_sizes[@]}"; do
    rm -f -- "$icons_root/${size}x${size}/apps/$app_id.png"
  done
  refresh
  printf 'Removed %s\n' "$entry"
  exit 0
fi

if [[ ! -x "$bundle_dir/start.sh" ]]; then
  printf 'start.sh missing or not executable in %s\n' "$bundle_dir" >&2
  exit 1
fi

# desktop 文件里的值：反斜杠和双引号要转义，路径带空格时整体加引号。
exec_value=$(printf '%s' "$bundle_dir/start.sh" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
exec_value="\"$exec_value\""

mkdir -p "$data_dir/applications"
missing=0
for size in "${icon_sizes[@]}"; do
  src="$bundle_dir/share/icons/hicolor/${size}x${size}/apps/$app_id.png"
  if [[ ! -f "$src" ]]; then
    missing=1
    continue
  fi
  install -D -m 0644 "$src" "$icons_root/${size}x${size}/apps/$app_id.png"
done
if [[ $missing -eq 1 ]]; then
  printf 'Warning: the pack has no complete share/icons tree; the menu icon may be scaled\n' >&2
fi

cat > "$entry" <<EOF
[Desktop Entry]
Type=Application
Name=EasyConnect Hub
Comment=EasyConnect multi-gateway desktop client
Exec=$exec_value
Icon=$app_id
Terminal=false
Categories=Network;Utility;
Keywords=EasyConnect;VPN;ZJU;
StartupWMClass=$app_id
EOF

refresh
printf 'Installed %s\n' "$entry"
