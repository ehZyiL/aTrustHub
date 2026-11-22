#!/usr/bin/env bash
set -euo pipefail

# Exercise the real maintenance scripts inside a disposable chroot. systemctl
# and the helper are fixtures: no host systemd, network or installation changes.
app_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/easyconnect-helper-setup.XXXXXXXX")
trap 'rm -rf -- "$test_root"' EXIT
mkdir -p "$test_root"/{usr/bin,usr/local/libexec,etc/systemd/system,run,dev}
mkdir -p "$test_root/bundle/core"
ln -s usr/bin "$test_root/bin"
printf 'root:x:0:0:root:/root:/bin/bash\ndesktop:x:1000:1000:Desktop:/home/desktop:/bin/bash\n' > "$test_root/etc/passwd"
printf 'root:x:0:\ndesktop:x:1000:\n' > "$test_root/etc/group"
printf 'passwd: files\ngroup: files\n' > "$test_root/etc/nsswitch.conf"
for tool in bash dirname install getent stat flock mktemp rm mv cat mkdir chmod ln; do
  tool_path=$(command -v "$tool")
  cp -L "$tool_path" "$test_root/usr/bin/$tool"
  while read -r library; do
    cp -L --parents "$library" "$test_root"
  done < <(ldd "$tool_path" | awk '/=> \// {print $3} /^[[:space:]]*\// {print $1}')
done
cp "$app_root/packaging/linux/"{install-capture-helper.sh,uninstall-capture-helper.sh,connect-hub-capture@.service} "$test_root/bundle/"
for tool in ip nft busctl systemd-run; do
  printf '#!/bin/bash\nexit 0\n' > "$test_root/usr/bin/$tool"
  chmod +x "$test_root/usr/bin/$tool"
done
cat > "$test_root/usr/bin/systemctl" <<'MOCK'
#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> /calls
case "$1" in
  list-units) cat /running ;;
  list-unit-files) cat /enabled ;;
  is-active) [[ -f /active ]] ;;
  stop) rm -f /active ;;
  enable) : > /active ;;
  disable|daemon-reload|reset-failed) ;;
  *) exit 99 ;;
esac
MOCK
chmod +x "$test_root/usr/bin/systemctl"
cat > "$test_root/bundle/core/connect-hub-capture" <<'MOCK'
#!/bin/bash
if [[ ${1:-} == --protocol-version ]]; then
  printf '%s\n' "${CANDIDATE_PROTOCOL:-11}"
  exit 0
fi
printf 'new-helper %s\n' "$*" >> /calls
MOCK
chmod +x "$test_root/bundle/core/connect-hub-capture"
cat > "$test_root/check.sh" <<'CHECK'
#!/bin/bash
set -euo pipefail
[[ ${EASYCONNECT_SETUP_SANDBOX:-} == 1 && -f /.setup-sandbox ]] || exit 99
unit=connect-hub-capture@1000.service
helper=/usr/local/libexec/connect-hub-capture
template=/etc/systemd/system/connect-hub-capture@.service
reset_case() {
  rm -rf -- /usr/local/libexec /etc/systemd/system /run/connect-hub-capture /run/easyconnect-hub-capture
  mkdir -p /usr/local/libexec /etc/systemd/system
  rm -f /active
  : > /calls
  : > /running
  : > /enabled
}
old_helper() {
  cat > "$helper" <<'OLD'
#!/bin/bash
printf 'old-helper %s\n' "$*" >> /calls
[[ ${RECOVER_FAIL:-0} == 0 ]]
OLD
  chmod +x "$helper"
}
expect_failure() {
  local expected=$1
  shift
  local actual=0
  "$@" >/result 2>&1 || actual=$?
  [[ $actual == "$expected" ]] || { cat /result; printf 'Expected exit %s, got %s\n' "$expected" "$actual"; exit 1; }
}
passed() { printf 'PASS %s\n' "$1"; }

reset_case
bash /bundle/install-capture-helper.sh --uid 1000 >/result
[[ -x $helper && -f $template && -f /active ]]
[[ $(cat "$helper") == "$(cat /bundle/core/connect-hub-capture)" ]]
[[ $(cat /calls) == *"enable --now $unit"* ]]
passed 'fresh install'

reset_case
old_helper
: > /active
bash /bundle/install-capture-helper.sh --uid 1000 >/result
calls=$(cat /calls)
[[ $calls == *"stop $unit"*"old-helper --uid=1000 --recover"*"enable --now $unit"* ]]
[[ $(cat "$helper") == "$(cat /bundle/core/connect-hub-capture)" ]]
passed 'upgrade cleans old helper before replacement'

reset_case
old_helper
expected=$(cat "$helper")
export RECOVER_FAIL=1
expect_failure 1 bash /bundle/install-capture-helper.sh --uid 1000
unset RECOVER_FAIL
[[ $(cat "$helper") == "$expected" && ! -e $template && ! -e /active ]]
passed 'failed recovery preserves old executable and stops installation'

reset_case
old_helper
expected=$(cat "$helper")
printf 'connect-hub-capture@2000.service loaded active running\n' > /running
expect_failure 1 bash /bundle/install-capture-helper.sh --uid 1000
[[ $(cat "$helper") == "$expected" && ! -e $template ]]
[[ $(cat /calls) != *"old-helper"* ]]
passed 'another user prevents shared upgrade'

reset_case
old_helper
expected=$(cat "$helper")
: > /active
export CANDIDATE_PROTOCOL=8
expect_failure 1 bash /bundle/install-capture-helper.sh --uid 1000
unset CANDIDATE_PROTOCOL
[[ $(cat "$helper") == "$expected" && -f /active && ! -s /calls ]]
passed 'old candidate protocol is refused before stopping existing service'

# 旧的（改名前的）助手必须先被撤掉，否则两个特权服务会抢同一套网络规则。
reset_case
legacy=/usr/local/libexec/easyconnect-hub-capture
legacy_template=/etc/systemd/system/easyconnect-hub-capture@.service
cat > "$legacy" <<'OLD'
#!/bin/bash
printf 'legacy-helper %s\n' "$*" >> /calls
OLD
chmod +x "$legacy"
: > "$legacy_template"
: > /active
bash /bundle/install-capture-helper.sh --uid 1000 >/result
calls=$(cat /calls)
[[ ! -e $legacy && ! -e $legacy_template ]]
[[ -x $helper && -f $template && -f /active ]]
[[ $calls == *"legacy-helper --uid=1000 --recover"* ]]
[[ $calls == *"enable --now $unit"* ]]
passed 'upgrade removes the pre-rename helper before installing the new one'

reset_case
old_helper
: > "$template"
printf 'connect-hub-capture@2000.service enabled\n' > /enabled
bash /bundle/uninstall-capture-helper.sh --uid 1000 >/result
[[ -x $helper && -f $template ]]
[[ $(cat /calls) == *"old-helper --uid=1000 --recover"*"disable $unit"* ]]
passed 'uninstall preserves another installed user'

reset_case
old_helper
: > "$template"
bash /bundle/uninstall-capture-helper.sh --uid 1000 >/result
[[ ! -e $helper && ! -e $template ]]
[[ $(cat /calls) == *"old-helper --uid=1000 --recover"*"disable $unit"*"daemon-reload"* ]]
passed 'last-user uninstall recovers before removal'

reset_case
old_helper
: > "$template"
export RECOVER_FAIL=1
expect_failure 1 bash /bundle/uninstall-capture-helper.sh --uid 1000
unset RECOVER_FAIL
[[ -x $helper && -f $template ]]
[[ $(cat /calls) != *"disable $unit"* ]]
passed 'failed uninstall recovery preserves files and enabled state'

reset_case
mkdir -m 0755 /run/connect-hub-capture
exec {held_lock}>/run/connect-hub-capture/installer.lock
flock -n "$held_lock"
expect_failure 75 bash /bundle/install-capture-helper.sh --uid 1000
expect_failure 75 bash /bundle/uninstall-capture-helper.sh --uid 1000
exec {held_lock}>&-
[[ ! -e $helper && ! -s /calls ]]
passed 'concurrent maintenance is rejected'

reset_case
mkdir -m 0755 /run/connect-hub-capture
ln -s /calls /run/connect-hub-capture/installer.lock
expect_failure 1 bash /bundle/install-capture-helper.sh --uid 1000
expect_failure 1 bash /bundle/uninstall-capture-helper.sh --uid 1000
[[ ! -s /calls ]]
passed 'symlink lock is rejected'
CHECK
: > "$test_root/.setup-sandbox"
export EASYCONNECT_SETUP_SANDBOX=1
unshare --user --map-root-user chroot "$test_root" /bin/bash /check.sh
