#!/usr/bin/env bash
set -euo pipefail

bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
capture_uid=${SUDO_UID:-${PKEXEC_UID:-}}
if [[ ${1:-} == --uid && $# == 2 ]]; then
  capture_uid=$2
elif (( $# != 0 )); then
  printf 'Usage: sudo %s [--uid UID]\n' "$0" >&2
  exit 1
fi
if (( EUID != 0 )); then
  printf 'Installing the network helper requires system authorization. Run: sudo %s\n' "$0" >&2
  exit 1
fi
if [[ ! "$capture_uid" =~ ^[1-9][0-9]{0,9}$ ]] || ! getent passwd "$capture_uid" >/dev/null; then
  printf 'A valid non-root desktop UID is required; use --uid UID when running directly as root.\n' >&2
  exit 1
fi
for capture_tool in /usr/bin/ip /usr/bin/nft /usr/bin/busctl /usr/bin/systemd-run /usr/bin/systemctl /usr/bin/flock; do
  test -x "$capture_tool" || { printf 'Missing dependency: %s\n' "$capture_tool" >&2; exit 1; }
done
# 内部程序在 core/ 里；平铺位置留给拆分前的包。
capture_helper="$bundle_dir/core/connect-hub-capture"
if [[ ! -x "$capture_helper" ]]; then
  capture_helper="$bundle_dir/connect-hub-capture"
fi
if [[ ! -x "$capture_helper" ]]; then
  printf 'Missing capture helper in bundle: %s (expected core/ or the bundle root)\n' "$capture_helper" >&2
  exit 1
fi
test -f "$bundle_dir/connect-hub-capture@.service"
capture_protocol=$("$capture_helper" --protocol-version)
if [[ "$capture_protocol" != 11 ]]; then
  printf 'Capture helper protocol mismatch: expected 11, got %s. Replace the complete bundle.\n' "$capture_protocol" >&2
  exit 1
fi
capture_unit="connect-hub-capture@${capture_uid}.service"

# Everything the pre-rename helper installed. It is removed in the same
# transaction as the new one is installed, so an upgrade cannot leave two
# privileged services fighting over the same network rules.
capture_legacy_name=easyconnect-hub-capture
capture_legacy_unit="${capture_legacy_name}@${capture_uid}.service"

# Serialize GUI and terminal installations/uninstalls, across desktop users.
# Keep this separate from the helper's network transaction lock: recovery uses
# that lock while an installer waits for the system service to stop.
capture_setup_dir=/run/connect-hub-capture
capture_legacy_setup_dir=/run/${capture_legacy_name}
for dir in "$capture_setup_dir" "$capture_legacy_setup_dir"; do
  if [[ ! -e "$dir" ]]; then
    install -d -o root -g root -m 0755 "$dir"
  fi
  if [[ -L "$dir" || ! -d "$dir" || $(stat -c '%u:%a' "$dir") != 0:755 ]]; then
    printf 'Unsafe installer state directory: %s\n' "$dir" >&2
    exit 1
  fi
done
# The lock lives in the new directory; the legacy one only keeps its own lock so
# an interrupted old installer is respected instead of being raced.
capture_setup_lock="$capture_setup_dir/installer.lock"
if [[ -L "$capture_setup_lock" || ( -e "$capture_setup_lock" && ! -f "$capture_setup_lock" ) ]]; then
  printf 'Unsafe installer lock\n' >&2
  exit 1
fi
exec {capture_setup_fd}>"$capture_setup_lock"
if ! /usr/bin/flock -n "$capture_setup_fd"; then
  printf 'Another helper installation or removal is in progress\n' >&2
  exit 75
fi

# The binary and service template are shared. Do not upgrade them underneath
# another user's running helper or interrupt that user's network leases.
capture_units=$(systemctl list-units 'connect-hub-capture@*.service' 'easyconnect-hub-capture@*.service' --state=active,activating,deactivating,reloading --plain --no-legend --no-pager)
while read -r capture_name capture_rest; do
  case "$capture_name" in
    connect-hub-capture@*.service|easyconnect-hub-capture@*.service)
      if [[ "$capture_name" != "$capture_unit" && "$capture_name" != "$capture_legacy_unit" ]]; then
        printf 'Another user helper is running (%s); stop it before upgrading the shared helper.\n' "$capture_name" >&2
        exit 1
      fi
      ;;
  esac
done <<< "$capture_units"

# A running instance must finish ownership cleanup before its binary changes.
if systemctl is-active --quiet "$capture_unit"; then
  systemctl stop "$capture_unit"
fi
if [[ -x /usr/local/libexec/connect-hub-capture ]]; then
  /usr/local/libexec/connect-hub-capture --uid="$capture_uid" --recover
fi

# Migrate away from the pre-rename helper: stop it, let it undo its network
# changes, then remove its unit, binary and runtime directories.
capture_legacy_present=false
if [[ -e "/etc/systemd/system/${capture_legacy_name}@.service" ]]; then
  capture_legacy_present=true
elif [[ -n "$(systemctl list-unit-files "${capture_legacy_name}@*.service" --no-legend --no-pager 2>/dev/null || true)" ]]; then
  capture_legacy_present=true
fi
if [[ "$capture_legacy_present" == true ]]; then
  if systemctl is-active --quiet "$capture_legacy_unit"; then
    systemctl stop "$capture_legacy_unit" || true
  fi
  systemctl disable "$capture_legacy_unit" >/dev/null 2>&1 || true
  if [[ -x /usr/local/libexec/${capture_legacy_name} ]]; then
    /usr/local/libexec/${capture_legacy_name} --uid="$capture_uid" --recover >/dev/null 2>&1 || true
  fi
  rm -f -- "/etc/systemd/system/${capture_legacy_name}@.service" "/usr/local/libexec/${capture_legacy_name}"
  rm -rf -- "/run/${capture_legacy_name}" "/run/${capture_legacy_name}-${capture_uid}"
  systemctl daemon-reload
  printf 'Removed the pre-rename helper (%s@%s.service).\n' "$capture_legacy_name" "$capture_uid"
fi

install -d -o root -g root -m 0755 /usr/local/libexec
capture_staging=$(mktemp /usr/local/libexec/.connect-hub-capture.XXXXXXXX)
trap 'rm -f -- "$capture_staging"' EXIT
install -o root -g root -m 0755 "$capture_helper" "$capture_staging"
mv -f -- "$capture_staging" /usr/local/libexec/connect-hub-capture
install -o root -g root -m 0644 "$bundle_dir/connect-hub-capture@.service" /etc/systemd/system/connect-hub-capture@.service
systemctl daemon-reload
systemctl reset-failed "$capture_unit" >/dev/null 2>&1 || true
systemctl enable --now "$capture_unit"
systemctl is-active --quiet "$capture_unit"
printf 'Capture helper installed for UID %s. Programs still run as your desktop user.\n' "$capture_uid"
