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
capture_helper="$bundle_dir/core/easyconnect-hub-capture"
if [[ ! -x "$capture_helper" ]]; then
  capture_helper="$bundle_dir/easyconnect-hub-capture"
fi
if [[ ! -x "$capture_helper" ]]; then
  printf 'Missing capture helper in bundle: %s (expected core/ or the bundle root)\n' "$capture_helper" >&2
  exit 1
fi
test -f "$bundle_dir/easyconnect-hub-capture@.service"
capture_protocol=$("$capture_helper" --protocol-version)
if [[ "$capture_protocol" != 10 ]]; then
  printf 'Capture helper protocol mismatch: expected 10, got %s. Replace the complete bundle.\n' "$capture_protocol" >&2
  exit 1
fi
capture_unit="easyconnect-hub-capture@${capture_uid}.service"

# Serialize GUI and terminal installations/uninstalls, across desktop users.
# Keep this separate from the helper's network transaction lock: recovery uses
# that lock while an installer waits for the system service to stop.
capture_setup_dir=/run/easyconnect-hub-capture
if [[ ! -e "$capture_setup_dir" ]]; then
  install -d -o root -g root -m 0755 "$capture_setup_dir"
fi
if [[ -L "$capture_setup_dir" || ! -d "$capture_setup_dir" || $(stat -c '%u:%a' "$capture_setup_dir") != 0:755 ]]; then
  printf 'Unsafe installer state directory\n' >&2
  exit 1
fi
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
capture_units=$(systemctl list-units 'easyconnect-hub-capture@*.service' --state=active,activating,deactivating,reloading --plain --no-legend --no-pager)
while read -r capture_name capture_rest; do
  if [[ "$capture_name" == easyconnect-hub-capture@*.service && "$capture_name" != "$capture_unit" ]]; then
    printf 'Another user helper is running (%s); stop it before upgrading the shared helper.\n' "$capture_name" >&2
    exit 1
  fi
done <<< "$capture_units"

# A running instance must finish ownership cleanup before its binary changes.
if systemctl is-active --quiet "$capture_unit"; then
  systemctl stop "$capture_unit"
fi
if [[ -x /usr/local/libexec/easyconnect-hub-capture ]]; then
  /usr/local/libexec/easyconnect-hub-capture --uid="$capture_uid" --recover
fi
install -d -o root -g root -m 0755 /usr/local/libexec
capture_staging=$(mktemp /usr/local/libexec/.easyconnect-hub-capture.XXXXXXXX)
trap 'rm -f -- "$capture_staging"' EXIT
install -o root -g root -m 0755 "$capture_helper" "$capture_staging"
mv -f -- "$capture_staging" /usr/local/libexec/easyconnect-hub-capture
install -o root -g root -m 0644 "$bundle_dir/easyconnect-hub-capture@.service" /etc/systemd/system/easyconnect-hub-capture@.service
systemctl daemon-reload
systemctl reset-failed "$capture_unit" >/dev/null 2>&1 || true
systemctl enable --now "$capture_unit"
systemctl is-active --quiet "$capture_unit"
printf 'Capture helper installed for UID %s. Programs still run as your desktop user.\n' "$capture_uid"
