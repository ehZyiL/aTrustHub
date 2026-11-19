#!/usr/bin/env bash
set -euo pipefail

capture_uid=${SUDO_UID:-${PKEXEC_UID:-}}
if [[ ${1:-} == --uid && $# == 2 ]]; then
  capture_uid=$2
elif (( $# != 0 )); then
  printf 'Usage: sudo %s [--uid UID]\n' "$0" >&2
  exit 1
fi
if (( EUID != 0 )) || [[ ! "$capture_uid" =~ ^[1-9][0-9]{0,9}$ ]]; then
  printf 'Run with sudo from the authorized desktop user, or specify --uid UID as root.\n' >&2
  exit 1
fi
capture_unit="easyconnect-hub-capture@${capture_uid}.service"
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
systemctl stop "$capture_unit"
if [[ -x /usr/local/libexec/easyconnect-hub-capture ]]; then
  /usr/local/libexec/easyconnect-hub-capture --uid="$capture_uid" --recover
fi
systemctl disable "$capture_unit"
# Keep a shared executable if another user's instance is installed or running.
capture_other=false
capture_installed=$(systemctl list-unit-files 'easyconnect-hub-capture@*.service' --state=enabled --no-legend --no-pager)
capture_running=$(systemctl list-units 'easyconnect-hub-capture@*.service' --state=active,activating,deactivating,reloading --plain --no-legend --no-pager)
while read -r capture_name capture_state capture_rest; do
  if [[ "$capture_name" == easyconnect-hub-capture@*.service && "$capture_name" != "$capture_unit" && "$capture_name" != easyconnect-hub-capture@.service ]]; then
    capture_other=true
  fi
done <<< "$capture_installed"
while read -r capture_name capture_rest; do
  if [[ "$capture_name" == easyconnect-hub-capture@*.service && "$capture_name" != "$capture_unit" ]]; then
    capture_other=true
  fi
done <<< "$capture_running"
if [[ "$capture_other" == false ]]; then
  rm -f -- /etc/systemd/system/easyconnect-hub-capture@.service /usr/local/libexec/easyconnect-hub-capture
  systemctl daemon-reload
fi
printf 'Capture helper disabled for UID %s; its owned network rules have been removed.\n' "$capture_uid"
