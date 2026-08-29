#!/usr/bin/env bash
set -Eeuo pipefail

SETUP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_FILE="/run/3proxy-setup.state"
BACKUP_ROOT="/var/backups/3proxy"

require_root() {
  [[ $EUID -eq 0 ]] || { echo "This step must run as root" >&2; exit 1; }
}

require_file() {
  [[ -f "$1" ]] || { echo "Required file not found: $1" >&2; exit 1; }
}

parse_config_arg() {
  CONFIG="$SETUP_ROOT/config.yaml"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config) CONFIG="${2:?--config requires a path}"; shift 2 ;;
      *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
  done
  require_file "$CONFIG"
  python3 "$SETUP_ROOT/tools/config.py" validate --config "$CONFIG"
}

yaml_get() {
  python3 "$SETUP_ROOT/tools/config.py" get --config "$CONFIG" --path "$1"
}

load_backup_state() {
  [[ -f "$STATE_FILE" ]] || return 1
  BACKUP_DIR="$(sed -n 's/^BACKUP_DIR=//p' "$STATE_FILE")"
  [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]]
}

restore_latest_backup() {
  load_backup_state || { echo "No backup state available; rollback skipped" >&2; return 1; }
  echo "==> Restoring backup: $BACKUP_DIR"
  systemctl stop 3proxy 2>/dev/null || true
  if [[ -f "$BACKUP_DIR/3proxy" ]]; then
    install -m 755 "$BACKUP_DIR/3proxy" /usr/local/bin/3proxy
  else
    rm -f -- /usr/local/bin/3proxy
  fi
  if [[ -f "$BACKUP_DIR/3proxy.cfg" ]]; then
    install -D -m 600 "$BACKUP_DIR/3proxy.cfg" /etc/3proxy/3proxy.cfg
  else
    rm -f -- /etc/3proxy/3proxy.cfg
  fi
  if [[ -f "$BACKUP_DIR/setup.yaml" ]]; then
    install -D -m 600 "$BACKUP_DIR/setup.yaml" /etc/3proxy/setup.yaml
  else
    rm -f -- /etc/3proxy/setup.yaml
  fi
  rm -rf -- /etc/3proxy/tls
  if [[ -d "$BACKUP_DIR/tls" ]]; then
    install -d -m 755 /etc/3proxy
    cp -a "$BACKUP_DIR/tls" /etc/3proxy/tls
  fi
  if [[ -f "$BACKUP_DIR/3proxy.service" ]]; then
    install -D -m 644 "$BACKUP_DIR/3proxy.service" /etc/systemd/system/3proxy.service
  else
    rm -f -- /etc/systemd/system/3proxy.service
  fi
  if [[ -f "$BACKUP_DIR/build-manifest.json" ]]; then
    install -D -m 644 "$BACKUP_DIR/build-manifest.json" /usr/local/share/3proxy-build/manifest.json
  else
    rm -f -- /usr/local/share/3proxy-build/manifest.json
  fi
  systemctl daemon-reload
  if [[ -f /etc/systemd/system/3proxy.service ]]; then
    systemctl enable 3proxy >/dev/null
    systemctl restart 3proxy
  fi
}
