#!/usr/bin/env bash
set -Eeuo pipefail

SETUP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"


require_root() {
  [[ $EUID -eq 0 ]] || { echo "This step must run as root" >&2; exit 1; }
}

require_file() {
  [[ -f "$1" ]] || { echo "Required file not found: $1" >&2; exit 1; }
}

parse_config_arg() {
  local settings
  settings="$(python3 "$SETUP_ROOT/tools/instance.py" env "$@")"
  eval "$settings"
  require_file "$CONFIG"
  python3 "$SETUP_ROOT/tools/config.py" validate --config "$CONFIG"
  local operation=prepare argument
  for argument in "$@"; do [[ "$argument" != --existing ]] || operation=verify; done
  python3 "$SETUP_ROOT/tools/instance.py" "$operation" "$@"
  if [[ "$operation" == prepare ]]; then CONFIG="$INSTANCE_STATE/requested.yaml"; fi
}

yaml_get() {
  python3 "$SETUP_ROOT/tools/config.py" get --config "$CONFIG" --path "$1"
}

load_backup_state() {
  [[ -f "$STATE_FILE" ]] || return 1
  BACKUP_DIR="$(sed -n 's/^BACKUP_DIR=//p' "$STATE_FILE")"
  [[ -n "$BACKUP_DIR" && "$BACKUP_DIR" == "$BACKUP_ROOT/"* && -d "$BACKUP_DIR" && ! -L "$BACKUP_DIR" ]]
}

restore_latest_backup() {
  load_backup_state || { echo "No backup state available; rollback skipped" >&2; return 1; }
  echo "==> Restoring backup: $BACKUP_DIR"
  systemctl stop "$SERVICE" 2>/dev/null || true
  if systemctl is-active --quiet "$SERVICE"; then echo "Rollback cannot stop $SERVICE" >&2; return 1; fi
  if [[ -f "$BACKUP_DIR/3proxy" ]]; then
    install -m 755 "$BACKUP_DIR/3proxy" ${BINARY}
  else
    rm -f -- ${BINARY}
  fi
  if [[ -f "$BACKUP_DIR/3proxy.cfg" ]]; then
    install -D -m 640 -o root -g "$SERVICE_GROUP" "$BACKUP_DIR/3proxy.cfg" ${CONFIG_DIR}/3proxy.cfg
  else
    rm -f -- ${CONFIG_DIR}/3proxy.cfg
  fi
  if [[ -f "$BACKUP_DIR/setup.yaml" ]]; then
    install -D -m 600 "$BACKUP_DIR/setup.yaml" ${CONFIG_DIR}/setup.yaml
    install -m 600 "$BACKUP_DIR/setup.yaml" "$INSTANCE_STATE/requested.yaml"
  else
    rm -f -- ${CONFIG_DIR}/setup.yaml
  fi
  if [[ -f "$BACKUP_DIR/client-ca.crt" ]]; then
    install -m 644 "$BACKUP_DIR/client-ca.crt" "$CONFIG_DIR/client-ca.crt"
  else
    rm -f -- "$CONFIG_DIR/client-ca.crt"
  fi
  rm -f -- "$INSTANCE_STATE/pending-client-ca.crt"
  rm -rf -- ${CONFIG_DIR}/tls
  if [[ -d "$BACKUP_DIR/tls" ]]; then
    install -d -m 755 ${CONFIG_DIR}
    cp -a "$BACKUP_DIR/tls" ${CONFIG_DIR}/tls
  fi
  if [[ -f "$BACKUP_DIR/3proxy.service" ]]; then
    install -D -m 644 "$BACKUP_DIR/3proxy.service" ${UNIT_FILE}
  else
    systemctl disable "$SERVICE" >/dev/null 2>&1 || true
    rm -f -- ${UNIT_FILE}
  fi
  if [[ -f "$BACKUP_DIR/build-manifest.json" ]]; then
    install -D -m 644 "$BACKUP_DIR/build-manifest.json" ${BUILD_MANIFEST}
  else
    rm -f -- ${BUILD_MANIFEST}
  fi
  systemctl daemon-reload
  if [[ -f ${UNIT_FILE} ]]; then
    if [[ -f "$BACKUP_DIR/enabled" ]]; then
      systemctl enable "$SERVICE" >/dev/null
    else
      systemctl disable "$SERVICE" >/dev/null
    fi
    if [[ -f "$BACKUP_DIR/active" ]]; then systemctl restart "$SERVICE"; fi
  fi
}
