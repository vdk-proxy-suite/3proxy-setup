#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
parse_config_arg "$@"

timestamp="$(date -u +%Y%m%dT%H%M%S%NZ)"
BACKUP_DIR="$BACKUP_ROOT/$timestamp"
umask 077
install -d -m 700 "$BACKUP_DIR"

[[ -f ${BINARY} ]] && cp -a ${BINARY} "$BACKUP_DIR/3proxy"
[[ -f ${CONFIG_DIR}/3proxy.cfg ]] && cp -a ${CONFIG_DIR}/3proxy.cfg "$BACKUP_DIR/3proxy.cfg"
[[ -f ${CONFIG_DIR}/setup.yaml ]] && cp -a ${CONFIG_DIR}/setup.yaml "$BACKUP_DIR/setup.yaml"
[[ -f ${CONFIG_DIR}/client-ca.crt ]] && cp -a ${CONFIG_DIR}/client-ca.crt "$BACKUP_DIR/client-ca.crt"
[[ -d ${CONFIG_DIR}/tls ]] && cp -a ${CONFIG_DIR}/tls "$BACKUP_DIR/tls"
[[ -f ${UNIT_FILE} ]] && cp -a ${UNIT_FILE} "$BACKUP_DIR/3proxy.service"
[[ -f ${BUILD_MANIFEST} ]] && cp -a ${BUILD_MANIFEST} "$BACKUP_DIR/build-manifest.json"
install -m 600 "$CONFIG" "$BACKUP_DIR/requested-config.yaml"
python3 "$SETUP_ROOT/tools/acme.py" backup --config "$CONFIG" --directory "$BACKUP_DIR"
if systemctl is-active --quiet "$SERVICE"; then touch "$BACKUP_DIR/active"; fi
if systemctl is-enabled --quiet "$SERVICE"; then touch "$BACKUP_DIR/enabled"; fi

(
  cd "$BACKUP_DIR"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
printf 'BACKUP_DIR=%s\n' "$BACKUP_DIR" > "$STATE_FILE"
chmod 600 "$STATE_FILE"

echo "==> Backup saved: $BACKUP_DIR"
systemctl stop "$SERVICE" 2>/dev/null || true

if systemctl is-active --quiet "$SERVICE"; then
  echo "Unable to stop selected service: $SERVICE" >&2
  exit 1
fi
echo "==> Selected service stopped: $SERVICE"
