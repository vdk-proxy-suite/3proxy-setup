#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
parse_config_arg "$@"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="$BACKUP_ROOT/$timestamp"
install -d -m 700 "$BACKUP_DIR"

[[ -f /usr/local/bin/3proxy ]] && cp -a /usr/local/bin/3proxy "$BACKUP_DIR/3proxy"
[[ -f /etc/3proxy/3proxy.cfg ]] && cp -a /etc/3proxy/3proxy.cfg "$BACKUP_DIR/3proxy.cfg"
[[ -f /etc/systemd/system/3proxy.service ]] && cp -a /etc/systemd/system/3proxy.service "$BACKUP_DIR/3proxy.service"
[[ -f /usr/local/share/3proxy-build/manifest.json ]] && cp -a /usr/local/share/3proxy-build/manifest.json "$BACKUP_DIR/build-manifest.json"
install -m 600 "$CONFIG" "$BACKUP_DIR/config.yaml"

(
  cd "$BACKUP_DIR"
  sha256sum ./* > SHA256SUMS
)
printf 'BACKUP_DIR=%s\n' "$BACKUP_DIR" > "$STATE_FILE"
chmod 600 "$STATE_FILE"

echo "==> Backup saved: $BACKUP_DIR"
systemctl stop 3proxy 2>/dev/null || true

for _ in {1..10}; do
  pgrep -x 3proxy >/dev/null 2>&1 || break
  sleep 1
done
if pgrep -x 3proxy >/dev/null 2>&1; then
  pkill -TERM -x 3proxy || true
  sleep 2
fi
if pgrep -x 3proxy >/dev/null 2>&1; then
  pkill -KILL -x 3proxy || true
fi

if pgrep -x 3proxy >/dev/null 2>&1; then
  echo "Unable to stop all 3proxy processes" >&2
  exit 1
fi
echo "==> 3proxy processes stopped"
