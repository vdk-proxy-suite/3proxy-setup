#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
parse_config_arg "$@"

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null
systemctl restart "$SERVICE"

for _ in {1..10}; do
  systemctl is-active --quiet "$SERVICE" && break
  sleep 1
done
if ! systemctl is-active --quiet "$SERVICE"; then
  systemctl status "$SERVICE" --no-pager -l >&2 || true
  exit 1
fi

https_listener_state="$(python3 "$SETUP_ROOT/tools/config.py" has-https-listener --config "$CONFIG")"
if [[ "$https_listener_state" == "true" ]]; then
  echo "==> Running mandatory TLS-first checks for HTTPS listeners"
  https_listener_ids="$(python3 "$SETUP_ROOT/tools/config.py" https-listeners --config "$CONFIG")"
  while IFS= read -r listener_id; do
    [[ -n "$listener_id" ]] || continue
    python3 "$SETUP_ROOT/tools/healthcheck.py" \
      --config "$CONFIG" --scope vm --endpoint "$listener_id" --tls-gate-only
  done <<< "$https_listener_ids"
fi

install -d -m 755 ${LOG_DIR}/healthchecks
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
report="${LOG_DIR}/healthchecks/$stamp.json"
set +e
python3 "$SETUP_ROOT/tools/healthcheck.py" --config "$CONFIG" --scope vm --json "$report"
health_rc=$?
set -e
cp -f "$report" ${LOG_DIR}/healthchecks/latest.json
if [[ $health_rc -ne 0 ]]; then
  echo "==> Health-check reports degraded endpoints (non-blocking): $report"
else
  echo "==> Health-check passed: $report"
fi
exit 0
