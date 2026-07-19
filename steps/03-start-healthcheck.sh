#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
parse_config_arg "$@"

systemctl daemon-reload
systemctl enable 3proxy >/dev/null
systemctl restart 3proxy

for _ in {1..10}; do
  systemctl is-active --quiet 3proxy && break
  sleep 1
done
if ! systemctl is-active --quiet 3proxy; then
  systemctl status 3proxy --no-pager -l >&2 || true
  exit 1
fi

install -d -m 755 /var/log/3proxy/healthchecks
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
report="/var/log/3proxy/healthchecks/$stamp.json"
set +e
python3 "$SETUP_ROOT/tools/healthcheck.py" --config "$CONFIG" --scope vm --json "$report"
health_rc=$?
set -e
cp -f "$report" /var/log/3proxy/healthchecks/latest.json
if [[ $health_rc -ne 0 ]]; then
  echo "==> Health-check reports degraded endpoints (non-blocking): $report"
else
  echo "==> Health-check passed: $report"
fi
exit 0
