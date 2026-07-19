#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
parse_config_arg "$@"

getent group proxy-observability >/dev/null || groupadd --system proxy-observability
install -d -m 755 /etc/3proxy
install -d -o root -g proxy-observability -m 2750 /var/log/3proxy
touch /var/log/3proxy/3proxy.log
chown root:proxy-observability /var/log/3proxy/3proxy.log
chmod 640 /var/log/3proxy/3proxy.log

tmp_cfg="$(mktemp /etc/3proxy/3proxy.cfg.XXXXXX)"
tmp_unit="$(mktemp /etc/systemd/system/3proxy.service.XXXXXX)"
cleanup() { rm -f -- "$tmp_cfg" "$tmp_unit"; }
trap cleanup EXIT

python3 "$SETUP_ROOT/tools/config.py" render-3proxy --config "$CONFIG" --output "$tmp_cfg"
python3 "$SETUP_ROOT/tools/config.py" render-systemd --output "$tmp_unit"
chmod 600 "$tmp_cfg"
chmod 644 "$tmp_unit"
mv -f "$tmp_cfg" /etc/3proxy/3proxy.cfg
mv -f "$tmp_unit" /etc/systemd/system/3proxy.service

marker=/var/lib/3proxy-setup/monitor-v1-migrated
if [[ -s /var/log/3proxy/3proxy.log && ! -f "$marker" ]]; then
  install -d -m 700 /var/lib/3proxy-setup
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  gzip -c /var/log/3proxy/3proxy.log > "/var/log/3proxy/3proxy.log.pre-monitor-$stamp.gz"
  chown root:proxy-observability "/var/log/3proxy/3proxy.log.pre-monitor-$stamp.gz"
  chmod 640 "/var/log/3proxy/3proxy.log.pre-monitor-$stamp.gz"
  : > /var/log/3proxy/3proxy.log
  touch "$marker"
  chmod 600 "$marker"
  echo "==> Archived the legacy log before monitor_v1 migration"
fi

install -m 600 "$CONFIG" /etc/3proxy/setup.yaml
echo "==> Generated /etc/3proxy/3proxy.cfg and systemd unit"

if [[ "$(yaml_get server.manage_ufw)" == "true" ]] && command -v ufw >/dev/null 2>&1; then
  if ufw status | grep -q "Status: active"; then
    while IFS= read -r port; do ufw allow "$port/tcp"; done < <(python3 "$SETUP_ROOT/tools/config.py" ports --config "$CONFIG")
    cidr="$(yaml_get server.udp_client_cidr)"
    ufw allow from "$cidr" to any port 1024:65535 proto udp
  fi
else
  echo "==> Firewall management disabled; ensure TCP listeners and dynamic UDP relay ports are allowed"
fi
