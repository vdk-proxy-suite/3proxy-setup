#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
source "$SETUP_ROOT/lib/tls.sh"
require_root
parse_config_arg --check-listeners "$@"
python3 "$SETUP_ROOT/tools/acme.py" preflight --config "$CONFIG"

systemctl stop "$SERVICE" 2>/dev/null || true
if systemctl is-active --quiet "$SERVICE"; then echo "Selected service is still active" >&2; exit 1; fi

getent group proxy-observability >/dev/null || groupadd --system proxy-observability
config_mode=750
log_mode=2750
if [[ -z "$INSTANCE_ID" ]]; then config_mode=755; fi
install -d -m "$config_mode" -o root -g "$SERVICE_GROUP" "$CONFIG_DIR"
if [[ -f "$INSTANCE_STATE/pending-client-ca.crt" ]]; then
  install -m 644 "$INSTANCE_STATE/pending-client-ca.crt" "$CONFIG_DIR/client-ca.crt"
  rm -f -- "$INSTANCE_STATE/pending-client-ca.crt"
fi
set_managed_tls_paths "$CONFIG_DIR/tls"
if [[ -n "$INSTANCE_ID" ]]; then
  install -d -m 750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$DATA_DIR"
elif [[ ! -d "$DATA_DIR" ]]; then
  install -d -m 755 "$DATA_DIR"
fi
prepare_managed_tls
if [[ -d "$CONFIG_DIR/tls" ]]; then
  chown root:"$SERVICE_GROUP" "$CONFIG_DIR/tls" "$CONFIG_DIR/tls/server.key"
  chmod 750 "$CONFIG_DIR/tls"
  chmod 640 "$CONFIG_DIR/tls/server.key"
fi
install -d -o "$SERVICE_USER" -g proxy-observability -m "$log_mode" ${LOG_DIR}
python3 "$SETUP_ROOT/tools/instance.py" prepare-log "$@"

tmp_cfg="$(mktemp ${CONFIG_DIR}/3proxy.cfg.XXXXXX)"
tmp_unit="$(mktemp ${UNIT_FILE}.XXXXXX)"
cleanup() { rm -f -- "$tmp_cfg" "$tmp_unit"; }
trap cleanup EXIT

python3 "$SETUP_ROOT/tools/config.py" render-3proxy --config "$CONFIG" --output "$tmp_cfg"
python3 "$SETUP_ROOT/tools/config.py" render-systemd --config "$CONFIG" --output "$tmp_unit"
chown root:"$SERVICE_GROUP" "$tmp_cfg"
chmod 640 "$tmp_cfg"
chmod 644 "$tmp_unit"
mv -f "$tmp_cfg" ${CONFIG_DIR}/3proxy.cfg
python3 "$SETUP_ROOT/tools/instance.py" unit-intent --unit-file "$tmp_unit" "$@"
mv -f "$tmp_unit" ${UNIT_FILE}

marker=${INSTANCE_STATE}/monitor-v1-migrated
if [[ -s ${LOG_DIR}/3proxy.log && ! -f "$marker" ]]; then
  install -d -m 700 ${INSTANCE_STATE}
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  gzip -c ${LOG_DIR}/3proxy.log > "${LOG_DIR}/3proxy.log.pre-monitor-$stamp.gz"
  chown "$SERVICE_USER":proxy-observability "${LOG_DIR}/3proxy.log.pre-monitor-$stamp.gz"
  chmod 640 "${LOG_DIR}/3proxy.log.pre-monitor-$stamp.gz"
  : > ${LOG_DIR}/3proxy.log
  touch "$marker"
  chmod 600 "$marker"
  echo "==> Archived the legacy log before monitor_v1 migration"
fi

if [[ "$(readlink -f "$CONFIG")" != "$CONFIG_DIR/setup.yaml" ]]; then
  install -m 600 "$CONFIG" "$CONFIG_DIR/setup.yaml"
fi
echo "==> Generated ${CONFIG_DIR}/3proxy.cfg and systemd unit"

python3 "$SETUP_ROOT/tools/instance.py" configure-firewall "$@"
