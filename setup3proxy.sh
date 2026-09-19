#!/usr/bin/env bash
set -Eeuo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTION="${1:-all}"
if [[ $# -gt 0 ]]; then shift; fi
case "$ACTION" in
  -h|--help) echo "Usage: $0 [all|update|reconfigure|0|1|2|3|start|stop|status|healthcheck|backup|rollback|cleanup] [--instance ID] [--config PATH] [--update-existing] [--legacy]"; exit 0 ;;
  cleanup) exec "$BASE_DIR/clean3proxy.sh" "$@" ;;
  all|update|reconfigure|0|1|2|3|start|stop|status|healthcheck|backup|rollback) ;;
  *) echo "Unknown action: $ACTION" >&2; exit 2 ;;
esac
if [[ $EUID -ne 0 ]]; then echo "Run as root" >&2; exit 1; fi
if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import yaml' >/dev/null 2>&1; then
  echo "Install parser dependencies explicitly: apt-get install python3 python3-yaml" >&2
  exit 1
fi
source "$BASE_DIR/lib/common.sh"
settings="$(python3 "$BASE_DIR/tools/instance.py" env "$@")"
eval "$settings"
python3 "$BASE_DIR/tools/config.py" validate --config "$CONFIG"
case "$ACTION" in
  status|start|stop)
    python3 "$BASE_DIR/tools/instance.py" verify "$@"
    exec systemctl "$ACTION" "$SERVICE" ;;

  healthcheck) exec python3 "$BASE_DIR/tools/healthcheck.py" --config "$CONFIG" --scope vm ;;
  backup|rollback) python3 "$BASE_DIR/tools/instance.py" verify "$@" ;;
esac
prepare_args=()
case "$ACTION" in all|update|reconfigure|2) prepare_args+=(--check-listeners) ;; esac
case "$ACTION" in backup|rollback) ;; *) python3 "$BASE_DIR/tools/instance.py" prepare "${prepare_args[@]}" "$@" ;; esac
case "$ACTION" in backup|rollback) ;; *) CONFIG="$INSTANCE_STATE/requested.yaml" ;; esac
step_args=(--config "$CONFIG")
[[ -n "$INSTANCE_ID" ]] || step_args+=(--legacy)
case "$ACTION" in backup|rollback) step_args+=(--existing) ;; esac
rollback_armed=0
on_error() {
  local rc=$?
  trap - ERR
  if [[ $rollback_armed -eq 1 ]]; then restore_latest_backup || true; fi
  exit "$rc"
}
trap on_error ERR
run_step() { bash "$BASE_DIR/steps/${1}-"*.sh "${step_args[@]}"; }
case "$ACTION" in
  all|update) run_step 00; rollback_armed=1; run_step 01; run_step 02; run_step 03; rollback_armed=0 ;;
  reconfigure) run_step 00; rollback_armed=1; run_step 02; run_step 03; rollback_armed=0 ;;
  0|1|2|3) run_step "0$ACTION" ;;
  backup) run_step 00 ;;
  rollback) restore_latest_backup ;;
esac
echo "==> $SERVICE action '$ACTION' completed"
