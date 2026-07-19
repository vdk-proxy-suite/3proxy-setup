#!/usr/bin/env bash
set -Eeuo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=0
ASSUME_YES=0
KEEP_BACKUPS=0
PURGE_SETUP=0
PURGE_UFW=0

usage() {
  cat <<'EOF'
Usage: sudo ./clean3proxy.sh [options]

Completely stops and removes the 3proxy installation managed by this package.

Options:
  --dry-run       Show actions without changing the system (default without --yes)
  --yes           Perform the cleanup
  --keep-backups  Preserve /var/backups/3proxy
  --purge-setup   Also remove this extracted 3proxy-setup directory
  --purge-ufw     Delete UFW rules described by the saved setup YAML
  -h, --help      Show this help

Cloud firewall/security-group rules and the global systemd journal are never removed.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --yes) ASSUME_YES=1 ;;
    --keep-backups) KEEP_BACKUPS=1 ;;
    --purge-setup) PURGE_SETUP=1 ;;
    --purge-ufw) PURGE_UFW=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [[ $ASSUME_YES -eq 0 ]]; then
  DRY_RUN=1
fi
if [[ $DRY_RUN -eq 0 && $EUID -ne 0 ]]; then
  echo "Real cleanup must run as root; use sudo or run with --dry-run" >&2
  exit 1
fi

print_command() {
  printf '  '
  printf '%q ' "$@"
  printf '\n'
}

run() {
  print_command "$@"
  if [[ $DRY_RUN -eq 0 ]]; then
    "$@"
  fi
}

try_run() {
  print_command "$@"
  if [[ $DRY_RUN -eq 0 ]]; then
    "$@" || true
  fi
}

remove_path() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    run rm -rf -- "$path"
  fi
}

saved_config=""
if [[ -f /etc/3proxy/setup.yaml ]]; then
  saved_config=/etc/3proxy/setup.yaml
elif [[ -f "$BASE_DIR/config.yaml" ]]; then
  saved_config="$BASE_DIR/config.yaml"
fi

echo "==> Mode: $([[ $DRY_RUN -eq 1 ]] && echo dry-run || echo cleanup)"
echo "==> Stopping services and processes"
try_run systemctl disable --now 3proxy.service
try_run systemctl stop 3proxy.service
try_run pkill -TERM -x 3proxy
if [[ $DRY_RUN -eq 0 ]]; then
  for _ in 1 2 3 4 5; do
    pgrep -x 3proxy >/dev/null 2>&1 || break
    sleep 1
  done
fi
if pgrep -x 3proxy >/dev/null 2>&1; then
  try_run pkill -KILL -x 3proxy
fi

if [[ $PURGE_UFW -eq 1 ]]; then
  echo "==> Removing explicitly requested UFW rules"
  if [[ -z "$saved_config" ]]; then
    echo "No saved setup YAML found; UFW cleanup skipped" >&2
  elif ! command -v ufw >/dev/null 2>&1; then
    echo "UFW is not installed; UFW cleanup skipped"
  elif [[ ! -f "$BASE_DIR/tools/config.py" ]]; then
    echo "config.py is unavailable; UFW cleanup skipped" >&2
  else
    while IFS= read -r port; do
      try_run ufw --force delete allow "$port/tcp"
    done < <(python3 "$BASE_DIR/tools/config.py" ports --config "$saved_config")
    cidr="$(python3 "$BASE_DIR/tools/config.py" get --config "$saved_config" --path server.udp_client_cidr)"
    try_run ufw --force delete allow from "$cidr" to any port 1024:65535 proto udp
  fi
fi

echo "==> Removing installed files, configuration, logs and runtime state"
for path in \
  /etc/3proxy \
  /usr/local/etc/3proxy \
  /usr/local/bin/3proxy \
  /usr/local/share/3proxy-build \
  /var/log/3proxy \
  /var/lib/3proxy \
  /var/lib/3proxy-setup \
  /var/cache/3proxy \
  /run/3proxy \
  /run/3proxy.pid \
  /run/3proxy-setup.state \
  /etc/systemd/system/3proxy.service \
  /etc/systemd/system/multi-user.target.wants/3proxy.service \
  /etc/init.d/3proxy; do
  remove_path "$path"
done

if [[ $KEEP_BACKUPS -eq 0 ]]; then
  remove_path /var/backups/3proxy
else
  echo "==> Preserving /var/backups/3proxy"
fi

try_run systemctl daemon-reload
try_run systemctl reset-failed 3proxy.service

if [[ $PURGE_SETUP -eq 1 ]]; then
  resolved_base="$(readlink -f "$BASE_DIR")"
  if [[ -z "$resolved_base" || "$resolved_base" == "/" || ! -f "$resolved_base/clean3proxy.sh" || ! -d "$resolved_base/steps" ]]; then
    echo "Refusing to remove unsafe setup path: $resolved_base" >&2
    exit 1
  fi
  echo "==> Removing standalone setup directory"
  run rm -rf -- "$resolved_base"
fi

if [[ $DRY_RUN -eq 1 ]]; then
  echo "==> Dry-run complete; nothing was changed. Re-run with --yes to execute."
else
  if pgrep -x 3proxy >/dev/null 2>&1; then
    echo "Cleanup failed: a 3proxy process is still running" >&2
    exit 1
  fi
  echo "==> 3proxy cleanup complete"
fi
