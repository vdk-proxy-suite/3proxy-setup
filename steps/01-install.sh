#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
parse_config_arg "$@"

version="$(yaml_get install.version)"
source_url="$(yaml_get install.source_url)"
source_sha="$(yaml_get install.sha256)"
patch_sha="$(sha256sum "$SETUP_ROOT"/patches/*.patch | sha256sum | awk '{print $1}')"

if [[ "${FORCE_REBUILD:-0}" != "1" && -x /usr/local/bin/3proxy && -f /usr/local/share/3proxy-build/manifest.json ]]; then
  if python3 "$SETUP_ROOT/tools/config.py" manifest-matches \
      --manifest /usr/local/share/3proxy-build/manifest.json \
      --version "$version" --source-sha "$source_sha" --patch-sha "$patch_sha"; then
    echo "==> Installed binary matches source and patch manifest; build skipped"
    exit 0
  fi
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y build-essential curl ca-certificates libssl-dev libpcre2-dev patch python3-yaml iproute2

work="$(mktemp -d /tmp/3proxy-build.XXXXXX)"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT

archive="$work/3proxy.tar.gz"
curl -fsSL "$source_url" -o "$archive"
printf '%s  %s\n' "$source_sha" "$archive" | sha256sum -c -
tar xzf "$archive" -C "$work"
src="$work/3proxy-$version"
[[ -d "$src" ]] || { echo "Unexpected source directory" >&2; exit 1; }

for patch_file in "$SETUP_ROOT"/patches/*.patch; do
  echo "==> Applying $(basename "$patch_file")"
  patch --batch --forward --dry-run -d "$src" -p1 < "$patch_file"
  patch --batch --forward -d "$src" -p1 < "$patch_file"
done

make -C "$src" -f Makefile.Linux
test -x "$src/bin/3proxy"
install -D -m 755 "$src/bin/3proxy" /usr/local/bin/3proxy.new
mv -f /usr/local/bin/3proxy.new /usr/local/bin/3proxy

install -d -m 755 /usr/local/share/3proxy-build
binary_sha="$(sha256sum /usr/local/bin/3proxy | awk '{print $1}')"
python3 "$SETUP_ROOT/tools/config.py" write-manifest \
  --output /usr/local/share/3proxy-build/manifest.json \
  --version "$version" --source-sha "$source_sha" --patch-sha "$patch_sha" --binary-sha "$binary_sha"
chmod 644 /usr/local/share/3proxy-build/manifest.json
echo "==> Installed patched 3proxy $version ($binary_sha)"
