#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
parse_config_arg "$@"

version="$(yaml_get install.version)"
source_url="$(yaml_get install.source_url)"
source_sha="$(yaml_get install.sha256)"
patch_sha="$(sha256sum "$SETUP_ROOT"/patches/*.patch | sha256sum | awk '{print $1}')"
build_profile="cmake-openssl"

if [[ "${FORCE_REBUILD:-0}" != "1" && -x /usr/local/bin/3proxy && -f /usr/local/share/3proxy-build/manifest.json ]]; then
  if python3 "$SETUP_ROOT/tools/config.py" manifest-matches \
      --manifest /usr/local/share/3proxy-build/manifest.json \
      --version "$version" --source-sha "$source_sha" --patch-sha "$patch_sha" \
      --build-profile "$build_profile"; then
    echo "==> Installed binary matches source and patch manifest; build skipped"
    exit 0
  fi
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends build-essential cmake curl ca-certificates libssl-dev patch python3-yaml iproute2

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

cmake -S "$src" -B "$src/build" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -D3PROXY_USE_WOLFSSL=OFF \
  -D3PROXY_USE_OPENSSL=ON \
  -D3PROXY_USE_PCRE2=OFF \
  -D3PROXY_USE_PAM=OFF \
  -D3PROXY_USE_ODBC=OFF \
  -D3PROXY_STATIC_LINK=OFF \
  -D3PROXY_BUILD_NONE=ON
cmake --build "$src/build" --target 3proxy --parallel "$(nproc)"
binary="$src/build/bin/3proxy"
test -x "$binary"
grep -Fxq '3PROXY_USE_WOLFSSL:BOOL=OFF' "$src/build/CMakeCache.txt"
grep -Fxq '3PROXY_USE_OPENSSL:BOOL=ON' "$src/build/CMakeCache.txt"
grep -q -- '-DWITH_SSL' "$src/build/compile_commands.json"
if grep -q -- '-DWITH_WOLFSSL' "$src/build/compile_commands.json"; then
  echo "Built 3proxy unexpectedly enables wolfSSL" >&2
  exit 1
fi
dependencies="$(ldd "$binary")"
if grep -q 'not found' <<<"$dependencies" \
    || ! grep -Eq 'libssl\.so' <<<"$dependencies" \
    || ! grep -Eq 'libcrypto\.so' <<<"$dependencies"; then
  echo "Built 3proxy binary does not have a complete dynamic OpenSSL dependency set" >&2
  exit 1
fi

feature_cfg="$work/tls-feature-check.cfg"
feature_log="$work/tls-feature-check.log"
feature_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
printf '%s\n' \
  'ssl_client_mode 3' \
  'ssl_client_verify' \
  'ssl_client_ca_file /etc/ssl/certs/ca-certificates.crt' \
  'ssl_client_sni feature-check.invalid' \
  'ssl_client_min_proto_version TLSv1.2' \
  'ssl_cli' \
  'auth iponly' \
  'allow * 127.0.0.1' \
  'parent 1000 connect+s 127.0.0.1 9 probe probe' \
  'deny *' \
  "socks -i127.0.0.1 -p${feature_port}" \
  'end' > "$feature_cfg"
set +e
timeout 2s "$binary" "$feature_cfg" > "$feature_log" 2>&1
feature_rc=$?
set -e
if [[ $feature_rc -ne 124 ]] \
    || grep -Eq 'Unknown command:|Command: .* failed|failed to set client context' "$feature_log"; then
  cat "$feature_log" >&2
  echo "Built 3proxy failed the OpenSSL client runtime smoke test" >&2
  exit 1
fi
install -D -m 755 "$binary" /usr/local/bin/3proxy.new
mv -f /usr/local/bin/3proxy.new /usr/local/bin/3proxy

install -d -m 755 /usr/local/share/3proxy-build
binary_sha="$(sha256sum /usr/local/bin/3proxy | awk '{print $1}')"
python3 "$SETUP_ROOT/tools/config.py" write-manifest \
  --output /usr/local/share/3proxy-build/manifest.json \
  --version "$version" --source-sha "$source_sha" --patch-sha "$patch_sha" \
  --build-profile "$build_profile" --binary-sha "$binary_sha"
chmod 644 /usr/local/share/3proxy-build/manifest.json
echo "==> Installed 3proxy $version with verified OpenSSL client support ($binary_sha)"
