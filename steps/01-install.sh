#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
require_root
parse_config_arg "$@"

version="$(yaml_get install.version)"
source_url="$(yaml_get install.source_url)"
source_sha="$(yaml_get install.sha256)"
patch_sha="$(python3 "$SETUP_ROOT/tools/build_checks.py" patchset-sha \
  --directory "$SETUP_ROOT/patches")"
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
apt-get install -y --no-install-recommends build-essential cmake curl ca-certificates libssl-dev openssl patch python3-yaml iproute2

work="$(mktemp -d /tmp/3proxy-build.XXXXXX)"
feature_pid=""
feature_parent_pid=""
feature_parent_rc=1
cleanup() {
  [[ -z "$feature_pid" ]] || kill "$feature_pid" 2>/dev/null || true
  [[ -z "$feature_parent_pid" ]] || kill "$feature_parent_pid" 2>/dev/null || true
  rm -rf -- "$work"
}
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
feature_tls_log="$work/tls-handshake-check.log"
feature_parent_log="$work/tls-parent-check.log"
feature_ca_cert="$work/tls-feature-ca.crt"
feature_ca_key="$work/tls-feature-ca.key"
feature_cert="$work/tls-feature-check.crt"
feature_key="$work/tls-feature-check.key"
feature_request="$work/tls-feature-check.csr"
feature_ext="$work/tls-feature-check.cnf"
feature_authority="127.0.0.1:443"
feature_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
feature_parent_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
while [[ "$feature_parent_port" == "$feature_port" ]]; do
  feature_parent_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
done
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
  -keyout "$feature_ca_key" -out "$feature_ca_cert" -subj '/CN=3proxy-feature-check-ca' \
  -addext 'basicConstraints = critical,CA:TRUE' \
  -addext 'keyUsage = critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -keyout "$feature_key" -out "$feature_request" \
  -subj '/CN=feature-check.invalid' >/dev/null 2>&1
printf '%s\n' \
  '[server_ext]' \
  'basicConstraints = critical,CA:FALSE' \
  'keyUsage = critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage = serverAuth' \
  'subjectAltName = IP:127.0.0.1,DNS:feature-check.invalid' > "$feature_ext"
openssl x509 -req -sha256 -days 2 -in "$feature_request" \
  -CA "$feature_ca_cert" -CAkey "$feature_ca_key" -CAcreateserial \
  -extfile "$feature_ext" -extensions server_ext -out "$feature_cert" >/dev/null 2>&1
printf '%s\n' \
  "ssl_server_cert $feature_cert" \
  "ssl_server_key $feature_key" \
  'ssl_server_min_proto_version TLSv1.2' \
  'ssl_server_no_verify' \
  'ssl_client_mode 3' \
  'ssl_client_verify' \
  "ssl_client_ca_file $feature_ca_cert" \
  'ssl_client_sni feature-check.invalid' \
  'ssl_client_min_proto_version TLSv1.2' \
  'ssl_serv' \
  'ssl_cli' \
  'auth iponly' \
  'allow * 127.0.0.1' \
  "parent 1000 connect+s 127.0.0.1 $feature_parent_port" \
  'deny *' \
  "proxy -i127.0.0.1 -p${feature_port}" \
  'ssl_noserv' \
  'ssl_nocli' \
  'end' > "$feature_cfg"
python3 "$SETUP_ROOT/tools/build_checks.py" tls-connect-parent \
  --listen-host 127.0.0.1 --port "$feature_parent_port" \
  --cert "$feature_cert" --key "$feature_key" \
  --expected-sni feature-check.invalid \
  --expected-authority "$feature_authority" --timeout 8 \
  > "$feature_parent_log" 2>&1 &
feature_parent_pid=$!
for _ in {1..50}; do
  kill -0 "$feature_parent_pid" 2>/dev/null || break
  grep -Fq "PROBE_READY host=127.0.0.1 port=$feature_parent_port" \
    "$feature_parent_log" && break
  sleep 0.05
done
if ! kill -0 "$feature_parent_pid" 2>/dev/null \
    || ! grep -Fq "PROBE_READY host=127.0.0.1 port=$feature_parent_port" \
      "$feature_parent_log"; then
  cat "$feature_parent_log" >&2
  echo "TLS CONNECT parent probe failed to become ready" >&2
  exit 1
fi
"$binary" "$feature_cfg" > "$feature_log" 2>&1 &
feature_pid=$!
for _ in {1..50}; do
  kill -0 "$feature_pid" 2>/dev/null || break
  if timeout 1s openssl s_client -connect "127.0.0.1:$feature_port" \
      -CAfile "$feature_ca_cert" -verify_ip 127.0.0.1 -verify_return_error \
      < /dev/null > "$feature_tls_log" 2>&1; then
    break
  fi
  sleep 0.05
done
printf 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' \
    "$feature_authority" "$feature_authority" \
  | timeout 3s openssl s_client -quiet -connect "127.0.0.1:$feature_port" \
      -CAfile "$feature_ca_cert" -verify_ip 127.0.0.1 -verify_return_error \
      >> "$feature_tls_log" 2>&1 || true
if wait "$feature_parent_pid"; then
  feature_parent_rc=0
else
  feature_parent_rc=$?
fi
feature_parent_pid=""
if ! kill -0 "$feature_pid" 2>/dev/null \
    || (( feature_parent_rc != 0 )) \
    || ! grep -Fq 'Verify return code: 0 (ok)' "$feature_tls_log" \
    || ! grep -Eq '^HTTP/1\.[01] 200 ' "$feature_tls_log" \
    || ! grep -Fq \
      "PROBE_OK sni=feature-check.invalid authority=$feature_authority " \
      "$feature_parent_log" \
    || grep -Eq 'Unknown command:|Command: .* failed|failed to (set|create|read|use)' "$feature_log"; then
  cat "$feature_log" >&2
  cat "$feature_tls_log" >&2
  cat "$feature_parent_log" >&2
  echo "Built 3proxy failed the combined OpenSSL server/client runtime smoke test" >&2
  exit 1
fi
kill "$feature_pid" 2>/dev/null || true
wait "$feature_pid" 2>/dev/null || true
feature_pid=""
install -D -m 755 "$binary" /usr/local/bin/3proxy.new
mv -f /usr/local/bin/3proxy.new /usr/local/bin/3proxy

install -d -m 755 /usr/local/share/3proxy-build
binary_sha="$(sha256sum /usr/local/bin/3proxy | awk '{print $1}')"
python3 "$SETUP_ROOT/tools/config.py" write-manifest \
  --output /usr/local/share/3proxy-build/manifest.json \
  --version "$version" --source-sha "$source_sha" --patch-sha "$patch_sha" \
  --build-profile "$build_profile" --binary-sha "$binary_sha"
chmod 644 /usr/local/share/3proxy-build/manifest.json
echo "==> Installed 3proxy $version with verified OpenSSL server/client support ($binary_sha)"
