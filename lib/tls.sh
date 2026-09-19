#!/usr/bin/env bash

set_managed_tls_paths() {
  MANAGED_TLS_DIR="$1"
  MANAGED_TLS_CA_CERT="$MANAGED_TLS_DIR/ca.crt"
  MANAGED_TLS_CA_KEY="$MANAGED_TLS_DIR/ca.key"
  MANAGED_TLS_SERVER_CERT="$MANAGED_TLS_DIR/server.crt"
  MANAGED_TLS_SERVER_KEY="$MANAGED_TLS_DIR/server.key"
}

set_managed_tls_paths /etc/3proxy/tls

certificate_public_key_sha256() {
  openssl x509 -in "$1" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | sha256sum \
    | awk '{print $1}'
}

private_key_public_key_sha256() {
  openssl pkey -in "$1" -pubout -outform DER 2>/dev/null \
    | sha256sum \
    | awk '{print $1}'
}

managed_ca_is_valid() {
  local directory="$1"
  local required_seconds="$2"
  local cert="$directory/ca.crt"
  local key="$directory/ca.key"
  [[ -f "$cert" && -f "$key" ]] || return 1
  openssl x509 -in "$cert" -checkend "$required_seconds" -noout >/dev/null 2>&1 || return 1
  openssl verify -CAfile "$cert" "$cert" >/dev/null 2>&1 || return 1
  openssl x509 -in "$cert" -noout -text 2>/dev/null | grep -Fq 'CA:TRUE' || return 1
  [[ "$(certificate_public_key_sha256 "$cert")" == "$(private_key_public_key_sha256 "$key")" ]]
}

managed_leaf_is_valid() {
  local directory="$1"
  local public_ip="$2"
  local cert="$directory/server.crt"
  local key="$directory/server.key"
  [[ -f "$cert" && -f "$key" ]] || return 1
  openssl x509 -in "$cert" -checkend 86400 -noout >/dev/null 2>&1 || return 1
  openssl verify -purpose sslserver -CAfile "$directory/ca.crt" "$cert" >/dev/null 2>&1 || return 1
  openssl x509 -in "$cert" -checkip "$public_ip" -noout >/dev/null 2>&1 || return 1
  python3 "$SETUP_ROOT/tools/certificates.py" \
    --config "$CONFIG" --certificate "$cert" >/dev/null 2>&1 || return 1
  [[ "$(certificate_public_key_sha256 "$cert")" == "$(private_key_public_key_sha256 "$key")" ]]
}

generate_managed_ca() {
  local directory="$1"
  local validity_days="$2"
  local common_name="3proxy-ca-$(openssl rand -hex 16)"
  openssl genrsa -out "$directory/ca.key" 4096 >/dev/null 2>&1
  openssl req -x509 -new -sha256 -key "$directory/ca.key" \
    -days "$validity_days" -out "$directory/ca.crt" -subj "/CN=$common_name" \
    -addext 'basicConstraints = critical,CA:TRUE' \
    -addext 'keyUsage = critical,keyCertSign,cRLSign'
}

generate_managed_leaf() {
  local directory="$1"
  local validity_days="$2"
  local common_name="3proxy-leaf-$(openssl rand -hex 16).invalid"
  python3 "$SETUP_ROOT/tools/config.py" render-openssl \
    --config "$CONFIG" --output "$directory/leaf.cnf"
  openssl genrsa -out "$directory/server.key" 4096 >/dev/null 2>&1
  openssl req -new -sha256 -key "$directory/server.key" \
    -out "$directory/server.csr" -subj "/CN=$common_name" -config "$directory/leaf.cnf"
  openssl x509 -req -sha256 -in "$directory/server.csr" \
    -CA "$directory/ca.crt" -CAkey "$directory/ca.key" -CAcreateserial \
    -out "$directory/server.crt" -days "$validity_days" \
    -extensions v3_req -extfile "$directory/leaf.cnf"
  rm -f -- "$directory/server.csr" "$directory/ca.srl" "$directory/leaf.cnf"
}

install_managed_tls_directory() (
  set -Eeuo pipefail
  umask 077
  local public_ip leaf_days ca_days regenerate required_ca_seconds
  local tls_parent work_dir old_dir=""
  public_ip="$(yaml_get server.public_ip)"
  leaf_days="$(yaml_get tls.server.validity_days)"
  ca_days="$(yaml_get tls.server.ca_validity_days)"
  regenerate="$(yaml_get tls.server.regenerate_on_setup)"
  required_ca_seconds=$(( leaf_days * 86400 ))
  tls_parent="$(dirname "$MANAGED_TLS_DIR")"
  work_dir="$(mktemp -d "$tls_parent/.tls.new.XXXXXX")"
  chmod 700 "$work_dir"

  cleanup_managed_tls_work() {
    if [[ -n "$old_dir" && -d "$old_dir" && ! -d "$MANAGED_TLS_DIR" ]]; then
      mv -- "$old_dir" "$MANAGED_TLS_DIR"
      old_dir=""
    fi
    [[ ! -d "$work_dir" ]] || rm -rf -- "$work_dir"
    [[ -z "$old_dir" || ! -d "$old_dir" ]] || rm -rf -- "$old_dir"
  }
  trap cleanup_managed_tls_work EXIT

  if [[ "$regenerate" == "false" ]] \
      && managed_ca_is_valid "$MANAGED_TLS_DIR" "$required_ca_seconds"; then
    install -m 600 "$MANAGED_TLS_CA_KEY" "$work_dir/ca.key"
    install -m 644 "$MANAGED_TLS_CA_CERT" "$work_dir/ca.crt"
    echo "==> Reusing managed 3proxy private CA"
  else
    echo "==> Generating managed 3proxy private CA"
    generate_managed_ca "$work_dir" "$ca_days"
  fi

  if [[ "$regenerate" == "false" ]] \
      && managed_ca_is_valid "$MANAGED_TLS_DIR" "$required_ca_seconds" \
      && managed_leaf_is_valid "$MANAGED_TLS_DIR" "$public_ip"; then
    install -m 600 "$MANAGED_TLS_SERVER_KEY" "$work_dir/server.key"
    install -m 644 "$MANAGED_TLS_SERVER_CERT" "$work_dir/server.crt"
    echo "==> Reusing managed HTTPS listener certificate for $public_ip"
  else
    echo "==> Issuing managed HTTPS listener certificate for $public_ip"
    generate_managed_leaf "$work_dir" "$leaf_days"
  fi

  chmod 600 "$work_dir/ca.key" "$work_dir/server.key"
  chmod 644 "$work_dir/ca.crt" "$work_dir/server.crt"
  managed_ca_is_valid "$work_dir" "$required_ca_seconds"
  managed_leaf_is_valid "$work_dir" "$public_ip"

  if [[ -d "$MANAGED_TLS_DIR" ]]; then
    old_dir="$(mktemp -d "$tls_parent/.tls.old.XXXXXX")"
    rmdir -- "$old_dir"
    mv -- "$MANAGED_TLS_DIR" "$old_dir"
  fi
  mv -- "$work_dir" "$MANAGED_TLS_DIR"
  work_dir=""
  [[ -z "$old_dir" ]] || rm -rf -- "$old_dir"
  old_dir=""
  trap - EXIT
  echo "==> Managed HTTPS listener CA: $MANAGED_TLS_CA_CERT"
)

prepare_managed_tls() {
  local https_listener_state
  https_listener_state="$(python3 "$SETUP_ROOT/tools/config.py" has-https-listener --config "$CONFIG")"
  if [[ "$https_listener_state" != "true" ]]; then
    return 0
  fi
  command -v openssl >/dev/null 2>&1 || {
    echo "OpenSSL CLI is required for managed HTTPS listener certificates" >&2
    return 1
  }
  install -d -m 755 "$(dirname "$MANAGED_TLS_DIR")"
  if [[ "$(python3 "$SETUP_ROOT/tools/config.py" tls-server-mode --config "$CONFIG")" == external ]]; then
    python3 "$SETUP_ROOT/tools/tls_material.py" --config "$CONFIG" --directory "$MANAGED_TLS_DIR"
  elif [[ "$(python3 "$SETUP_ROOT/tools/config.py" tls-server-mode --config "$CONFIG")" == acme_ip ]]; then
    python3 "$SETUP_ROOT/tools/acme.py" install --config "$CONFIG"
  else
    install_managed_tls_directory
  fi
}
