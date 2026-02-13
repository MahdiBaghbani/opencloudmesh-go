#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

get_env_or_default() {
  local var_name="$1"
  local default_value="$2"
  local value="${!var_name:-}"

  if [ -n "$value" ]; then
    printf "%s" "$value"
  else
    printf "%s" "$default_value"
  fi
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf "%s" "$value"
}

write_nsswitch() {
  printf "hosts: files dns\n" > /etc/nsswitch.conf
}

validate_host() {
  local host="$1"
  local trimmed
  trimmed="$(trim "$host")"

  if [ -z "$trimmed" ]; then
    echo "HOST must not be empty" >&2
    exit 1
  fi

  if [[ "$trimmed" =~ [[:space:]] ]]; then
    echo "HOST must not contain whitespace: $trimmed" >&2
    exit 1
  fi

  if [[ "$trimmed" == *"://"* ]] || [[ "$trimmed" == *"/"* ]] || [[ "$trimmed" == *"?"* ]] || [[ "$trimmed" == *"#"* ]]; then
    echo "HOST format is invalid: $trimmed" >&2
    exit 1
  fi

  printf "%s" "$trimmed"
}

ensure_hosts() {
  local host="$1"
  if [ -z "$host" ]; then
    return
  fi

  local entry="127.0.0.1 ${host}.docker"
  if [ -f /etc/hosts ] && grep -Fqx "$entry" /etc/hosts; then
    return
  fi

  if [ -f /etc/hosts ] && [ -s /etc/hosts ]; then
    printf "\n%s\n" "$entry" >> /etc/hosts
  else
    printf "%s\n" "$entry" >> /etc/hosts
  fi
}

ensure_logfile() {
  touch /var/log/opencloudmesh-go.log
}

# Load TLS cert/key/CA from base64 env vars. Overrides pre-installed files when set.
load_tls_from_env() {
  local cert_b64
  cert_b64="$(trim "$(get_env_or_default TLS_CERT "")")"
  if [ -n "$cert_b64" ]; then
    echo "$cert_b64" | base64 -d > /tls/ocm-go.crt
    chmod 644 /tls/ocm-go.crt
  fi

  local key_b64
  key_b64="$(trim "$(get_env_or_default TLS_KEY "")")"
  if [ -n "$key_b64" ]; then
    echo "$key_b64" | base64 -d > /tls/ocm-go.key
    chmod 600 /tls/ocm-go.key
  fi

  local ca_b64
  ca_b64="$(trim "$(get_env_or_default TLS_CA "")")"
  if [ -n "$ca_b64" ]; then
    echo "$ca_b64" | base64 -d > /tls/certificate-authority/dockypody.crt
    chmod 644 /tls/certificate-authority/dockypody.crt
    cp /tls/certificate-authority/dockypody.crt /usr/local/share/ca-certificates/dockypody.crt
    update-ca-certificates
  fi
}

resolve_origin() {
  local validated_host="$1"
  local tls_enabled="$2"
  local public_origin
  public_origin="$(trim "$(get_env_or_default PUBLIC_ORIGIN "")")"

  if [ -n "$public_origin" ]; then
    printf "%s" "$public_origin"
    return
  fi

  if [ -n "$validated_host" ]; then
    if [ "$tls_enabled" = "true" ]; then
      printf "https://%s.docker" "$validated_host"
    else
      printf "http://%s.docker:8080" "$validated_host"
    fi
    return
  fi

  echo "Either PUBLIC_ORIGIN or HOST must be set" >&2
  exit 1
}

validate_mode() {
  local mode
  mode="$(trim "$(get_env_or_default OCM_GO_MODE "")")"

  if [ -z "$mode" ]; then
    printf ""
    return
  fi

  case "$mode" in
    strict|interop|dev)
      printf "%s" "$mode"
      ;;
    *)
      echo "OCM_GO_MODE must be strict, interop, or dev; got: $mode" >&2
      exit 1
      ;;
  esac
}

start_ocm_go() {
  local origin="$1"
  local mode="$2"
  local config="$3"

  local cmd=(
    /app/bin/opencloudmesh-go
    --config "$config"
    --public-origin "$origin"
  )

  if [ -n "$mode" ]; then
    cmd+=(--mode "$mode")
  fi

  "${cmd[@]}" >> /var/log/opencloudmesh-go.log 2>&1 &
}

main() {
  write_nsswitch

  local tls_enabled
  tls_enabled="$(trim "$(get_env_or_default TLS_ENABLED "false")")"
  if [ "$tls_enabled" = "true" ]; then
    load_tls_from_env
  fi

  local host
  host="$(trim "$(get_env_or_default HOST "")")"

  local validated_host=""
  if [ -n "$host" ]; then
    validated_host="$(validate_host "$host")"
  fi

  ensure_hosts "$validated_host"
  ensure_logfile

  local origin
  origin="$(resolve_origin "$validated_host" "$tls_enabled")"

  local mode
  mode="$(validate_mode)"

  local config
  config="$(trim "$(get_env_or_default CONFIG "")")"
  if [ -z "$config" ]; then
    if [ "$tls_enabled" = "true" ]; then
      config="/configs/config-tls.toml"
    else
      config="/configs/config.toml"
    fi
  fi
  if [ ! -f "$config" ]; then
    echo "Config file not found: $config" >&2
    exit 1
  fi

  start_ocm_go "$origin" "$mode" "$config"
}

main "$@"
