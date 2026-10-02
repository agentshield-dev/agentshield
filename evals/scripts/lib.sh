#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
EVAL_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(cd "$EVAL_DIR/.." && pwd)
OUTPUT_DIR=${OUTPUT_DIR:-$EVAL_DIR/output}
CACHE_DIR=${CACHE_DIR:-$OUTPUT_DIR/cache}
KUBECONFIG_PATH=${KUBECONFIG_PATH:-$OUTPUT_DIR/kubeconfig}
OWNER_FILE=${OWNER_FILE:-$OUTPUT_DIR/cluster-owner}

CLUSTER_NAME=${CLUSTER_NAME:-agentshield-evals}
CLUSTER_IDENTITY=${CLUSTER_IDENTITY:-agentshield-mission-evals-v1}
OWNER_NAMESPACE=${OWNER_NAMESPACE:-agentshield-evals-system}
OWNER_CONFIGMAP=${OWNER_CONFIGMAP:-cluster-identity}
ISTIO_VERSION=${ISTIO_VERSION:-1.31.1}
ISTIO_ARCH=${ISTIO_ARCH:-amd64}
ISTIO_ARCHIVE_SHA256=${ISTIO_ARCHIVE_SHA256:-cb4af2e8a099acfc51368c1d15d4deab8321ae628554d4ee5c74f62ebe775857}
GATEWAY_API_VERSION=${GATEWAY_API_VERSION:-v1.3.0}
GATEWAY_API_SHA256=${GATEWAY_API_SHA256:-78796d5c51450fc55d8dc8092ba8137f8c807982d7508d7875d5c537a24082b9}

ISTIO_ARCHIVE="$CACHE_DIR/istio-${ISTIO_VERSION}-linux-${ISTIO_ARCH}.tar.gz"
ISTIO_HOME="$CACHE_DIR/istio-${ISTIO_VERSION}"
ISTIOCTL="$ISTIO_HOME/bin/istioctl"
GATEWAY_API_MANIFEST="$CACHE_DIR/gateway-api-${GATEWAY_API_VERSION}-standard-install.yaml"

export KUBECONFIG="$KUBECONFIG_PATH"

# Detector-only evals measure deterministic detection without model calls or agentgateway.
EVAL_DETECTOR_ONLY=${AGENTSHIELD_EVAL_DETECTOR_ONLY:-0}

detector_only() {
  [[ "$EVAL_DETECTOR_ONLY" == 1 ]]
}

log() {
  printf '[mission-evals] %s\n' "$*"
}

fail() {
  printf '[mission-evals] error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

kind_cluster_exists() {
  kind get clusters 2>/dev/null | grep -Fxq "$CLUSTER_NAME"
}

kube() {
  kubectl --kubeconfig "$KUBECONFIG_PATH" "$@"
}

local_owner_matches() {
  [[ -f "$OWNER_FILE" ]] && [[ "$(<"$OWNER_FILE")" == "$CLUSTER_NAME:$CLUSTER_IDENTITY" ]]
}

cluster_owner_matches() {
  [[ -s "$KUBECONFIG_PATH" ]] || return 1
  local actual
  actual=$(kube -n "$OWNER_NAMESPACE" get configmap "$OWNER_CONFIGMAP" -o jsonpath='{.data.id}' 2>/dev/null || true)
  [[ "$actual" == "$CLUSTER_IDENTITY" ]]
}

require_owned_cluster() {
  kind_cluster_exists || fail "kind cluster $CLUSTER_NAME does not exist"
  local_owner_matches || fail "local ownership record does not match $CLUSTER_NAME:$CLUSTER_IDENTITY"
  cluster_owner_matches || fail "in-cluster ownership marker does not match $CLUSTER_IDENTITY"
}

download_verified() {
  local url=$1
  local destination=$2
  local checksum=$3

  mkdir -p "$(dirname "$destination")"
  if [[ ! -s "$destination" ]]; then
    log "downloading $url"
    curl --fail --location --silent --show-error "$url" --output "$destination.tmp"
    mv "$destination.tmp" "$destination"
  fi
  printf '%s  %s\n' "$checksum" "$destination" | sha256sum --check --status || {
    rm -f "$destination"
    fail "checksum mismatch for $destination"
  }
}
