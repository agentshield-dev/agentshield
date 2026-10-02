#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

for command_name in curl kubectl sha256sum tar; do
  require_command "$command_name"
done
require_owned_cluster

istio_url="https://github.com/istio/istio/releases/download/${ISTIO_VERSION}/istio-${ISTIO_VERSION}-linux-${ISTIO_ARCH}.tar.gz"
gateway_api_url="https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"

download_verified "$istio_url" "$ISTIO_ARCHIVE" "$ISTIO_ARCHIVE_SHA256"
download_verified "$gateway_api_url" "$GATEWAY_API_MANIFEST" "$GATEWAY_API_SHA256"

if [[ ! -x "$ISTIOCTL" ]]; then
  rm -rf "$ISTIO_HOME"
  tar -xzf "$ISTIO_ARCHIVE" -C "$CACHE_DIR"
fi
[[ -x "$ISTIOCTL" ]] || fail "archive did not provide $ISTIOCTL"

log "installing Gateway API $GATEWAY_API_VERSION"
kube apply --server-side -f "$GATEWAY_API_MANIFEST"
kube wait --for=condition=Established crd/gateways.gateway.networking.k8s.io --timeout=120s

log "installing Istio $ISTIO_VERSION with the ambient profile"
"$ISTIOCTL" install --kubeconfig "$KUBECONFIG_PATH" -f "$EVAL_DIR/config/istio-ambient.yaml" -y
kube -n istio-system rollout status deployment/istiod --timeout=180s
kube -n istio-system rollout status daemonset/ztunnel --timeout=180s
log "Istio ambient installation is ready"
