#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.34.0}
CILIUM_VERSION=${CILIUM_VERSION:-1.18.15}
METALLB_VERSION=v0.16.1
AGENTGATEWAY_VERSION=v1.6.0
FALCO_CHART_VERSION=9.2.1
# Older Falco releases fail on recent host kernels, which the kind node shares.
FALCO_IMAGE_TAG=${FALCO_IMAGE_TAG:-0.45.1}

"$SCRIPT_DIR/preflight.sh"
mkdir -p "$OUTPUT_DIR"
cd "$REPO_ROOT"

if kind_cluster_exists; then
  require_owned_cluster
  log "using existing owned cluster $CLUSTER_NAME"
else
  [[ ! -e "$OWNER_FILE" ]] || fail "stale ownership record exists without cluster: $OWNER_FILE"
  kind create cluster --name "$CLUSTER_NAME" --image "$KIND_NODE_IMAGE" \
    --config "$EVAL_DIR/config/kind.yaml" --kubeconfig "$KUBECONFIG_PATH" --wait 0s
  chmod 600 "$KUBECONFIG_PATH"
  kube create namespace "$OWNER_NAMESPACE" --dry-run=client -o yaml | kube apply -f -
  kube -n "$OWNER_NAMESPACE" create configmap "$OWNER_CONFIGMAP" \
    --from-literal=id="$CLUSTER_IDENTITY" \
    --from-literal=cluster-name="$CLUSTER_NAME" \
    --from-literal=purpose=agentshield-mission-evals \
    --dry-run=client -o yaml | kube apply -f -
  printf '%s:%s\n' "$CLUSTER_NAME" "$CLUSTER_IDENTITY" >"$OWNER_FILE"
fi

log "installing Cilium $CILIUM_VERSION with Hubble"
helm upgrade --install cilium "https://helm.cilium.io/cilium-$CILIUM_VERSION.tgz" \
  --namespace kube-system \
  --set operator.replicas=1 \
  --set kubeProxyReplacement=true \
  --set cni.exclusive=false \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --wait --timeout 10m
kube -n kube-system rollout restart daemonset/cilium
kube -n kube-system rollout status daemonset/cilium --timeout=300s
kube -n kube-system rollout status deployment/cilium-operator --timeout=300s
kube -n kube-system rollout status deployment/hubble-relay --timeout=300s
kube wait --for=condition=Ready node --all --timeout=300s

log "installing MetalLB $METALLB_VERSION"
kube apply -f "https://raw.githubusercontent.com/metallb/metallb/${METALLB_VERSION}/config/manifests/metallb-native.yaml"
kube rollout status deployment/controller -n metallb-system --timeout=180s
kube rollout status daemonset/speaker -n metallb-system --timeout=180s
kube apply -f "$EVAL_DIR/manifests/metallb-pool.yaml"

log "installing Gateway API and Istio ambient"
OUTPUT_DIR="$OUTPUT_DIR" KUBECONFIG_PATH="$KUBECONFIG_PATH" OWNER_FILE="$OWNER_FILE" \
  CLUSTER_NAME="$CLUSTER_NAME" CLUSTER_IDENTITY="$CLUSTER_IDENTITY" \
  "$SCRIPT_DIR/install-istio.sh"

if detector_only; then
  log "detector-only mode; skipping agentgateway"
else
  log "installing agentgateway $AGENTGATEWAY_VERSION"
  kube create namespace agentgateway-system --dry-run=client -o yaml | kube apply -f -
  printf '%s' "$OPENAI_API_KEY" | kube -n agentgateway-system create secret generic openai-api \
    --from-file=OPENAI_API_KEY=/dev/stdin --dry-run=client -o yaml | kube apply -f -
  helm upgrade --install agentgateway-standalone \
    oci://cr.agentgateway.dev/charts/agentgateway-standalone \
    --namespace agentgateway-system \
    --version "$AGENTGATEWAY_VERSION" \
    --values "$EVAL_DIR/config/agentgateway-values.yaml" \
    --wait --timeout 5m
fi

log "installing AgentShield and PostgreSQL"
OUTPUT_DIR="$OUTPUT_DIR" KUBECONFIG_PATH="$KUBECONFIG_PATH" OWNER_FILE="$OWNER_FILE" \
  CLUSTER_NAME="$CLUSTER_NAME" CLUSTER_IDENTITY="$CLUSTER_IDENTITY" \
  "$SCRIPT_DIR/telemetry.sh" start
OUTPUT_DIR="$OUTPUT_DIR" KUBECONFIG_PATH="$KUBECONFIG_PATH" OWNER_FILE="$OWNER_FILE" \
  CLUSTER_NAME="$CLUSTER_NAME" CLUSTER_IDENTITY="$CLUSTER_IDENTITY" \
  "$SCRIPT_DIR/telemetry.sh" collector-up

# Falco posts alerts to the collector's webhook_event receiver, so it installs after the collector.
log "installing Falco $FALCO_IMAGE_TAG"
helm upgrade --install falco oci://ghcr.io/falcosecurity/charts/falco \
  --namespace falco --create-namespace \
  --version "$FALCO_CHART_VERSION" \
  --set tty=true \
  --set image.tag="$FALCO_IMAGE_TAG" \
  --values "$EVAL_DIR/config/falco-values.yaml" \
  --wait --timeout 10m

if ! detector_only; then
  service_type=$(kube get service agentgateway-standalone -n agentgateway-system -o jsonpath='{.spec.type}')
  load_balancer_ip=$(kube get service agentgateway-standalone -n agentgateway-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
  [[ "$service_type" == "LoadBalancer" ]] || { echo "agentgateway service is $service_type, want LoadBalancer" >&2; exit 1; }
  [[ "$load_balancer_ip" == 10.200.0.* ]] || { echo "unexpected agentgateway load balancer IP: $load_balancer_ip" >&2; exit 1; }
fi
if kube get services -A -o json | jq -e '.items[] | select(.spec.type == "NodePort" or any(.spec.ports[]?; (.nodePort // 0) != 0))' >/dev/null; then
  echo "NodePort allocation found in experiment cluster" >&2
  exit 1
fi

detector_only || printf 'agentgateway LoadBalancer: http://%s\n' "$load_balancer_ip"
printf 'cluster kubeconfig: %s\n' "$KUBECONFIG_PATH"
printf 'status: providers, OTLP collector, and Falco ready; mission evals not run\n'
