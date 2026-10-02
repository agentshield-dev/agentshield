#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

[[ "${ADOPT_EXISTING_EVAL_CLUSTER:-}" == "$CLUSTER_NAME" ]] ||
  fail "set ADOPT_EXISTING_EVAL_CLUSTER=$CLUSTER_NAME to acknowledge adoption"

require_command kind
require_command kubectl
kind_cluster_exists || fail "kind cluster $CLUSTER_NAME does not exist"
mkdir -p "$OUTPUT_DIR"
kind get kubeconfig --name "$CLUSTER_NAME" >"$KUBECONFIG_PATH"
chmod 600 "$KUBECONFIG_PATH"

unexpected_namespaces=$(kube get namespace -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' |
  awk '!/^(default|kube-node-lease|kube-public|kube-system|local-path-storage|metallb-system|agentgateway-system|agentshield-evals-system|agentshield-system|cilium-secrets|istio-system|observability|aseval-[a-z0-9-]+)$/')
[[ -z "$unexpected_namespaces" ]] || fail "refusing adoption; unexpected namespaces: $unexpected_namespaces"

kube create namespace "$OWNER_NAMESPACE" --dry-run=client -o yaml | kube apply -f -
kube -n "$OWNER_NAMESPACE" create configmap "$OWNER_CONFIGMAP" \
  --from-literal=id="$CLUSTER_IDENTITY" \
  --from-literal=cluster-name="$CLUSTER_NAME" \
  --from-literal=purpose=agentshield-mission-evals \
  --dry-run=client -o yaml | kube apply -f -
printf '%s:%s\n' "$CLUSTER_NAME" "$CLUSTER_IDENTITY" >"$OWNER_FILE"
log "adopted disposable eval cluster $CLUSTER_NAME"
