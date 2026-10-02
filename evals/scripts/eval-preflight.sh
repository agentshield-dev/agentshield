#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

"$SCRIPT_DIR/preflight.sh"
require_owned_cluster

wait_available() {
  local namespace=$1
  local resource=$2
  kube -n "$namespace" rollout status "$resource" --timeout=30s >/dev/null
}

kube get --raw=/readyz >/dev/null
kube wait --for=condition=Ready node --all --timeout=30s >/dev/null

wait_available kube-system daemonset/cilium
wait_available kube-system deployment/cilium-operator
wait_available kube-system deployment/hubble-relay
wait_available istio-system deployment/istiod
wait_available istio-system daemonset/ztunnel
wait_available metallb-system deployment/controller
wait_available metallb-system daemonset/speaker
detector_only || wait_available agentgateway-system deployment/agentgateway-standalone
wait_available agentshield-system deployment/postgres
wait_available agentshield-system deployment/agentshield
wait_available observability deployment/opentelemetry-collector

for crd in \
  ciliumnetworkpolicies.cilium.io \
  gateways.gateway.networking.k8s.io \
  authorizationpolicies.security.istio.io \
  peerauthentications.security.istio.io; do
  kube wait --for=condition=Established "crd/$crd" --timeout=30s >/dev/null
done

kube -n kube-system get service hubble-relay >/dev/null
kube -n metallb-system get ipaddresspool kind >/dev/null

if ! detector_only; then
  service_type=$(kube -n agentgateway-system get service agentgateway-standalone -o jsonpath='{.spec.type}')
  load_balancer_ip=$(kube -n agentgateway-system get service agentgateway-standalone -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
  [[ "$service_type" == LoadBalancer ]] || fail "agentgateway service is $service_type"
  [[ -n "$load_balancer_ip" ]] || fail "agentgateway has no LoadBalancer address"
fi

if kube get services -A -o json | jq -e '
  .items[] | select(.spec.type == "NodePort" or any(.spec.ports[]?; (.nodePort // 0) != 0))
' >/dev/null; then
  fail "NodePort allocation exists in the eval cluster"
fi

health=$(kube -n agentshield-system get endpoints agentshield -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null || true)
[[ -n "$health" ]] || fail "AgentShield service has no ready endpoint"

discovery_account=system:serviceaccount:agentshield-system:agentshield
for permission in \
  'list gatewayclasses.gateway.networking.k8s.io' \
  'list ciliumnetworkpolicies.cilium.io' \
  'list ciliumclusterwidenetworkpolicies.cilium.io' \
  'list ciliumendpoints.cilium.io' \
  'list ciliumnodes.cilium.io' \
  'list clusterroles.rbac.authorization.k8s.io' \
  'list mutatingwebhookconfigurations.admissionregistration.k8s.io'; do
  read -r verb resource <<<"$permission"
  [[ "$(kube auth can-i --as="$discovery_account" "$verb" "$resource" 2>/dev/null)" == yes ]] || fail "AgentShield cannot $permission"
done

graph_proxy=/api/v1/namespaces/agentshield-system/services/agentshield:8088/proxy/api/v1/graph
graph_ready=false
for _ in $(seq 1 60); do
  if kube get --raw "$graph_proxy" 2>/dev/null | jq -e '.snapshot.resources | length > 0' >/dev/null; then
    graph_ready=true
    break
  fi
  sleep 1
done
[[ "$graph_ready" == true ]] || fail "AgentShield graph was not materialized"

(
  cd "$REPO_ROOT"
  go test ./evals ./evals/cmd
  go run ./evals/cmd \
    --validate-only \
    --kubeconfig "$KUBECONFIG_PATH"
  go run ./evals/cmd \
    --suite rules \
    --validate-only \
    --kubeconfig "$KUBECONFIG_PATH"
) >/dev/null

log "mission eval provider preflight passed"
catalog_scenarios=$(jq '.campaigns | length' "$EVAL_DIR/campaigns.json")
printf 'cluster=%s\n' "$CLUSTER_NAME"
printf 'catalog-campaigns=%s\n' "$catalog_scenarios"
printf 'rule-campaigns=%s\n' "$(jq '.campaigns | length' "$EVAL_DIR/rule-campaigns.json")"
printf 'validated-campaigns=%s\n' "$catalog_scenarios"
detector_only || printf 'agentgateway=http://%s\n' "$load_balancer_ip"
printf 'execution-status=not-run\n'
