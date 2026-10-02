#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

"$SCRIPT_DIR/eval-preflight.sh"

if [[ "${1:-}" == "--validate-only" ]]; then
  log "all mission eval contracts are ready; no resources or model calls were created"
  exit 0
fi

for argument in "$@"; do
  case "$argument" in
    --model-endpoint | --model-endpoint=*) fail "eval-run selects the in-cluster agentgateway endpoint" ;;
  esac
done

artifact_dir=${EVAL_ARTIFACT_DIR:-$EVAL_DIR/output/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$artifact_dir"

port_forward_log="$artifact_dir/postgres-port-forward.log"
port_mapping=:5432
if [[ -n "${AGENTSHIELD_DATABASE_PORT:-}" ]]; then
  port_mapping="$AGENTSHIELD_DATABASE_PORT:5432"
fi
kubectl --kubeconfig "$KUBECONFIG_PATH" -n agentshield-system \
  port-forward service/postgres "$port_mapping" >"$port_forward_log" 2>&1 &
port_forward_pid=$!
cleanup_port_forward() {
  kill "$port_forward_pid" 2>/dev/null || true
  wait "$port_forward_pid" 2>/dev/null || true
}
trap cleanup_port_forward EXIT

database_port=
for _ in $(seq 1 50); do
  database_port=$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9][0-9]*\) -> 5432$/\1/p' "$port_forward_log" | head -n 1)
  [[ -z "$database_port" ]] || break
  if ! kill -0 "$port_forward_pid" 2>/dev/null; then
    fail "PostgreSQL port-forward stopped; see $port_forward_log"
  fi
  sleep 0.1
done
if [[ -z "$database_port" ]]; then
  fail "PostgreSQL port-forward did not become ready; see $port_forward_log"
fi
if command -v pg_isready >/dev/null 2>&1; then
  pg_isready -h 127.0.0.1 -p "$database_port" -U agentshield -d agentshield >/dev/null ||
    fail "PostgreSQL did not accept connections through the port-forward; see $port_forward_log"
elif ! (exec 3<>"/dev/tcp/127.0.0.1/$database_port"); then
  fail "PostgreSQL port-forward did not accept TCP connections; see $port_forward_log"
fi

model_arguments=()
if detector_only; then
  model_arguments=(--detector-only)
  log "detector-only mode; no agentic investigation or model calls"
else
  gateway_ip=$(kube -n agentgateway-system get service agentgateway-standalone -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
  model_arguments=(--model-endpoint "http://$gateway_ip")
  log "using in-cluster agentgateway at http://$gateway_ip"
fi
export AGENTSHIELD_DATABASE_URL="postgres://agentshield:agentshield-evals-only@127.0.0.1:$database_port/agentshield?sslmode=disable"

log "writing mission eval artifacts to $artifact_dir"
(
  cd "$REPO_ROOT"
  go run ./evals/cmd \
    --kubeconfig "$KUBECONFIG_PATH" \
    --output "$artifact_dir" \
    "${model_arguments[@]}" \
    "$@"
)
log "mission eval execution completed: $artifact_dir"
