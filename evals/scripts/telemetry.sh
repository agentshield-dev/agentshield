#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

[[ $# -ge 1 ]] || fail "usage: $0 start|collector-up|collector-down|verify|stop"
action=$1
port=${AGENTSHIELD_OTLP_PORT:-18088}
binary="$CACHE_DIR/agentshield-evals"
image="agentshield-evals:$CLUSTER_IDENTITY"
manifest="$EVAL_DIR/manifests/agentshield.yaml.tmpl"

# Detector-only runs make no model calls, so they drop the Deployment rule authoring lines.
render_agentshield() {
  local authoring=()
  if detector_only; then
    authoring=(-e '/# authoring:begin/,/# authoring:end/d')
  fi
  sed "${authoring[@]}" -e "s|__AGENTSHIELD_IMAGE__|$image|g" -e "s|__CLUSTER_IDENTITY__|$CLUSTER_IDENTITY|g" "$manifest"
}

case "$action" in
  start)
    require_command docker
    require_command go
    require_owned_cluster
    mkdir -p "$CACHE_DIR"
    # Embed the web UI; make rebuilds ui/dist only when UI sources changed. UI=0 skips it.
    if [[ "${UI:-1}" != 0 ]]; then
      require_command make
      require_command pnpm
      log "building web UI"
      make --no-print-directory -C "$REPO_ROOT" ui >"$CACHE_DIR/ui-build.log" 2>&1 ||
        { cat "$CACHE_DIR/ui-build.log" >&2; fail "web UI build failed"; }
    fi
    (cd "$REPO_ROOT" && CGO_ENABLED=0 go build -o "$binary" ./cmd/agentshield)
    image_context=$(mktemp -d)
    trap 'rm -rf "$image_context"' EXIT
    cp "$binary" "$image_context/agentshield"
    docker build --quiet --tag "$image" --file "$EVAL_DIR/config/agentshield.Dockerfile" "$image_context" >/dev/null
    kind load docker-image --name "$CLUSTER_NAME" "$image" >/dev/null
    # Deployment rule authoring calls OpenAI with the key the eval already requires.
    # A redeploy without the key reuses the Secret an earlier run stored.
    if ! detector_only; then
      if [[ -n "${OPENAI_API_KEY:-}" ]]; then
        kube create namespace agentshield-system --dry-run=client -o yaml | kube apply -f - >/dev/null
        printf '%s' "$OPENAI_API_KEY" | kube -n agentshield-system create secret generic agentshield-model \
          --from-file=OPENAI_API_KEY=/dev/stdin --dry-run=client -o yaml | kube apply -f - >/dev/null
      elif ! kube -n agentshield-system get secret agentshield-model >/dev/null 2>&1; then
        fail "OPENAI_API_KEY is required for Deployment rule authoring"
      fi
    fi
    render_agentshield | kube apply -f -
    kube -n agentshield-system rollout status deployment/postgres --timeout=180s
    kube -n agentshield-system rollout restart deployment/agentshield
    kube -n agentshield-system rollout status deployment/agentshield --timeout=180s
    log "in-cluster AgentShield and PostgreSQL are ready"
    ;;
  collector-up)
    require_owned_cluster
    kube apply -f "$EVAL_DIR/manifests/otel-collector.yaml"
    kube -n observability rollout status deployment/opentelemetry-collector --timeout=180s
    ;;
  collector-down)
    kube delete namespace observability --ignore-not-found --wait=true --timeout=120s
    ;;
  verify)
    require_command curl
    require_command jq
    require_owned_cluster
    expected_source="evals/$CLUSTER_IDENTITY"
    port_forward_log=$(mktemp)
    kube -n agentshield-system port-forward service/agentshield "$port:8088" >"$port_forward_log" 2>&1 &
    port_forward_pid=$!
    cleanup_port_forward() {
      kill "$port_forward_pid" 2>/dev/null || true
      wait "$port_forward_pid" 2>/dev/null || true
      rm -f "$port_forward_log"
    }
    trap cleanup_port_forward EXIT
    for _ in $(seq 1 60); do
      matched=$(curl --fail --silent "http://127.0.0.1:$port/api/v1/graph" 2>/dev/null | \
        jq --arg source "$expected_source" '[.snapshot.telemetry[] | select(.kind == "active-probe" and .pluginId == "istio" and .sourceId == $source)] | length' 2>/dev/null || printf '0')
      if [[ "$matched" =~ ^[0-9]+$ ]] && (( matched > 0 )); then
        log "live graph contains $matched Istio OTLP telemetry rollup(s)"
        exit 0
      fi
      kill -0 "$port_forward_pid" 2>/dev/null || {
        cat "$port_forward_log" >&2
        fail "AgentShield API port-forward exited unexpectedly"
      }
      sleep 1
    done
    kube -n agentshield-system logs deployment/agentshield --tail=80 >&2 || true
    fail "no Istio OTLP telemetry contribution appeared in the live graph"
    ;;
  stop)
    if ! kind_cluster_exists; then
      log "kind cluster $CLUSTER_NAME does not exist; in-cluster AgentShield is stopped"
      exit 0
    fi
    require_owned_cluster
    kube delete namespace agentshield-system --ignore-not-found --wait=true --timeout=120s
    kube delete clusterrolebinding agentshield-evals-discovery --ignore-not-found
    kube delete clusterrole agentshield-evals-discovery --ignore-not-found
    ;;
  *) fail "unknown telemetry action: $action" ;;
esac
