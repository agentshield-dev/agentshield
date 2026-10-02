#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

matrix_dir=${EVAL_MATRIX_DIR:-$EVAL_DIR/output/$(date -u +%Y%m%dT%H%M%SZ)-matrix}
mkdir -p "$matrix_dir"

run_variant() {
  local name=$1
  shift
  log "running mission eval variant $name"
  EVAL_ARTIFACT_DIR="$matrix_dir/$name" "$SCRIPT_DIR/eval-run.sh" --variant "$name" "$@"
}

run_variant mini-selected \
  --model gpt-5-mini \
  --model-reasoning-effort low \
  --agentic-investigation-retrieval model_selected

run_variant mini-deterministic \
  --model gpt-5-mini \
  --model-reasoning-effort low \
  --agentic-investigation-retrieval deterministic

run_variant nano-deterministic \
  --model gpt-5.4-nano \
  --model-reasoning-effort low \
  --agentic-investigation-retrieval deterministic

run_variant luna-deterministic \
  --model gpt-6-luna \
  --model-reasoning-effort low \
  --agentic-investigation-retrieval deterministic

run_variant sol-5.6-deterministic \
  --model gpt-5.6-sol \
  --model-reasoning-effort low \
  --agentic-investigation-retrieval deterministic

run_variant astra-deterministic \
  --model gpt-6-astra \
  --model-reasoning-effort low \
  --agentic-investigation-retrieval deterministic

jq -s '{schemaVersion:"agentshield.mission-eval-matrix/v1alpha1",variants:.}' \
  "$matrix_dir/mini-selected/summary.json" \
  "$matrix_dir/mini-deterministic/summary.json" \
  "$matrix_dir/nano-deterministic/summary.json" \
  "$matrix_dir/luna-deterministic/summary.json" \
  "$matrix_dir/sol-5.6-deterministic/summary.json" \
  "$matrix_dir/astra-deterministic/summary.json" \
  >"$matrix_dir/summary.json"

log "mission eval matrix completed: $matrix_dir"
