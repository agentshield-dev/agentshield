#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

for command_name in docker go helm jq kind kubectl sha256sum; do
  require_command "$command_name"
done
if [[ "${UI:-1}" != 0 ]]; then
  require_command make
  require_command pnpm
fi
docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"

catalog="$EVAL_DIR/campaigns.json"
jq -e '
  .schemaVersion == "agentshield.mission-evals/v1alpha1" and
  (.campaigns | length) >= 4 and
  ([.campaigns[].id] | unique | length) == (.campaigns | length) and
  ([.campaigns[] | select(.class == "security")] | length) > 0 and
  ([.campaigns[] | select(.class == "benign")] | length) > 0 and
  ([.campaigns[].threatModel] | unique | length) >= 3 and
  all(.campaigns[]; .expected.requiredObservation == true)
' "$catalog" >/dev/null || fail "mission eval catalog failed validation"

if ! detector_only; then
  [[ -n "${OPENAI_API_KEY:-}" ]] || fail "OPENAI_API_KEY is required for agentgateway model calls"
fi
log "host and mission eval catalog preflight passed"
