#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_command kind
require_command kubectl
require_owned_cluster

kind delete cluster --name "$CLUSTER_NAME"
rm -f "$KUBECONFIG_PATH" "$OWNER_FILE"
log "deleted owned eval cluster $CLUSTER_NAME"
