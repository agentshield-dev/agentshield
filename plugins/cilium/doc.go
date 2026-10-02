// Package cilium projects Cilium CNI state onto Kubernetes Pods and Nodes and
// normalizes Hubble flows into telemetry events. It does not model Cilium
// service mesh, Envoy configuration, or L7 policy.
//
// # Inputs
//
// The plugin opens no Kubernetes watch. It declares Pods and Nodes as required
// and CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, CiliumEndpoint, and
// CiliumNode as optional capabilities, consuming them through the Kubernetes
// plugin's per-GVR and resource-coverage collections.
//
// # Identity and graph output
//
// Cilium objects keep their Kubernetes identities (kubernetes.io/v1 Object,
// cluster authority, apiVersion/kind/UID key). CiliumEndpoint and CiliumNode
// enrich the Pod and Node with the same namespace and name, because Cilium
// references them by name, instead of creating competing identities; missing
// or ambiguous matches produce diagnostics and no facet. The "cni-semantics"
// contribution emits governed-by from selected Pods to Cilium policies and
// cilium-cni-policy and cilium-cni facets. Policies with L7 rules contribute
// no rule counts or relationships. Evidence IDs match the Kubernetes plugin's
// upsert event IDs.
//
// Publication waits for both the object and coverage collections to reach a
// coherent generation. Unexpected subscription closure publishes a degraded
// replacement from the last coherent cache and returns an error.
//
// # Telemetry
//
// The unexported normalizeHubbleFlow maps one Hubble flow to a telemetry event
// with the original timestamp, a provider or content-derived retry-stable
// event ID, and Pod UID or network-destination endpoint claims, and
// ingestHubbleFlow submits it to the shared pipeline, which commits raw events
// before any graph rollup. No Hubble Relay transport or resumable cursor is
// included yet, so nothing calls them outside tests.
//
// The package also implements the cilium-network-policy/v1 remediation action,
// which declares ingress isolation for a Pod with a CiliumNetworkPolicy.
//
// See docs/plugins/cilium.md.
package cilium
