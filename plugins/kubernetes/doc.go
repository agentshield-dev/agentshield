// Package kubernetes is the Kubernetes source plugin and the shared Kubernetes
// observation layer that the Istio, agentgateway, and Cilium plugins build on.
//
// # Watches and collections
//
// The plugin owns API discovery and one dynamic shared informer factory per
// cluster. It always watches a required core inventory (namespaces, nodes,
// pods, services, workloads, RBAC, admission, NetworkPolicy, Ingress, and
// related resources) and the optional gateway-api-v1 capability. Semantic
// plugins add GroupVersionResources through [ResourceRequirementsProvider];
// the host merges them with [ResourceRequirements] before construction, so
// each GVR is watched once no matter how many plugins need it. Every watched
// GVR is published as its own kubernetes/resources/<group>/<version>/<resource>
// collection, and [CollectionResourceCoverage] reports per-capability API
// coverage. Consumers read these through [ResourceClient] rather than opening
// their own watches.
//
// Secret observations carry metadata and a sorted key list only; values, type,
// and annotations never enter a collection or the native-event store.
//
// # Identity
//
// Kubernetes objects use the kubernetes.io/v1 Object scheme with the configured
// cluster ID as authority and the lowercased apiVersion/kind/UID as the
// immutable key (see [ClaimFor] and [ClaimForUID]). Names, labels, and IP
// addresses are attributes. Every plugin asserting about a Kubernetes object
// reuses this scheme so its claims converge on the same graph resource.
// Service and Pod addresses materialize provider-neutral network destinations
// under the configured network ID, with exposes edges from their owners.
//
// # Graph output
//
// The "inventory" contribution asserts resources plus contains, runs-on,
// instantiates, uses-identity, exposes, member-of, governed-by, and backed-by
// relationships and network-exposure, transport-posture, policy-targeting, and
// route-backends facets. Node-to-cloud-instance backed-by edges are emitted
// only when a configured IdentityReferenceResolver (for example the AWS
// plugin) resolves the Node's spec.providerID.
//
// A hostNetwork Pod shares its Node's network namespace, so it keeps its
// kubernetes/pod-ip attribute and runs-on edge but never claims the Node
// address through network/addresses or exposes. It gets a network-exposure
// facet keyed host-network (rule kubernetes.pod.host-network-posture) with
// effect unknown and coverage partial: declared ports do not prove a
// listener. Host PID/IPC, privileged, NET_ADMIN, NET_RAW, SYS_ADMIN, and
// explicit unconfined-seccomp counts across regular, init, and ephemeral
// containers stay provider-native attributes, because the neutral vocabulary
// has no kernel-privilege domain. Capability counts reflect declared grants
// after drops; runtime default capabilities are not inferred. They describe
// configuration, not observed sockets, packet capture, iptables changes, or
// syscalls. NetworkPolicy
// enforcement on such Pods is CNI-dependent, so their governed-by edges use
// rule kubernetes.networkpolicy.host-network-target with effect and coverage
// unknown and kubernetes/network-policy-applicability=implementation-defined.
//
// # Failure behavior
//
// An unavailable required API fails startup. An optional API that is not
// advertised is unsupported coverage; one that cannot be read is degraded and
// marks the contribution degraded. Neither proves the absence of unobserved
// objects. Each change replaces the complete contribution at the next
// generation; deletion is omission.
//
// The package also implements the network-policy/v1 remediation action, which
// isolates a Pod's ingress with a NetworkPolicy and a controlled Pod label.
//
// See https://agent-shield.dev/docs/plugins/kubernetes/ and, for the plugin
// contract, https://agent-shield.dev/docs/plugins/contract/.
package kubernetes
