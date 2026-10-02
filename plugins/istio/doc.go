// Package istio projects Istio registry, routing, security, ambient, and
// waypoint semantics onto Kubernetes identities and maps Istio active-probe
// access logs to telemetry events.
//
// # Inputs
//
// The plugin opens no Kubernetes watch. It declares its GroupVersionResources
// through KubernetesResources and consumes the Kubernetes plugin's per-GVR
// collections and resource-coverage collection. Namespaces, Pods, Services,
// and Deployments are required; Gateway API Gateways and the Istio security
// and networking APIs are optional capabilities whose absence is reported as
// coverage, not as missing policy.
//
// # Identity and graph output
//
// Istio resources are Kubernetes objects, so assertions reuse the Kubernetes
// kubernetes.io/v1 Object scheme (cluster authority, apiVersion/kind/UID key).
// ServiceEntry hosts become provider-neutral DNS or IP network destinations
// under the configured network ID. The "semantics" contribution emits
// governed-by (AuthorizationPolicy, PeerAuthentication, waypoint association)
// and exposes (ServiceEntry, VirtualService destinations) relationships and
// authorization-posture, istio-mtls, istio-data-plane, and serviceentry-binding
// facets with typed security semantics where the neutral schema can represent
// them. [CollectionProjection] marks that contribution ready.
//
// Projection starts only after every object collection and the coverage
// collection have synchronized to a coherent generation. Malformed provider
// objects fail the candidate projection and keep the previous contribution.
// Unexpected subscription closure publishes a degraded replacement from the
// last coherent cache and returns an error.
//
// # Telemetry
//
// [Plugin.TelemetryMappings] registers an OTLP log mapper for active-probe
// records, typically emitted by an ambient waypoint. It resolves namespace and
// name endpoint references to UIDs from the last coherent object snapshot and
// rejects records whose identity cannot be resolved rather than guessing.
//
// The package also implements the peer-authentication/v1 remediation action,
// which requires mutual TLS for a Pod with a STRICT PeerAuthentication.
//
// See docs/plugins/istio.md for the telemetry attribute contract.
package istio
