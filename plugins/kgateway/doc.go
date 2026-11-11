// Package kgateway projects kgateway policy, backend, and gateway semantics
// from the gateway.kgateway.dev/v1alpha1 CRDs.
//
// # Inputs
//
// The plugin opens no Kubernetes watch. It consumes Services (required),
// GatewayClasses, Gateways, and HTTPRoutes (gateway-api-v1), and one optional
// capability per kgateway CRD: TrafficPolicy, ListenerPolicy,
// BackendConfigPolicy, Backend, DirectResponse, GatewayExtension, and
// GatewayParameters. A CRD the cluster does not serve is reported as
// not-installed on the kgateway-coverage facet of every Gateway whose class
// names a configured controller. Not-installed never means "no policy".
//
// Not covered: the deprecated HTTPListenerPolicy, GRPCRoute and ListenerSet
// targets, TrafficPolicy attached through an HTTPRoute ExtensionRef filter,
// and vendor extension CRDs outside gateway.kgateway.dev.
//
// # Identity and graph output
//
// All Kubernetes assertions reuse the kubernetes.io/v1 Object scheme. The
// Kubernetes plugin owns Gateway and HTTPRoute resources, their member-of and
// Service exposes edges; this plugin only adds to them. The "semantics"
// contribution emits:
//
//   - kgateway attributes on each kgateway object, asserted with the same
//     kubernetes/<kind> the Kubernetes plugin uses so the claims merge.
//   - Gateway or HTTPRoute governed-by TrafficPolicy for targetRefs and
//     targetSelectors in the policy namespace, carrying the policy's
//     authorization (or, for an ACL only, network-access) semantics.
//   - An authorization-posture facet on a TrafficPolicy that configures
//     extAuth, jwtAuth, basicAuth, apiKeyAuth, oauth2, or rbac, and a
//     network-access-posture facet for an acl. Explicitly disabled auth is
//     listed in kgateway/auth-disabled and carries no semantics. Route over
//     gateway precedence is not resolved, so coverage is partial.
//   - Gateway governed-by ListenerPolicy with access-log and client address
//     settings, provider-native because they shape observation, not access.
//   - Service or Backend governed-by BackendConfigPolicy with a
//     transport-posture facet: CA-verified TLS is require, insecureSkipVerify
//     is permit.
//   - A kgateway-egress facet on each Backend; dynamicForwardProxy is open
//     egress (external-addressable). Static hosts become network destinations
//     the Backend exposes. HTTPRoute exposes Backend for same-namespace refs.
//   - A kgateway-direct-response facet on HTTPRoutes answered by a
//     DirectResponse filter.
//   - A kgateway-gateway-service exposure facet on a Gateway that resolves
//     GatewayParameters with a Service type.
//
// Malformed objects fail the candidate projection and keep the previous
// contribution. Unresolved references yield diagnostics, not graph facts.
//
// See https://agent-shield.dev/docs/plugins/kgateway/.
package kgateway
