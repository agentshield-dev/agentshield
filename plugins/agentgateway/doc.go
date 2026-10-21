// Package agentgateway projects agentgateway ingress semantics from Kubernetes
// Gateway API objects and normalizes agentgateway access logs into telemetry
// events.
//
// # Inputs
//
// The plugin opens no Kubernetes watch. It consumes Services (required) and
// GatewayClasses, Gateways, and HTTPRoutes (the optional gateway-api-v1
// capability) through the Kubernetes plugin's per-GVR and resource-coverage
// collections. A Gateway is selected when its observed GatewayClass names a
// configured controller; the configured class names are a fallback only when
// the class object itself is not observed.
//
// # Identity and graph output
//
// All assertions reuse the Kubernetes kubernetes.io/v1 Object scheme (cluster
// authority, apiVersion/kind/UID key), enriching the resources the Kubernetes
// inventory already owns. The "semantics" contribution emits Gateway
// governed-by GatewayClass, HTTPRoute member-of Gateway, and HTTPRoute exposes
// Service relationships plus agentgateway-ingress, agentgateway-route, and
// agentgateway-backend facets. Only same-namespace references are projected;
// cross-namespace backends and missing Services yield diagnostics because
// ReferenceGrant coverage is not observed. Gateway status and addresses are
// recorded as observed state, never as proof of external exposure.
//
// Publication waits for both the object and coverage collections to reach a
// coherent generation. Malformed Gateway API objects fail the candidate
// projection and keep the previous contribution. Unexpected subscription
// closure publishes a degraded replacement from the last coherent cache and
// returns an error.
//
// # Telemetry
//
// The unexported normalizeAccessLog maps an access record to a telemetry
// event with the original timestamp, a request ID or content-derived
// retry-stable event ID, a client IP network-destination claim, and the
// backend Pod UID claim. Credentials, headers, bodies, and principal names are
// dropped. ingestAccessLog submits the event to the shared pipeline. No
// access-log transport or resumable cursor is included yet, so nothing calls
// them outside tests.
//
// See https://agent-shield.dev/docs/plugins/agentgateway/.
package agentgateway
