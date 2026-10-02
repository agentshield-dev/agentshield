# Security semantics

Detectors and the reasoning model must not need to understand every provider's policy format. So each plugin uses its projector to translate the security meaning of its assertions into one small, provider-neutral vocabulary: `graph.SecuritySemantics`. A Kubernetes NetworkPolicy, a CiliumNetworkPolicy, and an AWS Security Group attachment can all say "this resource is governed by a network-access policy", in the same words. The plugin is the producer and owner; the projector is its implementation category.

This page is the single reference for that vocabulary and the rules for using it.

## The rule for plugins

Every security-relevant fact a plugin emits through its projector must do one of two things:

1. Carry a `graph.SecuritySemantics` value on the facet or relationship that owns the fact, or
2. Stay provider-native, with a documented reason in the compliance table below.

The value is stored under the attribute key `agentshield.io/security-semantics` on the facet attributes or relationship properties. Build it with `graph.WithSecuritySemantics`. It is part of the assertion, so it has the same provenance, evidence, replacement, and retraction as the facet or relationship that carries it. It does not create a separate graph object.

The native assertion stays in the graph next to it. The neutral value is a summary for detectors and reasoning; the native attributes and evidence are what a person or the model drills into.

The graph compiler validates every value that is present. It cannot tell whether a plugin omitted required semantics. Tests for the plugin's projector and code review enforce that.

## Vocabulary (`v1`)

| Field | Allowed values |
| --- | --- |
| `version` | `v1` |
| `class` | `exposure`, `governance` |
| `domain` | `network-access`, `authorization`, `transport-authentication` |
| `state` | `declared`, `observed`, `unknown` |
| `scope` | `workload`, `namespace`, `mesh`, `service`, `gateway`, `cluster`, `external`, `unknown` |
| `direction` | `ingress`, `egress`, `bidirectional`, `not-applicable`, `unknown` |
| `coverage` | `complete`, `partial`, `unknown` |
| `protocols` | Up to 16 uppercase tokens, 1-32 characters each |
| `ports` | Up to 64 unique `(protocol, port)` pairs; ports are 1-65535 |
| `configurationDigest` | Optional, up to 128 characters |

The allowed `effect` depends on class and domain. `unknown` is always allowed.

| Class / domain | Effects |
| --- | --- |
| `exposure` / `network-access` | `internal`, `external-addressable` |
| `governance` / `network-access` | `restrict`, `allow`, `deny` |
| `governance` / `authorization` | `allow`, `deny`, `audit`, `custom` |
| `governance` / `transport-authentication` | `require`, `permit`, `disable`, `inherit` |

Encoding uppercases, sorts, and deduplicates protocols and ports. Decoding rejects unknown fields, invalid combinations, and any value that is not already in that normalized form. Lists longer than the limits are rejected, not truncated, so a projector must cap its input first and lower `coverage` when it does.

## Choosing `state` and `coverage`

`state` says what the claim is based on:

- `declared`: configuration expresses intent. It does not establish that a provider has activated or enforces the policy.
- `observed`: provider status or runtime facts establish a current state, rather than only desired configuration. Provider evidence that enforcement is enabled is sufficient for an observed enforcement claim; matching traffic, including denied traffic, is not required. If status establishes only resource presence or a controller condition, keep the effect `unknown` unless that status directly establishes a security effect.
- `unknown`: none of the above can be established.

`coverage` says how much of the native fact the summary captures:

- `complete`: the summary represents the whole relevant native rule.
- `partial`: some native detail is missing, for example named ports, port ranges, CIDRs, or a capped list.
- `unknown`: the projector cannot tell.

Coverage is about completeness of the summary, not confidence. It never upgrades `state`.

Be conservative:

- Do not claim external exposure from an Ingress, Gateway, agentgateway Gateway, ServiceEntry, or VirtualService alone. Use `effect=unknown` when externality is not proven.
- Do not claim enforcement from declared policy alone. A controller `Programmed` condition does not by itself prove external reachability or a security effect.
- A configuration digest describes the policy configuration, not the set of targets it currently selects, and must not change when input order changes.

## Current coverage by provider

| Provider | Carries security semantics | Stays provider-native (and why) |
| --- | --- | --- |
| Kubernetes | Service `network-exposure` facet; Ingress and Gateway `network-exposure` facets (gateway scope, `effect=unknown`); Gateway and HTTPRoute `transport-posture` facets; NetworkPolicy `policy-targeting` facets; Pod-to-NetworkPolicy `governed-by` edges | Ownership, containment, identity, current address bindings, Service selectors, Ingress and HTTPRoute backend forwarding, HTTPRoute parent membership and `route-backends`. These are topology or routing. They do not prove a security effect by themselves. Whether a route backend is protected is answered by traversing the graph to the selected Pods and their governance edges. |
| Istio | AuthorizationPolicy `governed-by` edges and `authorization-posture` facets; PeerAuthentication `governed-by` edges (with native target facets for drill-down); resolved waypoint `governed-by` edge as an observed binding with `effect=unknown` | VirtualService forwarding; ServiceEntry declarations and `serviceentry-binding` address-class summaries (they classify addresses without exposing them and do not prove reachability); unresolved waypoint and ambient intent; telemetry. |
| Cilium | Pod-to-Cilium-policy `governed-by` edges (declared, partial); endpoint `policy-enabled` facet (observed, partial) | The policy summary facet, endpoint IDs and state, node and IPAM metadata. L7 rules are reported as diagnostics and omitted because the neutral summary cannot describe them. |
| agentgateway | `agentgateway-ingress` facet on selected Gateways (`effect=unknown`; `observed` when controller status exists) | GatewayClass ownership, route parent membership, route-to-backend forwarding, route and backend metadata. Cross-namespace backends are omitted until ReferenceGrant is observed. |
| AWS | Security Group `aws-security-group-rules` facets (`ingress` and `egress`); ENI-to-Security Group `governed-by` edges (`effect=unknown`) | VPC, subnet, instance, and unresolved Security Group references stay as ENI attributes. Public addresses and `0.0.0.0/0` rules do not produce exposure claims, because route tables, gateways, and network ACLs are not observed. |

## Review checklist for projector changes

When you change a plugin's projector:

1. List each security-relevant fact it emits.
2. For each fact, either attach security semantics or add it to the "stays provider-native" column above with the reason, and say what evidence would let you revisit the decision. Do not use the native-only column to postpone a translation the `v1` vocabulary can already express conservatively.
3. Add tests that check:
   - the value is present on every carrier that needs one,
   - the exact class, domain, state, effect, scope, direction, and coverage,
   - capped protocol and port lists and a stable configuration digest,
   - native attributes are still present,
   - output is the same for shuffled input,
   - the value is retracted with its carrier when the provider object is deleted, and
   - status or configuration that could tempt an overclaim (for example `Programmed=True`) does not produce one.

Compiling the output in a test proves that the values are valid. It does not prove that they are present; the tests above do.
