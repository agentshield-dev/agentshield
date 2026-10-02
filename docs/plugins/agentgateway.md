# agentgateway plugin

The `agentgateway` plugin describes [agentgateway](https://agentgateway.dev) instances managed through the Kubernetes Gateway API: which Gateways agentgateway controls, which HTTPRoutes attach to them, and which Services those routes send traffic to. It also normalizes agentgateway access logs into telemetry events.

It is a semantic plugin: the Kubernetes plugin watches the Gateway API resources for it.

Code: `plugins/agentgateway`.

## Summary

| | |
| --- | --- |
| Plugin ID, version | `agentgateway`, `1.0.0` |
| Role | Semantic plugin |
| Authority | `--agentgateway-cluster-id` |
| Source ID | `--agentgateway-source-id` |
| Identity scheme | `kubernetes.io/v1, Kind=Object` |
| Contribution | `semantics` |
| Collections consumed | The resources below, plus `kubernetes/resource-coverage` |
| Provider cursor | None |

## Kubernetes resources requested

| Capability | Resources | Required |
| --- | --- | --- |
| `agentgateway-core-v1` | services | Yes |
| `gateway-api-v1` | `gateway.networking.k8s.io/v1` gatewayclasses, gateways, httproutes | No |

The process needs `get`, `list`, and `watch` on these resources. Cost grows linearly with the number of objects plus route references in one cluster.

## Selecting agentgateway Gateways

A Gateway is selected when its GatewayClass has controller `agentgateway.dev/gatewayclass-controller`. If the GatewayClass object is not observed, a class named `agentgateway` is used as a fallback. An observed GatewayClass always wins: a class named `agentgateway` with a different controller is excluded, together with its Gateways.

The controller names and fallback class names are fields of `agentgateway.Config`. `cmd/agentshield` uses the defaults; there is no flag to change them.

## Graph output

The plugin asserts the selected GatewayClasses, Gateways, HTTPRoutes, and referenced Services as resources under their Kubernetes identities, so its facets and edges attach to the same nodes as the Kubernetes inventory.

| Rule ID | Output |
| --- | --- |
| `agentgateway.gateway.facet` | `agentgateway-ingress` facet on a selected Gateway: class source, listeners, addresses, `Accepted` and `Programmed` values |
| `agentgateway.gateway.class` | Gateway `governed-by` GatewayClass, when the class object is observed |
| `agentgateway.httproute.facet` | `agentgateway-route` facet on an attached HTTPRoute: hostnames, `Accepted` and `ResolvedRefs` values |
| `agentgateway.httproute.gateway` | HTTPRoute `member-of` Gateway, for a same-namespace parent reference (acceptance stays in the facet) |
| `agentgateway.backend.facet` | `agentgateway-backend` facet on a referenced same-namespace Service, with a route count |
| `agentgateway.httproute.backend` | HTTPRoute `exposes` Service, for a same-namespace backend reference |

Missing status conditions are recorded as `unknown`, not as negative values.

The `agentgateway-ingress` facet carries exposure security semantics with gateway scope and `effect=unknown`. Its state is `observed` when controller status or addresses exist, `declared` otherwise. A Gateway, its addresses, or `Programmed=True` do not prove external exposure or enforcement. Everything else stays provider-native; see the [security semantics coverage table](../concepts/security-semantics.md#current-coverage-by-provider).

Cross-namespace backend references are not projected, because ReferenceGrants are not observed. They produce a diagnostic instead. A missing backend Service also produces a diagnostic and no edge.

## Lifecycle and failures

Replay and live changes fill a local cache. The plugin publishes after every consumed collection has sent `sync`. Each reconciliation replaces the whole `semantics` contribution.

Gateway API discovery failure or a degraded informer produces degraded health. `unsupported` Gateway API coverage does not prove absence. Malformed Gateway API objects fail the projection and keep the previous contribution. If a subscription closes unexpectedly, the plugin publishes a degraded replacement from its last cache and returns an error.

## Access logs

`normalizeAccessLog` converts one agentgateway access record into a `gateway-request` event with:

- the original observation time;
- the request ID, or a deterministic ID derived from content;
- the client IP as a network-destination identity and the backend Pod UID as the object;
- method, route, response code, and authentication state;
- outcome `allowed` for status below 400, otherwise `denied`;
- coverage `agentgateway-access-log`.

Authenticated requests get an `authenticated/` operation prefix, so rollups record that the request was authenticated without storing the principal. Credentials, headers, bodies, and principal names are dropped.

**Not wired yet:** `ingestAccessLog` sends a normalized event into the telemetry pipeline, but the binary has no access-log transport, configuration, or stored cursor, so nothing calls it today. A future transport must keep request IDs and original timestamps and store any resume cursor separately from the contribution generation.
The agentgateway flags are plugin-prefixed. Set `--agentgateway-cluster-id` to the Kubernetes source's cluster ID when its assertions should refer to the same Kubernetes objects.
