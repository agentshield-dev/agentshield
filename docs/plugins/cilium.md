# Cilium plugin

The `cilium` plugin adds Cilium CNI policy and endpoint state to the graph, normalizes Hubble network flows into telemetry events, and provides the CiliumNetworkPolicy remediation action. It does not model Cilium service mesh, Envoy configuration, or L7 policy (HTTP, DNS, Kafka). `CiliumEnvoyConfig` and `CiliumClusterwideEnvoyConfig` are not watched.

It is a semantic plugin: the Kubernetes plugin watches the Cilium CRDs for it.

Code: `plugins/cilium`.

## Summary

| | |
| --- | --- |
| Plugin ID, version | `cilium`, `1.0.0` |
| Role | Semantic plugin, remediation provider |
| Authority | `--cilium-cluster-id` |
| Source ID | `--cilium-source-id` |
| Identity schemes | Uses `kubernetes.io/v1, Kind=Object` (Pods, Nodes, policies) and `agentshield.io/v1, Kind=NetworkDestination` (external IPs in flows) |
| Contribution | `cni-semantics` |
| Collections consumed | The resources below, plus `kubernetes/resource-coverage` |
| Collection published | `cilium/projection` |

CiliumEndpoint and CiliumNode observations enrich the existing Kubernetes Pod and Node nodes; they do not create separate identities. Names and IP addresses are never identity keys.

## Kubernetes resources requested

| Capability | Resources | Required |
| --- | --- | --- |
| `cilium-core-v1` | pods, nodes | Yes |
| `cilium-policy-v2` | `cilium.io/v2` ciliumnetworkpolicies, ciliumclusterwidenetworkpolicies | No |
| `cilium-endpoint-v2` | `cilium.io/v2` ciliumendpoints | No |
| `cilium-node-v2` | `cilium.io/v2` ciliumnodes | No |

A Cilium API that is not served is `unsupported` and does not make the source unhealthy. An API that is served but cannot be synced is `degraded`. A missing or ambiguous Pod or Node reference produces a diagnostic and no facet; it is not read as "no policy".

The process needs `get`, `list`, and `watch` on these resources.

## Lifecycle

After both consumed collections have replayed and sent `sync`, the plugin replaces its whole contribution with the next generation. Deletions are omissions from the next replacement. If a subscription closes unexpectedly, it reports degraded health, keeps the last contribution, and returns an error.

## Graph output

| Rule ID | Output | Security semantics |
| --- | --- | --- |
| `cilium.policy.cni` | `cilium-cni-policy` facet on each Cilium policy: scope and count of CNI-level rules | None (summary) |
| `cilium.policy.selects-pod` | Pod `governed-by` Cilium policy | Governance / network-access, `declared`, `partial` |
| `cilium.endpoint.cni` | `cilium-cni` facet on a Pod: endpoint state, security identity, endpoint ID, ingress/egress enforcement mode | Observed `policy-enabled` value: governance, `observed`, `partial` |
| `cilium.node.cni` | `cilium-cni` facet on a Node: sorted Pod CIDRs and address count | None |

Rules with an L7 `rules` section are not counted and produce no Pod relationships. Their content is never copied into the graph.

Neither the policy edge nor the endpoint facet claims effective enforcement. See the [security semantics coverage table](../concepts/security-semantics.md#current-coverage-by-provider).

## Hubble flows

`normalizeHubbleFlow` converts one Hubble flow into a `network-flow` telemetry event:

- original Hubble timestamp;
- the provider flow ID, or a deterministic ID derived from content;
- Pod UID identities, or network-destination identities for other addresses;
- verdict as outcome, traffic direction as operation, and protocol and ports as properties;
- coverage `hubble-flow` and one evidence ID equal to the event ID.

Only TCP, UDP, SCTP, ICMP, and ICMPv6 are accepted. Labels, payloads, and HTTP fields are not kept. Missing endpoint identity, unknown IP text, zero timestamps, unsupported directions, and L7 protocol names are rejected.

**Not wired yet:** the repository has no Hubble Relay client, no flag to enable one, and no stored Hubble cursor. `ingestHubbleFlow` can send normalized flows into the pipeline, but nothing in `cmd/agentshield` calls it. A future transport must keep flow IDs and timestamps, apply backpressure, and store any resume cursor separately from the contribution generation.

## Remediation

Action `cilium-network-policy/v1` implements `network.declare-ingress-isolation` for `kubernetes/pod` targets. It labels the Pod with `agentshield.io/remediation-target` and creates an ingress-isolating CiliumNetworkPolicy. Before and after the label write it checks NetworkPolicies, CiliumNetworkPolicies, and CiliumClusterwideNetworkPolicies for overlap. See [Remediation](../architecture/remediation.md).
The Cilium flags are plugin-prefixed. Set `--cilium-cluster-id` to the Kubernetes source's cluster ID when Cilium assertions should refer to the same Kubernetes objects.
