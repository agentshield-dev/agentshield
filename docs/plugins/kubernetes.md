# Kubernetes plugin

The `kubernetes` plugin is the only component that talks to the Kubernetes API. It watches cluster objects, publishes them as collections for the semantic plugins (Istio, Cilium, agentgateway), and projects inventory and topology into the graph. It also provides the NetworkPolicy remediation actions.

Code: `plugins/kubernetes`.

## Summary

| | |
| --- | --- |
| Plugin ID, version | `kubernetes`, `0.0.1` |
| Role | Source plugin, remediation provider |
| Authority | `--kubernetes-cluster-id` (default `local`) |
| Network realm | `--kubernetes-network-id` (defaults to the cluster ID) |
| Source ID | `--kubernetes-source-id` (default `kubernetes/local`) |
| Identity scheme | `kubernetes.io/v1, Kind=Object`, key `lowercase(apiVersion/kind/UID)`. See [data model](../concepts/data-model.md#kubernetes-objects). |
| Contribution | `inventory` |
| Collections published | `kubernetes/resources/<group>/<version>/<resource>` per watched type; `kubernetes/resource-coverage` |
| Object event IDs | `kubernetes:<lowercase(apiVersion/kind/UID)>:<resourceVersion>:<upsert or delete>`, the same string projectors cite as evidence (`projectkit.KubernetesEventID`) |
| Provider cursor | None; informers handle list/watch recovery |

Choose `--kubernetes-cluster-id` once per cluster and never change it. It is part of every Kubernetes identity in the graph; changing it makes every resource look new. Kubernetes-backed consumer plugins also have their own prefixed cluster-ID options; set each to the same value when their assertions must reference these same objects.

## Connecting

With `--kubernetes-kubeconfig`, the plugin uses that file. Without it, it uses in-cluster configuration when `KUBERNETES_SERVICE_HOST` is set, and otherwise the standard kubeconfig loading rules (`KUBECONFIG`, then `~/.kube/config`, current context).

## What it watches

Required resources (startup fails if any are missing):

| Capability | Resources |
| --- | --- |
| `core` | namespaces, nodes, serviceaccounts, pods, services |
| `configuration` | configmaps, secrets |
| `storage` | persistentvolumeclaims |
| `workloads` | deployments, statefulsets, daemonsets, replicasets |
| `batch` | jobs, cronjobs |
| `ingress` | ingresses |
| `network-policy` | networkpolicies |
| `rbac` | roles, rolebindings, clusterroles, clusterrolebindings |
| `admission` | mutatingwebhookconfigurations, validatingwebhookconfigurations, validatingadmissionpolicies, validatingadmissionpolicybindings |

`validatingadmissionpolicies` is `admissionregistration.k8s.io/v1`, so the cluster must run Kubernetes 1.30 or later.

Optional: Gateway API `gateways` and `httproutes` (`gateway-api-v1`). The semantic plugins add their own requirements (for example Istio security CRDs, Cilium CRDs, and `gatewayclasses`); see their pages.

The plugin opens one shared informer per unique resource type, with a 30-minute resync. Secrets are published with metadata and a sorted `keys` list only; values, type, and annotations never enter collections or the database. The informer itself still reads Secrets, so the service account needs `list` and `watch` on them.

### RBAC

The process needs `get`, `list`, and `watch` on every resource above plus those requested by enabled semantic plugins. `evals/manifests/agentshield.yaml.tmpl` contains a complete read-only ClusterRole (`agentshield-evals-discovery`) you can copy. Remediation actions additionally need write access; see [below](#remediation).

## Coverage

At startup the plugin checks API discovery for every requested resource and publishes a coverage record per resource type on `kubernetes/resource-coverage`. Each discovery request is abandoned after 30 seconds; a stalled optional API is then `degraded` and a stalled required one fails startup.

| Status | Meaning |
| --- | --- |
| `covered` | Watched and synced |
| `unsupported` | Optional and not served by the cluster |
| `degraded` | Advertised but could not be discovered or watched |
| `failed` | Required and unavailable (startup fails) |

`unsupported` and `degraded` coverage never mean the objects do not exist. Semantic plugins wait for the coverage collection before publishing.

## Lifecycle

1. Recover the contribution generation.
2. Start informers and wait until this plugin's handler on each one has processed the initial list (the handler registration's `HasSynced`, not the informer's, which only means the store is filled). Until then the collections are still missing objects, and marking them ready would make semantic plugins retract facts about the Pods they have not yet seen.
3. Publish coverage, project all cached objects, and replace `inventory`.
4. Mark every resource collection and the coverage collection ready.
5. On any add, update, or delete, publish the change and schedule a reconciliation. Changes arriving during a reconciliation are coalesced into the next one. Each reconciliation re-projects the full cache and publishes a new generation.

An informer callback that fails to publish, or caches that never sync, stop the plugin with an error, and the manager restarts it (see [Errors](README.md#errors)).

## Graph output

### Resources

Every watched object with a UID becomes a resource of kind `kubernetes/<lowercase kind>`, except ReplicaSets, EndpointSlices, and Events. Gateway API objects are included only when Gateway API coverage is `covered`. Objects watched only because a semantic plugin requested them (for example Istio AuthorizationPolicies) are projected here too.

Attributes include `kubernetes/api-version`, `kubernetes/name`, `kubernetes/namespace`, `kubernetes/label/<key>`, a `kubernetes/spec-sha256`, and per-kind extras such as `kubernetes/pod-ip`, `kubernetes/provider-id` on Nodes, and, on Deployments, `kubernetes/service-account-name` and `kubernetes/pod-template-sha256`. The Pod template digest covers the template's spec and labels but not its annotations, so a `kubectl rollout restart` does not change it; [Deployment rule authoring](../architecture/detection-rules.md#trigger-and-queue) uses it to draft a rule per revision.

Pods and Services also get `network/addresses` and `network/role` (`control-plane-api` for `default/kubernetes`, `service` for other Services, `workload` for Pods), plus one `network/destination` resource per address with an `exposes` edge to it.

### Relationships

| Rule ID | Edge |
| --- | --- |
| `kubernetes.namespace.contains` | Namespace `contains` namespaced object |
| `kubernetes.owner.instantiates` | Owner `instantiates` object; ReplicaSets are skipped so Deployments point directly at Pods |
| `kubernetes.pod.service-account` | Pod `uses-identity` ServiceAccount |
| `kubernetes.pod.runs-on-node` | Pod `runs-on` Node |
| `kubernetes.node.backed-by-provider` | Node `backed-by` cloud resource, when another plugin (AWS) resolves the Node's `spec.providerID` |
| `kubernetes.service.selector` | Service `exposes` Pod, from the Service selector (not EndpointSlices) |
| `kubernetes.resource-exposes-address` | Pod or Service `exposes` network destination |
| `kubernetes.ingress.backend` | Ingress `exposes` Service |
| `kubernetes.networkpolicy.target` | Pod `governed-by` NetworkPolicy |
| `kubernetes.gateway.parent` | HTTPRoute `member-of` Gateway |
| `kubernetes.httproute.backend` | HTTPRoute `exposes` Service |

### Facets

| Facet kind / key | On | Security semantics |
| --- | --- | --- |
| `network-exposure` / `service` | Service | Exposure, from Service type and ports |
| `network-exposure` / `ingress` | Ingress | Exposure, gateway scope, `effect=unknown` |
| `network-exposure` / `gateway` | Gateway | Exposure, gateway scope, `effect=unknown` |
| `transport-posture` / `gateway`, `parent-listeners` | Gateway, HTTPRoute | Transport posture |
| `policy-targeting` / `networkpolicy` | NetworkPolicy | Governance summary |
| `route-backends` / `httproute` | HTTPRoute | None (routing detail) |

NetworkPolicy rule lists are capped at 100 entries with the full count recorded. Rules with named, ranged, or implicit ports use `coverage=partial`. The full list of carriers and native-only facts is in the [security semantics coverage table](../concepts/security-semantics.md#current-coverage-by-provider).

## Remediation

Action `network-policy/v1` implements `network.declare-ingress-isolation` for `kubernetes/pod` targets. It labels the Pod with `agentshield.io/remediation-target` and creates a NetworkPolicy that selects that label and denies ingress. It needs `update` on Pods and `create` on NetworkPolicies, in addition to read access. See [Remediation](../architecture/remediation.md).

Action `service-network-policy/v1` implements the same outcome for `kubernetes/service` targets. It writes no labels: it creates a NetworkPolicy whose Pod selector is the Service's `spec.selector`, so ingress is denied to every Pod in the namespace with those labels, including Pods created later. A Service without a selector is rejected, as is any selected Pod already covered by another ingress policy. It needs `create` on NetworkPolicies, in addition to read access.

## Scale

Every relevant change re-projects the whole cache, but an identical input digest is not republished and the store writes only affected current-graph rows. Projection remains proportional to inventory size, so plan for inventory size times relevant change rate. Not watching EndpointSlices keeps Pod churn from rewriting Service edges.
