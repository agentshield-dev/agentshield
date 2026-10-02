# Istio plugin

The `istio` plugin describes Istio security configuration in the graph: authorization policy, mTLS policy, ambient enrollment, waypoints, ServiceEntries, and VirtualService routing. It also maps Istio waypoint access logs into telemetry and provides the PeerAuthentication remediation action.

It is a semantic plugin: it reads Kubernetes collections and never opens its own Kubernetes watch.

Code: `plugins/istio`.

## Summary

| | |
| --- | --- |
| Plugin ID, version | `istio`, `0.0.1` |
| Role | Semantic plugin, telemetry mapper, remediation provider |
| Authority | `--istio-cluster-id`; network destinations use `--istio-network-id` |
| Source ID | `--istio-source-id` |
| Mesh root namespace | `--istio-root-namespace` (default `istio-system`) |
| Identity schemes | Uses `kubernetes.io/v1, Kind=Object` and `agentshield.io/v1, Kind=NetworkDestination`; registers none of its own |
| Contribution | `semantics`; telemetry rollups in `rollups` |
| Collections consumed | The resources below, plus `kubernetes/resource-coverage` |
| Collection published | `istio/projection` |

## Kubernetes resources requested

| Capability | Resources | Required |
| --- | --- | --- |
| `istio-core-v1` | namespaces, pods, services | Yes |
| `istio-workloads-v1` | deployments | Yes |
| `istio-gateway-v1` | `gateway.networking.k8s.io/v1` gateways | No |
| `istio-security-v1` | `security.istio.io/v1` authorizationpolicies, peerauthentications | No |
| `istio-networking-v1` | `networking.istio.io/v1` serviceentries, virtualservices | No |

If the Istio CRDs are not installed, coverage is `unsupported` and the plugin publishes what it can. Missing coverage does not mean there is no policy.

## Graph output

| Rule ID | Output |
| --- | --- |
| `istio.authorization-policy` | `istio/authorizationpolicy` resource |
| `istio.authorization-policy-target` | Workload `governed-by` AuthorizationPolicy, with security semantics (governance / authorization) |
| `istio.authorization-policy-posture` | `authorization-posture` facet on the policy |
| `istio.peer-authentication-target` | Workload `governed-by` PeerAuthentication, with security semantics (governance / transport-authentication) |
| `istio.peer-authentication-facet` | `istio-mtls` facet, key `peerauthentication/<namespace>/<name>`, on the target |
| `istio.ambient-intent` | `istio-data-plane` facet, key `ambient`, on enrolled workloads |
| `istio.waypoint-association` | Workload `governed-by` waypoint Gateway (observed binding, `effect=unknown`) |
| `istio.serviceentry` | `istio/serviceentry` resource |
| `istio.serviceentry-exposes-host` | ServiceEntry `exposes` network destination for each host |
| `istio.serviceentry-binding` | `serviceentry-binding` facet: endpoint counts and address classes, never endpoint values |
| `istio.virtualservice-destination` | VirtualService `exposes` destination, with route count, subsets, ports, and mirror flag |

Targeting follows Istio: a policy in the root namespace without a selector governs every Namespace; one with a workload selector governs matching Pods in every namespace, as Istio looks up root-namespace policies for every workload. A selector policy elsewhere governs matching Pods in its own namespace only.

`istio-data-plane` records ambient enrollment intent and waypoint binding. It does not claim that traffic is encrypted or that policy is enforced. `istio-mtls` records one PeerAuthentication declaration.

VirtualService forwarding, ServiceEntry declarations, unresolved waypoint or ambient intent, and telemetry stay provider-native; see the [security semantics coverage table](../concepts/security-semantics.md#current-coverage-by-provider).

## Lifecycle

The plugin subscribes to each requested collection and the coverage collection, builds a local cache from replay, waits for every `sync` marker, then projects and replaces `semantics`. Each later change re-projects the cache and publishes a new generation. Malformed objects fail the projection and keep the previous contribution. An unexpected subscription closure stops the plugin with an error.

## Telemetry

The Istio mapper turns waypoint access logs into `active-probe` telemetry events. It matches OTLP records whose attribute `agentshield.telemetry.kind` is `active-probe`. Subject is the caller and object is the destination.

Istio's default access logs do not carry these attributes. You need a custom `envoyOtelAls` extension provider in `meshConfig` that emits the `agentshield.*` attributes below, and a `Telemetry` resource that turns that provider on for your waypoints.

### Example waypoint configuration

`evals/config/istio-ambient.yaml` configures an Envoy OpenTelemetry access-log provider that emits these attributes from Istio peer metadata:

```yaml
meshConfig:
  extensionProviders:
    - name: agentshield-otel
      envoyOtelAls:
        service: opentelemetry-collector.observability.svc.cluster.local
        port: 4317
        logName: agentshield-istio
        logFormat:
          labels:
            agentshield.telemetry.kind: active-probe
            agentshield.event.id: '%REQ(X-REQUEST-ID)%'
            agentshield.evidence.id: '%REQ(X-REQUEST-ID)%'
            agentshield.subject.k8s.api_version: apps/v1
            agentshield.subject.k8s.kind: Deployment
            agentshield.subject.k8s.namespace: '%FILTER_STATE(downstream_peer_obj:FIELD:namespace)%'
            agentshield.subject.k8s.name: '%FILTER_STATE(downstream_peer_obj:FIELD:workload)%'
            agentshield.object.k8s.api_version: v1
            agentshield.object.k8s.kind: Service
            agentshield.object.k8s.namespace: '%FILTER_STATE(upstream_peer_obj:FIELD:namespace)%'
            agentshield.object.k8s.name: '%FILTER_STATE(upstream_peer_obj:FIELD:service)%'
            agentshield.object.authority: '%REQ(:AUTHORITY)%'
            agentshield.operation: '%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%'
            agentshield.coverage: ambient-waypoint
            agentshield.probe.http_statuses: '%RESPONSE_CODE%'
```

The collector then forwards these logs to AgentShield with an OTLP/HTTP exporter (see [Telemetry](../architecture/telemetry.md#otlp-logs)). Restrict who can send to the collector, because anyone who can set `agentshield.telemetry.kind` can route records to this mapper.

The evaluation harness enables the provider per namespace with a `Telemetry` resource that targets the waypoint (`evals/observation_istio.go`):

```yaml
apiVersion: telemetry.istio.io/v1
kind: Telemetry
metadata:
  name: waypoint-access-logs
  namespace: <namespace>
spec:
  targetRefs:
  - {group: gateway.networking.k8s.io, kind: Gateway, name: waypoint}
  accessLogging:
  - providers:
    - {name: agentshield-otel}
```

### Limitation: only Deployment callers resolve

Istio peer metadata gives the caller's workload name but not its UID or owner kind, so the example hard-codes `agentshield.subject.k8s.kind: Deployment`. The mapper looks up that kind, namespace, and name in its Kubernetes cache. A caller run by a StatefulSet, DaemonSet, Job, or bare Pod does not match a Deployment, so its record is rejected and counted in the OTLP partial-success response.

Name lookup only covers the kinds this plugin caches: Namespaces, Pods, Services, Deployments, Gateway API Gateways, AuthorizationPolicies, PeerAuthentications, ServiceEntries, and VirtualServices. A sender that supplies `agentshield.subject.k8s.uid` (or `agentshield.object.k8s.uid`) can name any kind, because a UID needs no lookup.

### Limitation: short Service names may not resolve

In the ambient eval cluster, the waypoint's upstream peer metadata did not name the destination Service. The mapper then falls back to `agentshield.object.authority`, which resolves only `<service>.<namespace>.svc.cluster.local[:port]`. A request addressed to a short name such as `http://catalog:8080` therefore cannot be resolved and is rejected, counted in the OTLP partial-success response. The rule evals address Services by fully qualified name for this reason.

### Attributes

Each endpoint needs an API version and kind, plus either a UID or a namespace and name. With namespace and name, the mapper resolves the UID from its Kubernetes cache. It never guesses: missing required fields reject the record.

| Attribute | Type | Notes |
| --- | --- | --- |
| `agentshield.telemetry.kind` | string | **Required.** Must be `active-probe`. |
| `agentshield.event.id` | string | **Required.** Stable across retries, together with the timestamp. |
| `agentshield.evidence.id` | string | Optional. Defaults to the event ID. |
| `agentshield.operation` | string | **Required.** For example `GET /allowed`. |
| `agentshield.outcome` | string | Optional, `allowed` or `denied`. Derived from the HTTP status when absent. |
| `agentshield.coverage` | string | **Required.** For example `ambient-waypoint`. |
| `agentshield.count` | integer or string | Optional positive count. Default 1. |
| `agentshield.subject.k8s.api_version` | string | **Required.** |
| `agentshield.subject.k8s.kind` | string | **Required.** |
| `agentshield.subject.k8s.uid` | string | Preferred when available. `-` counts as absent. |
| `agentshield.subject.k8s.namespace`, `agentshield.subject.k8s.name` | string | Used when the UID is absent. |
| `agentshield.object.k8s.api_version` | string | **Required.** |
| `agentshield.object.k8s.kind` | string | **Required.** |
| `agentshield.object.k8s.uid` | string | Preferred when available. `-` counts as absent. |
| `agentshield.object.k8s.namespace`, `agentshield.object.k8s.name` | string | Used when the UID is absent. |
| `agentshield.object.authority` | string | Optional. A `<service>.<namespace>.svc.cluster.local[:port]` value resolves the Service when peer metadata lacks it. |
| `agentshield.probe.http_statuses` | string | Optional HTTP status. `403` means `denied`; anything else means `allowed` when no outcome is set. |
| `agentshield.probe.expected_status` | string | Optional. If it equals the actual status, `probe/result` is `pass`. |
| `agentshield.probe.result` | string | Optional. Defaults to `observed`. Separate from outcome. |

## Remediation

Action `peer-authentication/v1` implements `transport.require-mutual-tls` for `kubernetes/pod` targets. It labels the Pod with `agentshield.io/remediation-target` and creates a `STRICT` PeerAuthentication that selects the label. Existing PeerAuthentications that select the Pod are conflicts; AuthorizationPolicies are not. The process needs `update` on Pods and `create` on PeerAuthentications. See [Remediation](../architecture/remediation.md).
The Istio flags are plugin-prefixed. Set `--istio-cluster-id` to the Kubernetes source's cluster ID when Istio assertions should refer to the same Kubernetes objects. `--istio-source-id` identifies the Istio producer independently of the Kubernetes source.
