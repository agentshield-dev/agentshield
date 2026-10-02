# Data model

The graph answers four questions:

1. What resources exist? (resources)
2. How are they connected? (relationships)
3. What independently computed aspects apply to each resource? (facets)
4. What traffic was observed between resources? (telemetry)

Plugins never write graph rows directly. They submit *assertions*, grouped into *contributions*. The graph compiler in `pkg/graph` combines the active assertions from every contribution into one graph. This page describes identities, assertions, and contributions. [Publication and storage](../architecture/publication-and-storage.md) describes how PostgreSQL stores them. The [glossary](glossary.md) defines every term used here.

## Identity

A resource identity is a tuple:

```text
((scheme group, version, kind), authority ID, immutable key)
```

The compiler normalizes the tuple using the registered scheme and derives a deterministic UUIDv5 from it. Identity keys use values the provider never changes. Names, namespaces, labels, IP addresses, and tags are attributes, not identity.

The scheme group names an authority contract, not a plugin. Any plugin may assert against a registered scheme. A plugin only registers a scheme (through `Descriptor.IdentitySchemes`) when it introduces a new authority.

### Kubernetes objects

```text
scheme        = kubernetes.io/v1, Kind=Object
authority ID  = stable cluster ID (for example, --kubernetes-cluster-id)
immutable key = lowercase(apiVersion/kind/UID)
```

`Object` covers every Kubernetes resource type because the API version and kind are already part of the key. A Pod therefore has one identity whether it is referenced by the Kubernetes plugin, an Istio policy, a Cilium endpoint, or a telemetry event. A deleted and recreated object gets a new UID and a new graph node.

The per-type collection that delivered the object, such as `kubernetes/resources/core/v1/pods`, is not part of its identity.

The `apiVersion` in the key is the group and version that AgentShield asks the API server for, which is fixed in each plugin's code (for example `security.istio.io/v1` for AuthorizationPolicies and `cilium.io/v2` for Cilium policies). It is not the CRD's storage version. So:

- Changing a CRD's storage version, or adding another served version, does not change any identity. The API server converts objects to the version AgentShield requested.
- If the cluster stops serving the version AgentShield requests, that resource type is reported as `unsupported` in coverage at startup (or startup fails, for a required type) and its objects are not in the graph.
- If a future AgentShield release requests a different version for a type (for example moving from `v1beta1` to `v1`), every object of that type gets a new identity. The next publication retracts the old resources and asserts new ones, findings that cite the old identities are invalidated, and history does not link the two. See [Known limits](../architecture/overview.md#known-limits).

### Built-in network schemes

`pkg/graph` registers three provider-neutral schemes that any plugin may use:

```text
agentshield.io/v1, Kind=NetworkDestination
  authority ID  = network realm ID (--kubernetes-network-id, defaults to that plugin's cluster ID)
  immutable key = dns/<host> or ip/<address>
  resource kind = network/destination

agentshield.io/v1, Kind=NetworkPeerClass
  authority ID  = network realm ID
  immutable key = one of private-ip, loopback-ip, link-local-ip, special-use-ip,
                  external-source, external-destination, dns-source, dns-destination
  resource kind = network/peer-class

agentshield.io/v1, Kind=ProcessClass
  authority ID  = cluster ID of the telemetry plugin
  immutable key = one of shell
  resource kind = process/class
```

A network destination lets configuration (for example an Istio ServiceEntry host) and telemetry refer to the same address. A peer class stands in for addresses that match no known resource, so unknown traffic does not create one graph node per IP address. A process class is the bounded object of `process-exec` telemetry: it names a category of process, not an executable path or process instance, which stay in the raw sink.

### Cloud resources

A cloud plugin registers its own scheme. The AWS plugin uses:

```text
aws.amazon.com/v1, Kind=Resource
  authority ID  = 12-digit owner account ID
  immutable key = <partition>/ec2/<region>/<type>/<id>
```

Two providers that describe the same thing (for example a Kubernetes Node and the EC2 instance behind it) keep separate identities. They are joined by a relationship (`backed-by`), not merged.

## Assertions

Every assertion carries:

- `pluginId`: the plugin that made the claim.
- `sourceId`: the configured source instance.
- `ruleId`: the projector rule, such as `kubernetes.service.selector`. Rule IDs never change meaning; new behavior gets a new ID.
- `evidenceIds`: sorted references to the native events or telemetry events that support the claim. A relationship cites every observation it needed. A Service-to-Pod `exposes` edge cites both the Service and the Pod.

`ReplaceContribution` rejects any assertion whose plugin ID or source ID does not match the contribution it is submitted in. It never rewrites them. When it reads the current graph back, the store checks each stored assertion against its owning contribution again.

Each assertion is stored once by SHA-256 content address. If two contributions submit the same assertion, they share the stored content and each keeps its own membership.

### Resources

A resource assertion gives an identity claim, a kind (for example `kubernetes/deployment` or `aws/ec2-security-group`), a display name, and attributes. Several plugins may assert the same resource; their assertions are grouped under one graph node. If they disagree on kind, the compiler records a conflict.

Plugins keep only resources that matter for security. For example, the Kubernetes plugin follows ReplicaSets to find a Pod's owner but emits a Deployment-to-Pod `instantiates` edge instead of a ReplicaSet node. It does not watch EndpointSlices.

Plugins may set two provider-neutral attributes when they know them for certain:

- `network/addresses`: the current addresses of a Pod, Service, or ENI.
- `network/role`: `control-plane-api` (the `default/kubernetes` Service), `service`, or `workload`.

For each current address, the plugin also emits a `network/destination` resource and an `exposes` edge to it. These are current facts, retracted when the address goes away. Telemetry uses them to resolve observed IP addresses to resources.

### Relationships

A relationship is a directed edge:

```text
(subject, predicate, object, optional qualifier)
```

Predicates are registered in `pkg/graph` and checked by a database constraint. The current set:

| Predicate | Example |
| --- | --- |
| `contains` | Namespace contains Pod |
| `instantiates` | Deployment instantiates Pod |
| `member-of` | HTTPRoute is a member of a Gateway |
| `uses-identity` | Pod uses ServiceAccount |
| `exposes` | Service exposes Pod; Pod exposes a network destination |
| `governed-by` | Pod governed by NetworkPolicy; ENI governed by Security Group |
| `communicates-with` | Workload communicates with Service (from telemetry) |
| `runs-on` | Pod runs on Node |
| `backed-by` | Node backed by EC2 instance |
| `executes` | Pod executes the `shell` process class (from runtime telemetry) |

A plugin may point a relationship at an identity that another contribution has not published yet. The relationship stays `unresolved` until both endpoints exist. Graph traversal skips unresolved relationships.

Adding a predicate is a data-model change: add it in `pkg/graph`, add a migration that updates the predicate constraint, and update this table.

### Facets

A facet attaches a plugin-owned aspect to a resource:

```text
(resource identity, facet kind, facet key, attributes)
```

`kind` names the aspect. `key` identifies which mechanism or object it came from. For example, Istio records data-plane enrollment and mTLS policy as separate facets:

```text
kind = istio-data-plane   key = ambient
kind = istio-mtls         key = peerauthentication/<namespace>/<name>
```

Facets let several plugins describe the same resource without overwriting each other.

### Security semantics

A facet or relationship that has security meaning carries a `graph.SecuritySemantics` value in its attributes or properties. It states the meaning in provider-neutral terms: for example "governance / network-access / restrict / declared / partial coverage". The vocabulary, validation rules, and per-provider coverage are documented in [security semantics](security-semantics.md).

### Telemetry

A telemetry assertion is a per-minute rollup of traffic between two resources. Its subject and object use the same identities as inventory, so traffic and topology meet at the same nodes. Exact unmatched addresses are replaced by a network peer class before rollup; the raw address stays in the raw sink. [Telemetry](../architecture/telemetry.md) describes the event schema, the rollup, and its limits.

## Contributions and generations

A contribution is the complete current output of one `(plugin ID, source ID, contribution name)` tuple. For example, the Kubernetes plugin owns `(kubernetes, <source ID>, inventory)` and Istio owns `(istio, <source ID>, semantics)`.

A plugin never patches a contribution. It submits the whole desired output as a new generation. Anything it omits is retracted. If generation 7 contained A, B, C and generation 8 contains A, C, D, then B is retracted and D is added. Assertions owned by other contributions are not affected.

Each replacement carries a generation number that must increase. A source that fails after a successful publication keeps its last contribution and reports degraded or stale health. A source removed on purpose is retired with an empty final version. The exact generation rules, statuses, and the transaction that applies them are in [Publication and storage](../architecture/publication-and-storage.md#generations).

Contributions are independent. Istio can publish a policy edge to a Pod before the Kubernetes contribution with that Pod exists; the edge resolves when the Pod arrives. No plugin waits for another plugin to publish.

## Compiling the graph

The graph compiler is a pure function from assertions to a graph. It:

- normalizes identity claims and derives resource IDs,
- checks provenance, predicates, and security semantics,
- groups assertions that describe the same resource, facet, or relationship,
- marks unresolved relationships and kind conflicts, and
- sorts everything so the same assertions always produce the same JSON and SHA-256 digest, regardless of input order.

The same compiler runs when a contribution is published and when the current graph is read. [Publication and storage](../architecture/publication-and-storage.md) explains both paths.
