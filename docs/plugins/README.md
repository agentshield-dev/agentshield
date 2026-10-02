# Plugins

Plugins connect AgentShield to providers. This page is the contract every plugin follows; read it before you change a plugin, collection, projector, or telemetry mapper. The [tutorial](tutorial.md) walks through a sample plugin, the [style guide](style-guide.md) covers code conventions, and the [`create-discovery-plugin` skill](../../.github/skills/create-discovery-plugin/SKILL.md) is a step-by-step checklist.

## Existing plugins

| Plugin | Role | Reads | Contribution | Page |
| --- | --- | --- | --- | --- |
| `kubernetes` | Source, remediation | Kubernetes API (one shared informer per resource type) | `inventory` | [kubernetes.md](kubernetes.md) |
| `istio` | Semantic, telemetry mapper, remediation | Kubernetes collections; OTLP waypoint access logs | `semantics` | [istio.md](istio.md) |
| `cilium` | Semantic, remediation | Kubernetes collections | `cni-semantics` | [cilium.md](cilium.md) |
| `agentgateway` | Semantic | Kubernetes collections | `semantics` | [agentgateway.md](agentgateway.md) |
| `falco` | Telemetry mapper | OTLP Falco alerts | none (host-owned `rollups`) | [falco.md](falco.md) |
| `aws` | Source, telemetry receiver | EC2 APIs, SQS, Firehose | `inventory` | [aws.md](aws.md) |

Every telemetry mapper also owns a `rollups` contribution that the host publishes for it (see [Telemetry](../architecture/telemetry.md#publication)).

## Roles and capabilities

A plugin implements `discovery.Plugin` (`Descriptor()` and `Run(ctx, Runtime)`) and `discovery.PluginInstance` (`SourceID()`). It has one of two roles:

- A **source plugin** owns a provider connection and publishes collections.
- A **semantic plugin** subscribes to another plugin's collections and never opens its own connection to that provider.

Both run a **projector** and publish contributions. Optional interfaces add more:

| Interface | Purpose |
| --- | --- |
| `discovery.TelemetryMappingProvider` | Convert OTLP log records into telemetry events. See [Writing a mapper](../architecture/telemetry.md#writing-a-mapper). |
| `discovery.RemediationProvider` | Offer remediation actions. See [Remediation](../architecture/remediation.md). |
| `discovery.IdentityReferenceResolver` | Turn a provider reference into an identity claim, for example an AWS `providerID` on a Kubernetes Node. The plugin that observes the reference still owns the relationship. |
| `kubernetes.ResourceRequirementsProvider` | Ask the Kubernetes plugin to watch specific resource types. |

A plugin with several parts (say, a projector and a telemetry mapper) tracks each part's state separately: one part being ready or healthy says nothing about another. Parts that share a provider connection or cache get one owner, which hands the same snapshot to each.

### Descriptor

`discovery.Descriptor` declares:

- `ID`, `Version`, and `Description`. `ID` and `Version` are required. `Version` is the plugin's release version and is informational only: it is not stored and is not part of contribution identity, input digests, or assertions, so changing it republishes nothing. In-tree plugins start at `0.1.0` while the project is pre-1.0. Bump it when the plugin's collections, identity schemes, or emitted assertions change in a way consumers should notice.
- `Consumes` and `Publishes`: collection names, for every part of the plugin.
- `IdentitySchemes`: only schemes for an authority this plugin introduces. Any plugin may use a registered scheme, but only for identities from that same authority. Register a new, versioned scheme when your provider is a new authority.

The manager rejects duplicate `(plugin, source)` instances, a collection with two publishers on one source, and a consumed collection with no publisher on that source.

### Runtime

`discovery.Runtime` is the plugin's only way to reach the rest of the system. It is scoped to the plugin's source ID.

| Method | Use |
| --- | --- |
| `Publish(ctx, Change)` | Publish an observation. Its metadata and content digest are stored as a native-event receipt, then its payload is delivered to subscribers in memory. Replaying an event ID with the same content is accepted; with different content, rejected. |
| `MarkReady(ctx, plugin, source, collection, generation)` | Mark a collection's cache coherent. |
| `Subscribe(ctx, collection)` | Receive a sorted replay, a `sync` marker, then live changes. |
| `ReplaceContribution(ctx, plugin, source, ContributionOutput)` | Publish a complete contribution. See [Publication and storage](../architecture/publication-and-storage.md). |
| `ContributionGeneration(ctx, plugin, source)` | Recover the last generation at startup. |

A slow subscriber never blocks publishers; it gets only the latest change per key, so treat each change as the current state of that key ([details](tutorial.md#2-receive-observations)). Keep collections (delivery), contributions (graph ownership), and identity schemes (normalization) separate.

## Kubernetes-backed plugins

Only the Kubernetes plugin talks to the Kubernetes API. A semantic plugin that needs Kubernetes objects:

1. Creates a `kubernetes.ResourceClient[T]` per resource type, with a `ResourceRequirement` (GVR, capability name, required or optional) and a decoder into a typed Go struct.
2. Returns those requirements from `KubernetesResources()`.
3. Lists `client.Collection()` and `kubernetes.CollectionResourceCoverage` in `Consumes`, and no other resource collections.

The Kubernetes plugin opens one informer per GVR across all plugins and publishes it as `kubernetes/resources/<group>/<version>/<resource>` (`core` for the empty group), so two plugins that need Pods share one watch. Never open your own informer.

`plugins/internal/coherentcache` implements the semantic-plugin [lifecycle](#lifecycle) below for these plugins: it publishes only when every resource collection and the coverage collection have synced at the same Kubernetes generation, and takes coverage and its observation time from the sync markers, never from changes after them.

Requirements are grouped into capabilities. A missing required capability fails startup; optional ones report their [coverage](#readiness-health-and-coverage) in `kubernetes/resource-coverage`. Optional collections still get a `sync` marker, so consumers can tell "empty" from "never synced".

## Lifecycle

A source plugin:

1. Recovers its contribution generation.
2. Builds its cache from list/watch, a snapshot feed, or polling.
3. Publishes upserts and deletes with stable event IDs.
4. Waits until the initial cache is complete.
5. Projects the cache and replaces its contribution.
6. Marks its collections ready, only after step 5 succeeds.

A semantic plugin:

1. Subscribes to its collections and applies replay and live changes to a local cache.
2. Waits for the `sync` marker of every collection it consumes.
3. Projects and replaces its contribution, without waiting for any other plugin.
4. If another plugin consumes collections it publishes, marks them ready after its first replacement.

Graph output always comes from the current cache. A change only tells the plugin to project again; never apply events to the graph as patches.

If the provider becomes unavailable after a successful publication, republish the last good input with `degraded` or stale health. Never publish a partial or empty replacement, because omission means deletion. Retire a contribution only when a source is removed on purpose.

## Rules

### Identity and ownership

- Build identity keys from immutable provider IDs, qualified by an authority (for example, cluster ID plus Kubernetes UID). Names, namespaces, labels, IP addresses, hosts, ports, and status are attributes.
- Never open a second connection to a provider another plugin already reads; consume its collection.
- A contribution is the complete current output of one `(plugin, source, contribution name)`. See the [data model](../concepts/data-model.md#contributions-and-generations).
- Reference other plugins' resources by stable identity. An edge to an identity that is not published yet stays unresolved until it arrives. Never wait for another plugin or depend on its publication order.

### Projectors

A projector is a pure function from a complete snapshot to `graph.Input`.

- No clients, goroutines, clocks, logging, storage, or publication. The provider adapter does all I/O and hands the projector an immutable snapshot.
- Decode provider JSON into typed Go structs, not generic maps or `unstructured` values.
- Sort input and output so shuffled input gives the same graph digest.
- If a reference matches nothing or several things, mark it unresolved or ambiguous. Never pick one arbitrarily.
- Use only predicates registered in `pkg/graph`. A genuinely new relationship needs a new predicate there and a migration for the database constraint.
- Keep attributes small and deterministic. Cap long lists and record how many items were left out; never drop a resource, relationship, or facet silently.
- Never put credentials, secret values, raw authorization material, or full provider payloads in attributes or evidence.
- Keep high-churn data out of contributions unless it is the security fact itself. For example, Service-to-Pod edges come from selectors, not EndpointSlices.
- Attach [security semantics](../concepts/security-semantics.md) to every security-relevant fact, or record why it stays provider-native. Do not infer exposure or enforcement from declared configuration or controller status, and keep provider interpretation out of detectors.

### Provenance

- Every assertion carries plugin ID, source ID, a rule ID, and at least one evidence ID.
- Cite every observation used to derive a relationship or facet, not only its subject.
- A rule ID names one meaning. Use a new rule ID when the output changes meaning.
- Build evidence IDs from stable provider identity and revision data; see the [style guide](style-guide.md#evidence-ids).

### Contributions and generations

- Replace the whole contribution every time. Leaving an assertion out retracts it.
- Generations only go up, including across restarts: recover the stored generation at startup and continue from it. Retrying a generation with the same content does nothing; reusing it with different content is rejected. See [Publication and storage](../architecture/publication-and-storage.md#generations).
- If the provider stream can resume, store its cursor separately from the generation.

### Readiness, health, and coverage

Track these separately:

- **Readiness**: the cache is complete.
- **Publication**: a replacement was stored.
- **Health**: observations are current (`healthy`, `degraded`, or stale).
- **Coverage**: which required and optional APIs were actually observed.

A missing optional API is `unsupported` coverage, not a failure; an advertised one that cannot be listed or watched is `degraded`. A required API failure blocks initial readiness, and after a successful publication marks the contribution degraded or stale instead of retracting it. Missing coverage never proves that something does not exist.

### Errors

- Malformed required input fails the whole projection, so the previous contribution stays active. Never skip fields that affect output; a partial replacement retracts valid facts.
- Return an error from `Run` on queue saturation, unexpected subscription closure, a failed required sync, or a publication failure.
- Do not return an error for one bad provider message that can never succeed; drop it, log it without its payload, and count it, as the AWS SQS subscriber does.

The manager supervises each plugin instance separately. When `Run` returns an error or panics (the panic becomes an error with its stack), the manager:

1. logs the failure;
2. republishes each contribution the instance last stored as healthy, at the next generation with `degraded` health, so its assertions stay active;
3. restarts the instance after a backoff that starts at one second, doubles per consecutive failure, is capped at two minutes, and resets once an attempt has run that long.

Other plugins keep running, and their subscriptions to the failed instance's collections stay open. Each attempt runs under its own context, so its subscriptions and watches end with it. The restarted instance recovers its generation and rebuilds its cache as at startup. At its first `MarkReady` of each collection, the runtime deletes the items it did not republish, so objects removed while it was down leave consumers' caches. Each delete's event ID is the item's last event ID with `:upsert` replaced by `:delete` (or `<plugin>:<collection>:<key>:<revision>:delete` if it has no such suffix), so end your upsert event IDs with `:upsert` and give your own deletes the matching ID. A `Run` that returns nil while the process is running is treated as finished and is not restarted. Only a panic in the `Run` goroutine is recovered; a panic in a goroutine the plugin starts still stops the process.

### Telemetry

Raw traffic events go to the telemetry pipeline, never through collections, native events, or contributions. The pipeline writes the raw sink before it updates graph rollups, and applies backpressure instead of dropping events. Event IDs must be stable across retries, and the original observation time must be kept. See the [mapper contract](../architecture/telemetry.md#writing-a-mapper).

## Testing

Test at least:

- stable identity, and the same graph digest for shuffled and reversed input;
- inclusion, relationship direction, facets, attribute encoding, caps, fan-out, and exact provenance;
- security semantics, per the [review checklist](../concepts/security-semantics.md#review-checklist-for-projector-changes);
- malformed input and unresolved or ambiguous references;
- replay before `sync` with no early publication, then live upserts and deletes, and deletion by omission;
- restart above the stored generation, idempotent retry (including the same event received later), and rejected conflicting reuse;
- health transitions, backpressure, and unexpected subscription closure;
- for a plugin with several parts, that one part failing leaves the others alone.

The [style guide](style-guide.md#tests) shows how we write these tests. Run:

```bash
gofmt -w ./plugins/<name>
go test -race ./plugins/<name> ./pkg/discovery ./pkg/graph ./pkg/state
go test ./...
make test-postgres
```

Kubernetes and Istio projector changes also need a `make eval-run` pass, which a maintainer runs. See [Testing](../development/testing.md#evaluation-suite).

## Documenting a plugin

Each plugin has a page in this directory covering:

- provider dependencies, credentials, permissions, rate limits, and consistency model;
- authority ID, source ID, identity schemes, contribution names, collections, and any stream cursor;
- resources, predicates, facets, and evidence emitted, who consumes them, and expected latency;
- security semantics, and native-only facts with the reason and what evidence would change that (also in the [coverage table](../concepts/security-semantics.md#current-coverage-by-provider));
- failure, backpressure, resync, and deletion behavior;
- expected inventory size and change rate;
- telemetry provenance (active probe, passive, or inferred), if any.
