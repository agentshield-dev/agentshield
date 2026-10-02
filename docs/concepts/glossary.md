# Glossary

Each term has one meaning across the AgentShield docs and code. Terms are grouped by the stage where they first appear.

## The five terms you need

> - **Resource and identity**: a resource is a node in the graph, such as a Pod or a Security Group. Its identity is built from values the provider never changes (for example cluster ID plus Kubernetes UID), so every plugin that mentions the same Pod lands on the same node; names and labels are just attributes.
> - **Assertion**: one fact a plugin states about the graph: a resource, a relationship, a facet, or a telemetry rollup. Each one records which plugin, source, rule, and evidence produced it.
> - **Contribution**: the complete current output of one plugin for one source under one name, published as a whole, for example `(kubernetes, kubernetes/local, inventory)`. Anything the plugin leaves out of its next publication is retracted.
> - **Generation**: the number on each publication of a contribution. It only goes up, even across restarts; retrying the same generation with the same content changes nothing.
> - **Facet**: a named aspect a plugin attaches to a resource without touching anyone else's data, such as Istio's `istio-mtls` facet on a workload.

The [data model](data-model.md) explains each in depth. The rest of this page defines everything else.

## Providers and plugins

- **Provider**: an external system AgentShield reads from or writes to, such as the Kubernetes API, Istio, Cilium, agentgateway, or AWS EC2.
- **Authority**: the provider namespace that makes an identifier unique. A Kubernetes cluster ID is the authority for Pod UIDs. An AWS account ID is the authority for ENI IDs.
- **Source**: one configured provider instance, such as one cluster or one AWS account and region. Its **source ID** (for example `kubernetes/local` or `aws/aws/111111111111/us-east-1`) appears on every assertion it produces.
- **Plugin**: a Go package under `plugins/` that implements `discovery.Plugin`: a `Descriptor()` and a `Run(ctx, Runtime)` loop. A plugin has a stable plugin ID such as `kubernetes` or `istio`.
- **Source plugin**: a plugin that owns a provider connection and publishes collections. `kubernetes` and `aws` are source plugins.
- **Semantic plugin**: a plugin that subscribes to another plugin's collections instead of opening its own provider connection. `istio`, `cilium`, and `agentgateway` are semantic plugins that read Kubernetes collections.
- **Provider adapter**: the I/O part of a source plugin: clients, list/watch or polling, retries, and cache sync. It is not a separate plugin.
- **Optional capability**: an extra Go interface a plugin may implement. The current ones are `discovery.TelemetryMappingProvider` (telemetry mapping), `discovery.RemediationProvider` (remediation actions), `discovery.IdentityReferenceResolver` (resolving provider references such as a Node `providerID`), and `kubernetes.ResourceRequirementsProvider` (asking the Kubernetes plugin to watch extra resource types).

## Observation delivery

- **Collection**: a named, replayable stream of current provider objects, such as `kubernetes/resources/core/v1/pods`. One plugin publishes it; any number may subscribe. A collection name controls delivery only. It is not part of graph identity.
- **Change**: one item in a collection: `upsert`, `delete`, or `sync`. Each change has a stable event ID.
- **Sync marker**: the `sync` change that tells subscribers the replay is complete and the cache is coherent.
- **Collection readiness**: the state set by `MarkReady` when a collection's cache is coherent. It is separate from contribution publication and source health.
- **Coverage**: which provider APIs a source could actually observe. Values are `covered`, `unsupported`, `degraded`, and `failed`. Missing coverage never proves that something does not exist.
- **Native event**: a provider observation delivered through a collection. PostgreSQL stores its identity, provenance metadata, and content digest as an evidence receipt, but not its provider payload.

## Graph

- **Projector**: a pure, deterministic function that turns current provider objects into a `graph.Input`. Projectors do no I/O.
- **Identity scheme**: a registered `(group, version, kind)` that defines how an identity key is normalized, for example `kubernetes.io/v1, Kind=Object`.
- **Identity claim**: `(scheme, authority ID, immutable key)`. The graph compiler turns a claim into a deterministic resource UUID.
- **Assertion**: one claim a plugin makes about the graph. There are four types: resource, relationship, facet, and telemetry. Every assertion carries plugin ID, source ID, rule ID, and evidence IDs.
- **Resource**: a graph node, such as a Pod, Service, or Security Group.
- **Relationship**: a directed edge `(subject, predicate, object)`.
- **Predicate**: a relationship type registered in `pkg/graph`, such as `exposes` or `governed-by`.
- **Facet**: a named aspect a plugin attaches to a resource, such as `istio-mtls` on a workload.
- **Security semantics**: the provider-neutral `graph.SecuritySemantics` value attached to a facet or relationship to describe its security meaning. See [security semantics](security-semantics.md).
- **Rule ID**: the immutable ID of the projector logic that produced an assertion, such as `kubernetes.service.selector`. A change in meaning gets a new rule ID.
- **Evidence ID**: a durable reference to the receipt for an observation that supports an assertion, such as a native event ID or a telemetry event ID.
- **Network destination**: a provider-neutral resource for an address or DNS name (`agentshield.io/v1, Kind=NetworkDestination`).
- **Network peer class**: a provider-neutral resource that stands for a class of unknown addresses, such as private or external (`agentshield.io/v1, Kind=NetworkPeerClass`).
- **Process class**: a provider-neutral resource that stands for a category of process a workload started, such as `shell` (`agentshield.io/v1, Kind=ProcessClass`).
- **Unresolved relationship**: a relationship whose subject or object resource is not in the graph yet. It resolves when the resource appears.
- **Conflict**: two active assertions that give one identity different resource kinds.

## Publication and storage

- **Contribution**: the complete current output of one `(plugin ID, source ID, contribution name)` tuple, for example `(kubernetes, kubernetes/local, inventory)`.
- **Replacement**: publishing a new complete contribution. Anything omitted from it is retracted.
- **Generation**: a per-contribution counter that must increase with each replacement and survives restarts.
- **Contribution version**: the immutable record of one published generation, including readiness, source health, and observation time.
- **Contribution head**: the pointer to a contribution's active version.
- **Retirement**: publishing an empty final version when a source is removed on purpose.
- **Graph compiler**: `pkg/graph`. It validates assertions, resolves references, removes duplicates, and sorts the result so the same input always produces the same graph and SHA-256 digest.
- **Current projections**: relational tables (`current_resources`, `current_relationships`, `current_facets`, and others) that serve indexed reads of the current graph.
- **Manifest**: an immutable list of the active contribution versions at one moment.
- **Analysis-view token**: a manifest ID plus an evaluation time. Together they identify the exact graph a reasoning result used.

## Telemetry

- **Telemetry mapper**: plugin code that recognizes a provider log format (through `Match`) and converts it into normalized `telemetry.Event` values (through `Map`).
- **Raw sink**: the durable store for normalized events: a local JSONL file or ClickHouse.
- **Rollup**: a per-minute summary of events with the same endpoints, kind, operation, outcome, and coverage. Rollups enter the graph as telemetry assertions.
- **Lease relationship**: the relationship the rollup keeps for each observed endpoint pair: `communicates-with` for network kinds, `executes` for process executions. It is created on first observation, refreshed near expiry, and retracted when observations stop for the retention period.

## Detection, reasoning, and remediation

- **Change feed**: the `graph_change_outbox` table. Each row is one `ContributionChangeEvent` with a global sequence number.
- **Checkpoint**: a coherent current graph plus the change-feed sequence it includes (`ReadGraphCheckpoint`).
- **Reasoning cursor**: the last change-feed sequence the detection service has processed, stored in `reasoning_cursors`.
- **Detection**: the deterministic stage that turns each change window into signals. It never calls a model.
- **Signal**: a detector output with a risk, reasons, and anchor resources. Every signal is recorded in `detection_signals` with what happened to it.
- **Ruleset**: a versioned set of CEL detection rules. Exactly one ruleset is active.
- **Deployment rule**: a model-drafted CEL rule scoped to one Deployment. It runs in **shadow** mode (recorded only) until an operator approves it, then in **active** mode.
- **Rule finding**: a finding created directly from an active rule's match, with no model call (`origin: detection_rule`).
- **Agentic investigation**: the model-calling stage that investigates built-in novelty signals from a durable, sampled queue (`investigation_jobs`).
- **Packet**: the compact JSON request agentic investigation sends to the model for one queued investigation.
- **Finding**: a validated, evidence-linked result stored in PostgreSQL and served at `/api/v1/findings`. Its origin is `agentic_investigation` or `detection_rule`.
- **Remediation outcome**: a provider-neutral desired result, such as `network.declare-ingress-isolation`. Reasoning suggests outcomes; it never picks a provider.
- **Proposal**: a remediation suggestion bound to a finding and one target resource.
- **Action**: a provider-specific way to achieve an outcome, such as the Kubernetes `network-policy/v1` action.
- **Plan, preparation, execution, verification**: the four remediation stages. Only execution writes to the provider, and only after user approval.
