# ADR 0003: Lease-based work partitioning across replicas

- Status: Proposed
- Date: 2026-11-15
- Owners: AgentShield maintainers

## Context

AgentShield currently runs one process per PostgreSQL database. Every process constructs every configured discovery plugin, holds the observation collection hub and telemetry accumulator in memory, and publishes complete contributions for the same `(plugin, source, contribution)` owners. Increasing the Helm `replicaCount` starts competing workers rather than dividing work.

The plugin contract already exposes stable plugin and source identities, but identity alone does not determine placement. Two plugins with the same `SourceID` can run independently when they do not share process-local state. Plugins that publish and consume the same in-memory collection must currently run together because collection payloads and coherent replay markers are not recoverable from PostgreSQL. Other process-local capabilities, such as identity resolvers, can impose the same constraint.

AgentShield should allow ordinary Deployment replicas to divide independent work and recover it after a replica fails. Losing up to the current 30-second unpublished telemetry interval during a process failure is accepted for this decision. Durable replay of that interval is not a prerequisite.

## Proposed decision

Run interchangeable AgentShield Deployment replicas. Each replica competes for renewable PostgreSQL leases over configured work units and runs only the units it owns.

### Work units

A work unit is the smallest configured set of plugin instances that cannot run correctly in separate processes.

Co-location is required when plugin instances:

- publish and consume the same process-local collection;
- share another process-local capability required during projection or remediation; or
- jointly own in-memory state that cannot be reconstructed independently.

Sharing a `SourceID` does not by itself require co-location. Independent plugin instances may be separate work units even when they describe the same provider source.

The initial configuration declares work units explicitly. Startup validation checks that every process-local collection publisher and consumer is assigned to the same unit and that a plugin instance belongs to exactly one unit. Automatic dependency inference and balancing are deferred until the configuration model is proven.

### Ownership and fencing

PostgreSQL stores a renewable ownership record for each work unit containing:

- work-unit ID;
- holder instance ID;
- monotonically increasing ownership epoch; and
- lease expiry.

Any replica may claim an unowned or expired unit. The process cancels a unit's plugins when renewal fails or ownership is lost. Graceful shutdown stops admission, drains accepted work under the existing deadline, stops provider watches, and releases the lease.

Every durable native-event receipt, graph contribution, and telemetry contribution from a leased unit carries its ownership epoch. The PostgreSQL transaction rejects an expired or stale epoch before committing the write. This closes the gap in which a paused or partitioned process loses its lease but has not yet observed cancellation.

Kubernetes Lease objects are not the publication fence. They can elect a worker, but PostgreSQL cannot atomically verify a Kubernetes Lease while committing a contribution. Checking the Lease before a database write leaves a time-of-check/time-of-use race, while using both lease systems creates two ownership authorities. Keeping acquisition and fencing with the published state gives one transactional authority.

### Startup and handoff

Every replica receives the same work-unit configuration and attempts to claim available units up to a configured local capacity. It must not open provider clients or watches before acquiring the corresponding lease.

After acquiring a unit, the new owner:

1. reads the highest durable contribution generation for each plugin/source;
2. obtains a coherent complete provider view;
3. publishes the next generation as an authoritative replacement under its ownership epoch; and
4. starts ordinary delta publication and telemetry projection.

Existing complete-replacement semantics repair missed provider changes during handoff. The previous owner's assertions remain active but stale until the replacement commits; lease acquisition alone does not retract healthy state.

The telemetry accumulator restores only series, relationship leases, and peer classes belonging to its owned work units. It rejects events outside those units and cannot publish or retract another unit's rollup contribution. Losing up to 30 seconds of unflushed accumulator state during handoff is accepted.

### Replica responsibilities

This decision partitions provider discovery and its dependent projection work.

- Read-only PostgreSQL-backed APIs may run on every replica.
- Resource rule authoring may run on every replica because its jobs already use renewable PostgreSQL leases.
- Detection and investigation require their own leased worker identities instead of relying on a shared default consumer ID.
- Prepared remediation must execute on a replica that hosts its provider instance. General load-balanced remediation requires durable preparation state or owner-aware routing and is not claimed by this decision.
- Source telemetry must be routed to the replica owning the corresponding work unit or admitted through a separately partitioned telemetry path. A normal Kubernetes Service does not provide source-aware routing, so telemetry routing remains an acceptance prerequisite rather than a reason to give replicas stable ordinals.

## Consequences

### Benefits

- Provider API load, watches, caches, and projection work divide across interchangeable replicas.
- A failed replica's work can move without changing an ordinal assignment.
- Only actual process-local dependencies constrain placement.
- PostgreSQL fencing prevents a stale holder from publishing after lease transfer.
- Scaling uses the existing Deployment model and does not introduce stable Pod identity or per-ordinal Services.

### Costs and risks

- Scaling helps only when multiple independent work units exist. One large provider watch is not divided internally.
- The current single-Kubernetes-source and single-AWS-region configuration must become multi-source before those providers can scale horizontally.
- Some Kubernetes-derived plugins initially remain in one work unit because the collection hub is process-local.
- Separating those plugins later requires a durable collection transport that stores payloads and coherent replay state, not only native-event digests.
- Cross-source process-local capabilities constrain placement until they become independently reconstructible.
- Telemetry ingress still needs source-aware routing or its own partitioning design.
- The public API is not fully stateless while remediation preparation remains process-local.

## Alternatives considered

| Alternative | Reason not selected |
| --- | --- |
| Increase Deployment replicas without partitioning | Duplicates provider work and creates competing complete contribution owners. |
| StatefulSet ordinals | Stable identity does not provide publication fencing and makes work reassignment depend on Pod identity. |
| Kubernetes Leases as the ownership authority | Lease ownership cannot be checked atomically with PostgreSQL publication, leaving stale-writer races. |
| Kubernetes Leases plus PostgreSQL fencing | Creates two ownership authorities without improving on a PostgreSQL lease and fence. |
| One elected leader for all work | Improves failover but does not distribute provider or telemetry load. |
| Co-locate every plugin sharing a source | Source identity is not a runtime dependency and would unnecessarily reduce available parallelism. |
| Distribute the current collection hub | Requires durable payloads, coherent replay, and live delivery before work-unit partitioning needs them. |

## Implementation boundary

The first implementation requires:

- a multi-source configuration model with explicit work units;
- validation of process-local dependencies within each work unit;
- PostgreSQL work-unit leases and publication fencing as a new embedded migration;
- a unique instance identity for each Deployment Pod;
- plugin construction and lifecycle controlled by acquired work units;
- telemetry restoration and publication filtered by owned work units;
- independently leased detection and investigation workers; and
- status reporting for available, owned, waiting, and degraded work units.

It does not require StatefulSets, automatic balancing, HPA-specific behavior, raw-event replay, within-source parallelism, distributed collection delivery, or durable remediation preparation.

## Validation required before acceptance

1. Two replicas claim disjoint work units, open only their owned provider watches, and publish only for those units.
2. Invalid configurations that separate a process-local publisher and consumer fail startup.
3. Independent plugins sharing a `SourceID` can be assigned to different work units.
4. A stale holder cannot record or publish after another replica acquires a higher ownership epoch.
5. Graceful reassignment preserves assertions until the new owner's authoritative replacement commits.
6. A killed or partitioned replica cannot produce two accepted writers for one unit.
7. Telemetry restoration and publication cannot cross work-unit ownership.
8. Detection and investigation run once per claimed job or partition, while read-only API traffic works across replicas.
9. PostgreSQL race tests cover lease acquisition, renewal, expiry, release, and fenced publication.

The ADR remains Proposed until work-unit fencing and handoff are proven with two Deployment replicas against one PostgreSQL database and source telemetry has an owner-aware admission path.
