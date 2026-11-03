# ADR 0001: Snapshot authority and delta publication

- Status: Accepted
- Date: 2026-11-03
- Owners: AgentShield maintainers

## Context

AgentShield stores provider-neutral graph assertions, contribution ownership, current projections, and the reasoning change feed in PostgreSQL. A contribution is owned by one `(plugin, source, contribution name)` tuple.

Complete contribution replacement provides a strong recovery contract: the submitted input is the owner's whole current output, so omission retracts an assertion. It is also expensive for localized changes. Even after graph projections became delta-maintained, replacing one assertion in a large contribution still required compiling, content-addressing, staging, and comparing the entire contribution.

Explicit assertion deltas avoid that work, but deltas alone are not a recovery authority. A publisher that misses an event, loses its provider cursor, or restarts without its previous membership cannot safely infer all required retractions. PostgreSQL has no durable provider event stream from which to reconstruct them.

AgentShield currently runs as one PostgreSQL-backed deployment. Adding Kafka and Flink now would provide durable replay, but would also add partition ownership, ordering, retention, schema evolution, poison-event handling, and replay operations before distributed processing requires them.

## Decision

AgentShield will use two publication operations for the same contribution owner.

1. Explicit delta publication is the ordinary update path. A publisher supplies its expected base generation, the next generation, assertions to add, and assertions to retract.
2. Selective complete replacement is the authoritative checkpoint and recovery path. A publisher supplies its complete current assertion set. PostgreSQL calculates membership additions and retractions, persists only newly referenced content, and updates only the affected graph projection.

The complete replacement defines truth. A delta is an efficient transition between accepted complete states; it is not the replay authority.

PostgreSQL remains the source of truth, using ordinary Go types and parameterized SQL. This decision does not introduce a graph database or a specialized graph query language.

### Ordering and integrity without a graph-wide digest

Publication does not compute or store a graph-wide SHA. A whole-graph digest makes every localized update proportional to graph size and duplicates contracts already represented by narrower durable values:

- the graph revision identifies committed current state;
- the contribution generation and submitted-content digest provide stale-write and idempotent-retry checks for one owner;
- content addresses deduplicate and identify individual assertions;
- the change-feed sequence orders committed changes across contribution owners;
- manifests pin contribution versions when a reproducible analysis selection is required.

These values serve different purposes and remain independently maintainable. None requires reading or hashing the complete graph during publication.

### Delta transaction

One PostgreSQL transaction must:

1. Lock and verify the contribution head and graph revision.
2. Reject a stale base generation, a conflicting same-generation retry, an unowned retraction, overlapping additions and retractions, or invalid provenance.
3. Validate immutable identity claims and persist newly referenced assertion content.
4. Apply active-membership additions and retractions.
5. Reconcile only the affected projection closure.
6. Record the immutable contribution version and advance its head.
7. Append the change-feed event and advance the graph revision.

Commit makes all effects visible together. Rollback makes none visible. A same-generation retry with identical content is a no-op.

Small deltas may use ordinary parameterized statements. Larger deltas must use temporary tables and `COPY` so SQL round trips do not grow per assertion.

### Authoritative replacement

A complete replacement must:

- stage the incoming assertion and identity manifests in PostgreSQL;
- validate immutable identity claims in bulk;
- compute additions and retractions against current membership;
- persist only new assertion content and identities;
- preserve omission-means-retraction semantics;
- reconcile only the affected projection closure;
- atomically update the contribution version, head, change feed, and graph revision.

Publishers must produce a complete replacement:

- after process or plugin restart, before resuming delta publication;
- after a provider relist, watch-cursor loss, or another event-gap indication;
- after PostgreSQL rejects a stale delta base;
- when the publisher detects local membership drift;
- periodically, using a bounded time or accepted-delta count.

The implementation must choose and expose the periodic bound. This ADR does not prescribe its default. Checkpoints should be staggered across contributions so they do not synchronize into a database spike.

At startup, a plugin reads its durable generation, obtains a coherent complete provider view, and publishes the next generation as a replacement. It must not infer retractions from an empty in-memory cache. It may publish deltas only after that replacement commits.

## Performance evidence

The experiments changed one resource assertion in an already populated contribution. Each normal range contains fixed one-operation samples against disposable PostgreSQL 16. The projection checkpoint was the delta-maintained projection implementation before publication ingestion was optimized.

| Contribution size | Projection checkpoint | Selective replacement | Explicit delta |
| ---: | ---: | ---: | ---: |
| 10,000 assertions | 0.79-0.89 s | 0.216-0.225 s | 36-65 ms |
| 50,000 assertions | 3.90-4.18 s | 0.908-0.911 s | 51-86 ms |
| 100,000 assertions | 8.25-8.57 s | 2.11-2.14 s | 48-117 ms |

Approximate allocations for the same operation were:

| Contribution size | Projection checkpoint | Selective replacement | Explicit delta |
| ---: | ---: | ---: | ---: |
| 10,000 assertions | 123 MB | 76-87 MB | 0.17-0.23 MB |
| 50,000 assertions | 609 MB | about 359 MB | 0.16-0.22 MB |
| 100,000 assertions | 1.24 GB | 717-845 MB | about 0.16 MB |

The host also produced isolated 23-second and 90-second PostgreSQL stalls during selective-replacement runs. Those samples are excluded from the normal ranges rather than hidden in an average. The allocation curve and remaining samples still show the architectural distinction: selective replacement is faster but linear in contribution size, while explicit delta publication is effectively independent of total graph size for a localized change.

These measurements support the publication contract. They are not service-level objectives. Production limits require representative provider payloads, concurrent publishers, and sustained-load measurements.

## Consequences

### Benefits

- Localized healthy-state updates scale with the changed assertion set rather than the complete contribution.
- Complete replacements provide deterministic repair without retaining every provider event.
- PostgreSQL transactions continue to protect ownership, provenance, projection coherence, and change-feed ordering.
- The system remains portable and does not require another storage engine or query language.
- Selective replacement also makes periodic checkpoints materially cheaper than the original full persistence path.

### Costs and risks

- The plugin runtime must track the accepted base generation and cannot emit deltas before its initial replacement.
- A retraction needs a stable representation that identifies exactly the assertion being removed.
- Restart, stale-base, cursor-loss, drift, and periodic-checkpoint paths become part of the correctness contract and need integration tests.
- Complete checkpoints remain linear in contribution size and can create load spikes if synchronized.
- Delta APIs and storage paths add another publication mode whose behavior must remain equivalent to complete replacement.

## Operational signals

The implementation should expose bounded-cardinality metrics for:

- delta and replacement publication latency;
- assertions added and retracted per publication;
- stale-base rejections;
- checkpoint reason: startup, periodic, provider relist, cursor loss, or drift;
- time and accepted-delta count since the last complete replacement;
- replacement input size and affected projection size.

Metrics must not use contribution names, resource IDs, assertion IDs, or provider object names as labels.

## Deferred distributed recovery

Kafka or another durable log, with Flink or an equivalent stateful processor, becomes appropriate when AgentShield needs multiple publication processes, durable replay independent of provider relists, partitioned processing, or long-lived event-time computation.

At that point the durable stream can become the recovery authority and PostgreSQL projections can be rebuilt from checkpoints plus replay. That operating model requires a separate decision covering partition ownership, ordering, retention, schema evolution, poison-event handling, and replay observability.

## Alternatives considered

| Alternative | Reason not selected |
| --- | --- |
| Complete replacement for every update | Correct and simple, but compilation, hashing, and manifest staging remain linear in contribution size. |
| Explicit deltas without complete checkpoints | Fast, but a missed delta or lost publisher cursor can leave membership divergent with no local repair authority. |
| One contribution per provider object | Localizes replacement but greatly increases contribution heads, versions, graph revisions, and outbox transactions. |
| Kafka and Flink now | Provides durable replay but adds distributed operational and schema contracts before they are required. |
| Graph database or specialized graph query language | The required set difference, ownership, projection, and transaction semantics fit PostgreSQL and normal SQL. |

## Implementation boundary

The storage experiments establish feasibility but are not the final public API. Runtime adoption still requires:

- a stable representation for retraction handles;
- contribution retirement semantics;
- bulk handling for large deltas;
- restart, stale-base, cursor-loss, drift, and periodic-checkpoint tests;
- plugin-runtime integration that cannot publish deltas before its initial complete replacement.
