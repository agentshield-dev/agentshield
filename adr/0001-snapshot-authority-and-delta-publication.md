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

The runtime checkpoints after 1,000 accepted deltas or 15 minutes, whichever is observed first on the contribution's next publication. Both bounds are operator-configurable. The first periodic deadline after startup is deterministically distributed across the final eighth of the configured interval by contribution owner; later periodic deadlines use the complete interval. The configured interval remains a hard maximum.

At startup, a plugin reads its durable generation, obtains a coherent complete provider view, and publishes the next generation as a replacement. It must not infer retractions from an empty in-memory cache. It may publish deltas only after that replacement commits.

## Performance evidence

The experiments changed one resource assertion in an already populated contribution. Each normal range contains fixed one-operation samples against disposable PostgreSQL 16. The projection checkpoint was the delta-maintained projection implementation before publication ingestion was optimized.

| Contribution size | Projection checkpoint | Selective replacement | Explicit delta |
| ---: | ---: | ---: | ---: |
| 10,000 assertions | 0.79-0.89 s | 0.244-0.262 s | 56-66 ms |
| 50,000 assertions | 3.90-4.18 s | 1.04-1.11 s | 63-94 ms |
| 100,000 assertions | 8.25-8.57 s | 2.29-2.32 s | 157-185 ms |

Approximate allocations for the same operation were:

| Contribution size | Projection checkpoint | Selective replacement | Explicit delta |
| ---: | ---: | ---: | ---: |
| 10,000 assertions | 123 MB | 76-87 MB | 0.23-0.30 MB |
| 50,000 assertions | 609 MB | about 424 MB | 0.16-0.24 MB |
| 100,000 assertions | 1.24 GB | 717-845 MB | about 0.24 MB |

The host also produced isolated 23-second, 90-second, and 118-second PostgreSQL stalls during selective-replacement runs. Those samples are excluded from the normal ranges rather than hidden in an average. A noisy mixed 100,000-assertion delta run ranged from 106 to 394 ms; the table uses a fresh isolated run. The allocation curve shows the architectural distinction: selective replacement is faster but linear in contribution size, while explicit delta publication removes whole-contribution allocation and grows much more slowly with indexed table size for a localized change.

The stall investigation repeated the 100,000-assertion replacement against PostgreSQL 16 with its data directory on tmpfs. Three samples completed in 2.25-2.62 seconds without a tail event, compared with a 93.77-second outlier on shared container storage. `EXPLAIN (ANALYZE, BUFFERS, WAL)` measured the membership replacement at 276 milliseconds and the initial 100,000-resource projection insert at 2.51 seconds, including 1.27 seconds across 100,000 foreign-key trigger calls and 62.6 MB of WAL. The membership plan remained sensitive to statistics and memory: after `ANALYZE`, 4 MB `work_mem` selected a 17.6 MB external merge sort and took 965 milliseconds, while a transaction-local 64 MB setting selected an in-memory hash plan and took 285 milliseconds.

The evidence attributes the extreme tail to shared host storage contention amplifying a write-heavy checkpoint, not to Kind or a PostgreSQL lock wait. Complete checkpoints still have substantial linear CPU, allocation, statement, foreign-key, and WAL costs. The follow-up experiments therefore evaluated bulk persistence, indexed membership comparison, and transaction-local memory tuning independently.

Sequential checkpoint optimization produced:

| Initial publication | 10,000 assertions | 50,000 assertions | 100,000 assertions |
| --- | ---: | ---: | ---: |
| Selective persistence baseline | 3.31 s | 15.03 s | 28.68 s |
| Bulk identity and assertion persistence | 3.26 s | 14.58 s | 25.69 s |
| Indexed membership anti-joins | 1.12-1.20 s | 5.88-5.93 s | 11.95-12.25 s |

The anti-join path also reduced localized replacement to 133-161 milliseconds at 10,000 assertions, 620-683 milliseconds at 50,000, and 1.34-1.50 seconds at 100,000. A transaction-local 16 MB `work_mem` setting did not improve the anti-join plan and produced worse initial-publication tail samples, so PostgreSQL defaults remain in use. Bulk persistence and indexed anti-joins retain all identity collision and foreign-key checks.

A final integrated fixed-operation sample measured localized replacement at 140 milliseconds, 647 milliseconds, and 1.35 seconds, and explicit delta publication at 31 milliseconds, 54 milliseconds, and 90 milliseconds for 10,000, 50,000, and 100,000 assertions respectively. Initial publication measured 1.15 seconds and 6.04 seconds at 10,000 and 50,000, while the 100,000 sample hit another shared-host tail at 33.88 seconds. The repeated three-sample 100,000 range remains the representative result; the tail reinforces the storage-contention finding rather than changing the checkpoint design.

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
- Restart, stale-base, cursor-loss, drift, and periodic-checkpoint paths are part of the correctness contract and require PostgreSQL-backed integration coverage.
- Complete checkpoints remain linear in contribution size and can create load spikes if synchronized.
- Delta APIs and storage paths add another publication mode whose behavior must remain equivalent to complete replacement.

## Operational signals

Complete checkpoints emit one debug-level completion event with fixed success and applied fields plus phase durations for compilation, local publication queueing, transaction setup, preparation, membership, persistence, projection, commit, and total time. Database and transaction failures emit the same event with the completed phases; compile and validation failures use their direct error paths. The event has no contribution, resource, assertion, or provider-object dimensions. A future metrics backend should expose bounded-cardinality counters and histograms for:

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

The runtime accepts complete projector output, derives its assertion delta in memory, and sends that delta to PostgreSQL. It forces the first publication of each plugin run to be a complete replacement and periodically checkpoints accepted deltas. PostgreSQL applies small and large deltas with the same set-based transaction contract. Contribution retirement continues to use an authoritative empty replacement.

This immediately removes full-contribution database work and centralizes checkpoint recovery, but projector execution and the in-memory diff remain linear in contribution size. Direct object-level projector deltas require a stable retraction-handle API and plugin-specific incremental projection work. They can adopt the existing storage contract without changing checkpoint or recovery semantics.
