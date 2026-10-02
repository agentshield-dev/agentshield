# Publication and storage

This page is the reference for how contributions are published and stored in PostgreSQL: the publication transaction, generations, the current graph tables, the change feed (outbox), manifests, and schema migrations. Other pages link here instead of repeating it. The concepts (identity, assertions, what a contribution is) are in the [data model](../concepts/data-model.md).

Code: `pkg/state/versioned.go`, `pkg/state/store.go`, `pkg/state/changes.go`, and `pkg/state/migrations/`.

## The publication transaction

A plugin publishes by calling `Runtime.ReplaceContribution` with a `discovery.ContributionOutput`: the contribution name, generation, complete `graph.Input`, source observation time, readiness, and source health. The store compiles the contribution, applies it to its revision-validated in-memory union, and compiles the candidate graph before opening the write transaction. If validation or compilation fails, nothing is written.

The short PostgreSQL transaction then:

1. Resolves the stable contribution ID for `(plugin ID, source ID, name)` and checks the generation and input digest against the current head.
2. Advances the singleton graph revision with compare-and-swap. If another publisher committed first, the transaction rolls back, reloads that revision, and rebuilds its candidate.
3. Persists assertion content in batches. Rows are keyed by SHA-256, so identical assertions from different contributions or generations share one row.
4. Records an immutable contribution version, advances its head, and applies membership additions and retractions with set-based SQL.
5. Upserts or deletes only projection rows changed by the candidate graph. Unrelated `current_*` rows and unresolved-edge timestamps are left untouched.
6. Enqueues rule-authoring jobs only for changed Deployment resources and appends one change-feed event unless the [telemetry exclusion](#what-the-change-feed-excludes) applies.

Then it commits, updates the in-process materializer, and returns the candidate graph view. An idempotent retry writes nothing and returns the current committed view. Publications have bounded transaction, lock, and statement waits; a timeout rolls back the whole transaction.

Any failure rolls back the whole transaction. Readers see either the previous state or the complete new one; there are no partial publications. If a plugin's projection or publication fails, its last successful contribution stays active.

### Concurrent publishers

Contribution ownership prevents two plugins from replacing each other's membership, but it does not by itself protect a graph compiled from several contributions. The graph revision compare-and-swap provides that protection without holding a graph-wide advisory lock during compilation. Only one candidate can advance a revision; a stale publisher reloads the winning graph and retries. PostgreSQL row locks still serialize the brief revision advance and change-sequence allocation.

## Generations

Each contribution has a generation number that must increase with each replacement.

| Submitted generation | Result |
| --- | --- |
| Lower than the head | Rejected as stale. |
| Equal, same input digest | Idempotent retry. Returns the existing version and writes nothing. |
| Equal, different input digest | Rejected. One generation names exactly one content. |
| Higher | New version, even if the graph content is unchanged. |

A higher generation with unchanged content still creates a version because readiness, health, and observation time are part of the version.

Plugins call `ContributionGeneration(plugin, source)` at startup and continue from the stored maximum, so generations keep increasing across restarts.

### Status

The head status is derived from the version:

| Status | When |
| --- | --- |
| `active` | Ready and source health `healthy`. |
| `degraded` | Ready and source health `degraded`. |
| `stale` | Not ready, or any other source health. |
| `retired` | Published by `RetireContribution`. |

`degraded` and `stale` contributions keep their last membership in the graph. A plugin that loses its provider connection should republish its last good input with degraded health rather than an empty or partial one.

`RetireContribution` publishes an empty final version and retracts everything the contribution owned. Use it only when a source is removed on purpose. The runtime does not call it automatically; for example, pointing the AWS plugin at a different account creates a new source ID, and the old source must be retired separately.

## The current graph

Publication keeps one compiled graph per database revision in memory. Whole-graph consumers such as `GET /api/v1/graph`, SSE, and graph traversal read that revision-validated materialization. `Store.Latest` remains the compatibility entry point for those deliberate whole-graph reads; it does not recompile an unchanged revision.

List, detail, search, and filter endpoints query the indexed `current_*` tables directly with keyset pagination. Projection rows retain their compiled assertion provenance, so these reads do not sacrifice detail for speed.

## The change feed

`graph_change_outbox` is a transactional outbox. Each row holds one `ContributionChangeEvent` for one published contribution version:

- a global sequence number, assigned from a single-row counter, so sequences have no gaps and follow commit order;
- the contribution's plugin, source, name, generation, status, readiness, and source health;
- the non-telemetry assertions added and retracted. Each one carries an entity locator (the graph entity type and ID, and for relationships the subject, predicate, and object), so a consumer can act on a retraction without reading the retracted row.

The event is built from the membership delta already computed in step 5. Publication never compares whole graphs and never waits for a consumer.

Contribution generations cannot order events across plugins, because each contribution counts independently. Consumers use the outbox sequence instead.

### What the change feed excludes

Telemetry rollups change every batch. If they produced events, telemetry volume would set the pace of reasoning. So:

- Telemetry assertions are always removed from event payloads, including in contributions that also own inventory.
- A version whose only changes are telemetry assertions, with unchanged readiness, health, and status, gets no event. It still commits and updates the current graph.
- A version with no assertion changes but a new generation still gets an (empty) event, so consumers see the new version.
- Readiness, health, and status changes always produce an event.

The lease relationships that the telemetry rollup maintains (`communicates-with`, and `executes` for process executions) are relationship assertions, not telemetry assertions. Their creation, refresh, and expiry do produce events, so a Pod's first shell wakes detection and reasoning once. See [Telemetry](telemetry.md#leases).

### Reading the change feed

- `ReadContributionChanges(after, limit)` returns events in sequence order.
- `ReadGraphCheckpoint` returns the latest committed sequence and the current graph, read in one repeatable-read snapshot so they match. The graph may include newer telemetry rollups that had no event.
- `reasoning_cursors` stores one `(through_sequence, graph_sha256)` position per consumer ID. Writing the same position with the same digest is a no-op; moving backwards, or the same position with a different digest, fails.

How the detection service uses these is described in [Change feed and reasoning](change-feed-and-reasoning.md#consuming-the-change-feed). Today there is one consumer. Consumer groups, outbox retention, and external streaming are not implemented.

## Manifests and history

`CreateManifest` (and `GET /api/v1/manifest`) records an immutable list of the active version of every non-retired contribution, plus status counts, read in one repeatable-read transaction. The manifest ID is derived from its content, so the same set of versions reuses the same manifest. A manifest ID plus an evaluation time is an *analysis-view token*: it identifies exactly which graph a reasoning result used.

The store does not rebuild the graph for an old manifest. A manifest records which contribution versions were active for audit correlation, but historical contribution membership is not retained. Historical reconstruction requires a separately designed retention contract before it is implemented.

## Tables

| What | Tables |
| --- | --- |
| Provider observation receipts | `native_events` |
| Resource identities | `resource_identities` |
| Contributions and versions | `contributions`, `contribution_versions`, `contribution_heads` |
| Assertion content | `resource_assertions`, `facet_assertions`, `relationship_assertions`, `telemetry_assertions` |
| Active membership | `contribution_current_assertions` |
| Current graph | `current_resources`, `current_facets`, `current_relationships`, `unresolved_relationships`, `assertion_conflicts` |
| Change feed | `graph_change_outbox`, `graph_change_sequence` |
| Detection and investigation | `reasoning_cursors`, `detection_signals`, `investigation_jobs`, `findings` (with `origin` `agentic_investigation` or `detection_rule`) |
| Manifests | `graph_manifests`, `graph_manifest_contributions` |
| Detection rules | `detector_rule_revisions`, `detector_rulesets`, `detector_ruleset_members`, `detector_activations`, `detector_active_ruleset` |
| Rule authoring | `deployment_rule_jobs` (drafts and their review status) |

Assertion tables use typed columns for fields that are queried and JSONB for attributes, properties, and evidence IDs.

PostgreSQL does not store provider payloads, complete graph snapshots, or raw telemetry. Raw telemetry goes to JSONL or ClickHouse (see [Telemetry](telemetry.md)).

`native_events` stores observation identity, provenance metadata, and a content digest for evidence-ID integrity. Provider payloads, including Kubernetes objects, are not stored.

## Schema migrations

The greenfield schema is split into three SQL files in `pkg/state/migrations/`: graph publication, detection, and rule authoring. They are embedded into the binary and applied at startup in one transaction while holding a PostgreSQL advisory lock, so several processes can start at once. Each file's SHA-256 is recorded in `schema_migrations`; if an embedded file no longer matches the database, startup fails. Migration does not inherit the caller's startup deadline. It runs under its own `state.Config.MigrationTimeout`, which defaults to 30 minutes.

Rules for contributors:

- Keep each baseline file as the direct definition of its current schema. Recreate development databases after changing one; upgrades are not supported before the first release.
- Update the graph baseline constraints when you add a predicate or assertion type.
- Run `make test-postgres` for any storage change.

The database role needs DDL rights the first time the service starts. See [PostgreSQL setup](../../deploy/kubernetes/README.md#postgresql).
