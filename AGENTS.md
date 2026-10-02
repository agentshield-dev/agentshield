# AgentShield contributor instructions

## Scope

These instructions apply to the entire repository. More specific `AGENTS.md` files may refine them for a subtree.

AgentShield turns provider observations into a deterministic, provider-neutral graph. Every change must preserve stable identity, assertion provenance, independent plugin ownership, replacement semantics, and limited telemetry cardinality. The [glossary](docs/concepts/glossary.md) defines the terms used below.

## Start here

- Graph or publication behavior: read [docs/concepts/data-model.md](docs/concepts/data-model.md) and [docs/architecture/publication-and-storage.md](docs/architecture/publication-and-storage.md).
- Discovery plugin, provider adapter, collection, projector, or telemetry mapper: read the [plugin contract](docs/plugins/README.md) and the [style guide](docs/plugins/style-guide.md). The [create-discovery-plugin skill](.github/skills/create-discovery-plugin/SKILL.md) is the step-by-step checklist.
- Security semantics on facets or relationships: read [docs/concepts/security-semantics.md](docs/concepts/security-semantics.md).
- Telemetry ingestion, storage, rollups, or backpressure: read [docs/architecture/telemetry.md](docs/architecture/telemetry.md).
- PostgreSQL storage or migrations: read [docs/architecture/publication-and-storage.md](docs/architecture/publication-and-storage.md).
- Reasoning, detectors, or remediation: read [docs/architecture/change-feed-and-reasoning.md](docs/architecture/change-feed-and-reasoning.md), [docs/architecture/detection-rules.md](docs/architecture/detection-rules.md), and [docs/architecture/remediation.md](docs/architecture/remediation.md).
- Use nearby tests and established package patterns as the primary implementation guide.

## Graph and plugin invariants

[docs/plugins/README.md](docs/plugins/README.md) is the full plugin contract. The hard rules:

- Identity keys are authority-qualified and immutable; names, labels, and IPs are attributes.
- Use only predicates registered in `pkg/graph`; a new one needs a migration for the database constraint.
- Every assertion carries plugin ID, source ID, rule ID, and evidence IDs.
- Projectors are pure and deterministic: no I/O, and shuffled input gives the same graph digest.
- A contribution is the whole current output of `(plugin, source, contribution name)`; omission retracts.
- Generations only go up, across restarts; a same-generation retry with the same content is a no-op.
- Readiness, contribution publication, source health, and coverage are separate states.
- Reference other plugins' resources by stable identity; never depend on another plugin's publication order.
- Reuse a provider watch through a shared collection; never open a duplicate one.
- Attach security semantics to every security-relevant fact, or document why it stays provider-native.

## Telemetry

- Keep high-volume raw events in the telemetry pipeline and raw sink, not in native discovery events or graph membership.
- Require stable event IDs across retries and preserve the original observation timestamp.
- Put only per-minute rollups with authority-qualified endpoints into the graph. Unresolved endpoints wait in the rollup's retry path.
- Store a provider stream cursor separately from the contribution generation.
- Write to the raw sink before projecting, and apply explicit backpressure. Do not silently drop or project uncommitted telemetry.
- Treat telemetry properties and evidence as sensitive. Do not log credentials, tokens, secrets, or raw authorization material.

## Storage and API safety

- Add schema changes as new embedded migrations; never edit an applied migration (startup verifies checksums).
- Preserve atomic contribution publication and a coherent current graph.
- Use structured JSON and SQL APIs instead of ad hoc serialization.
- The HTTP API is unauthenticated. Keep loopback binding as the default and document any exposure behind authenticated infrastructure. See [docs/operations/security-model.md](docs/operations/security-model.md).
- Never run state tests against a database whose data must be kept; integration tests truncate it.

## Validation

Run the narrowest relevant test first, then broaden:

```bash
gofmt -w ./path/to/changed/package
go test -race ./path/to/changed/package
go test ./...
```

[docs/development/testing.md](docs/development/testing.md) lists which suite each kind of change needs. In short:

- Discovery, graph, or state changes: the affected plugin plus `./pkg/discovery`, `./pkg/graph`, and `./pkg/state`.
- Persistence changes: `make test-postgres`.
- Kubernetes or Istio projector changes: `make eval-run` against the disposable eval cluster, verifying every campaign observation contract and the aggregate summary. `make eval-check` validates the cluster and contracts without model calls.
- Web UI changes under `ui/`: `make ui-lint`, `make ui-test`, and `make ui`, then check the affected views against a running service. Keep the Storybook fake backend in `ui/mocks` in step with `pkg/api` responses. The service sends a same-origin Content-Security-Policy, so do not add inline scripts or styles or load assets from other origins. Style the UI in `ui/src/styles.css`, which carries the product's established look, and change it only on request. `ui/dist` is build output; commit only its `.gitkeep`.

## Change discipline

- Keep changes focused; do not reformat or repair unrelated code.
- When contracts, identity, predicates, evidence, failure behavior, scale assumptions, or operational requirements change, update the documentation page that owns the topic ([docs/README.md](docs/README.md) maps topics to pages). Link to it from elsewhere instead of repeating it.
- The pipeline diagram lives only in [docs/concepts/overview.md](docs/concepts/overview.md#pipeline). Other pages, including the README, link to it instead of drawing their own.
- Do not commit generated runtime data from `.agentshield/` or credentials, kubeconfigs, database URLs, and telemetry payloads containing secrets.
