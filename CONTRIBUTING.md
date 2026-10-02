# Contributing to AgentShield

## Development setup

- Go 1.27 or later (see `go.mod`)
- [golangci-lint](https://golangci-lint.run) v2 for `make lint`
- Docker for PostgreSQL and integration tests
- Node.js 24 and [pnpm](https://pnpm.io) for UI work
- kind and kubectl for local clusters and end-to-end tests

Follow [Getting started](docs/getting-started.md) to run the service locally.

## Design docs

Read the docs for the area you are changing:

- [Data model](docs/concepts/data-model.md) for identity, assertions, and provenance.
- [Plugin contract](docs/plugins/README.md) for discovery, contribution replacement, and plugin tests.
- [Publication and storage](docs/architecture/publication-and-storage.md) for generations, persistence, and migrations.
- [Telemetry](docs/architecture/telemetry.md) for ingestion, rollups, and backpressure.

The [docs index](docs/README.md) links to the remaining design docs.

## Testing

Run `go test -race ./path/to/package` for the packages you changed, then `make test` and `make lint`. [Testing](docs/development/testing.md) lists the integration, UI, and evaluation suites and when to use them.

Database tests truncate their target. Use a disposable database, never one whose data you need.

Changes to Kubernetes or Istio plugin projection need a cluster evaluation before merging. A maintainer can run it; the setup and billed model calls are described in [Testing](docs/development/testing.md#evaluation-suite).

## Pull requests

- Discuss large changes or new plugins in an issue before implementing them.
- Keep changes focused and add tests for changed behavior.
- Update the docs that describe any behavior or configuration you change.
- Add migrations as new files in `pkg/state/migrations/`; do not edit applied migrations.
- Leave credentials, runtime data, and generated UI files out of commits. Only `ui/dist/.gitkeep` is tracked under `ui/dist`.
- Describe how you tested the change in the pull request.

Report vulnerabilities privately as described in [Security policy](SECURITY.md),
not in a public issue or pull request.

Contributions are licensed under [Apache License 2.0](LICENSE). DCO sign-off is not required.
