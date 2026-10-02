# Testing

How to run each test suite, what it needs, and when to run it. Start with the narrowest test that covers your change, then widen.

| Change | Run |
| --- | --- |
| Any Go change | `go test -race ./path/to/package`, then `make test` |
| Graph, discovery, or plugin code | The plugin's tests plus `./pkg/discovery ./pkg/graph ./pkg/state` |
| Storage, migrations, API | `make test-postgres` |
| Kubernetes or Istio projectors | `make eval-check`, then `make eval-run` (a maintainer runs this; see [Evaluation suite](#evaluation-suite)) |
| AWS plugin | `make test-aws-e2e` |
| Web UI | `make ui-lint`, `make ui-test`, `make ui` |
| Before every pull request | `make lint` and `make test` |

## Go unit tests

```bash
gofmt -w ./path/to/changed/package
go test -race ./path/to/changed/package
make test          # go test ./...
make lint          # golangci-lint run ./...  (make lint-fix applies fixes)
```

Requirements: Go 1.27 (see `go.mod`) and [golangci-lint](https://golangci-lint.run) v2 for `make lint`. Unit tests need no database, cluster, or Node toolchain; PostgreSQL-backed tests skip themselves when `AGENTSHIELD_TEST_DATABASE_URL` is not set.

CI runs `go test -race ./...` and golangci-lint on every pull request.

Projector tests should compile their output with the real graph compiler and compare graph digests for shuffled input. See [Plugins: Testing](../plugins/README.md#testing).

## PostgreSQL integration tests

```bash
make test-postgres
```

This runs `scripts/test-postgres.sh`, which needs Docker. It starts a throwaway `postgres:16-alpine` container on a random loopback port, runs `go test -race -count=1 ./pkg/state ./pkg/api` against it, and removes the container when done.

To use a database you already have:

```bash
export AGENTSHIELD_TEST_DATABASE_URL='postgres://user:pass@127.0.0.1:5432/agentshield_test?sslmode=disable'
go test -race -count=1 ./pkg/state ./pkg/api
```

**The tests truncate every table in that database.** Use an empty database created for testing.

## Web UI

The UI is a Vite and React app in `ui/`. Requirements: Node.js 24 (`ui/.nvmrc`) and pnpm. Every UI target runs `pnpm install --frozen-lockfile` first.

```bash
make ui-lint        # TypeScript and Biome checks
make ui-test        # every Storybook story and its interaction test in headless Chromium
make ui             # production build into ui/dist (embedded by go build)
```

The first `make ui-test` downloads Chromium through Playwright.

### Storybook and the fake backend

```bash
make demo           # interactive playground on http://127.0.0.1:5173
make ui-storybook   # http://127.0.0.1:6006
```

The playground and Storybook run the UI against the same fake backend, so you can work without PostgreSQL, the service, or a cluster. The fake backend is a set of [Mock Service Worker](https://mswjs.io) handlers in `ui/mocks` over an in-memory demo environment: a shop running on Kubernetes and Istio, with findings and remediations. It follows the real API's filtering, cursor paging, error messages, and event stream, including approving a remediation and the graph change that follows. `ui/stories` renders the whole app at each view, in empty, failing, slow, and reconnecting states, and renders components on their own.

Keep `ui/mocks` in step with `pkg/api` whenever a response changes.

Known quirks:

- The handlers run in a service worker. If stories show 404 errors after Storybook restarts, reload the page once.
- After upgrading `msw`, run `pnpm msw-worker` in `ui/` to refresh the committed worker script.

### Against a real service

```bash
make graph-ui       # service on 127.0.0.1:8088 without discovery (needs AGENTSHIELD_DATABASE_URL)
make ui-dev         # Vite dev server on http://localhost:5173, proxying /api to LISTEN
```

`make graph-ui` serves what is already stored. On an empty database the graph is empty; use `make run` against a cluster to fill it (see [Getting started](../getting-started.md)).

The service sends a same-origin Content-Security-Policy. Do not add inline scripts or styles, or load assets from other origins. Styles live in `ui/src/styles.css`. `ui/dist` is build output; commit only its `.gitkeep`.

## AWS end-to-end

```bash
make test-aws-e2e
```

Requirements: Docker, kind, kubectl, Go, jq, curl, and base64. The script creates a kind cluster named `agentshield-aws-e2e` (deleting an existing one with that name), runs LocalStack, PostgreSQL, and AgentShield in it, and checks:

- startup inventory of ENIs and Security Groups;
- a Security Group change delivered through EventBridge and SQS;
- ENI removal;
- a Firehose-format VPC Flow Log reaching the JSONL sink.

It deletes the cluster on exit. The events are synthetic; the test does not exercise real CloudTrail, VPC Flow Logs, or Firehose.

## Evaluation suite

The evaluation framework in `evals/` checks that AgentShield finds lateral movement in a live cluster without alerting on paired benign changes. It uses the production detection service and investigator, so model calls are real and cost money. Set `AGENTSHIELD_EVAL_DETECTOR_ONLY=1` for `make eval-up` and `make eval-run` to measure detection alone with no API key or model calls. `make eval-rules` runs the separate rule suite, which scores operator rule policies and, with a model, the rules the Deployment rule author drafts, against campaigns built for detection rules (see [rule evals](../../evals/README.md#rule-evals)). See [`evals/README.md`](../../evals/README.md) for the campaigns and scoring.

| Target | What it does |
| --- | --- |
| `make eval-up` | Creates (or reuses) the kind cluster `agentshield-evals` and installs Cilium with Hubble, MetalLB, Gateway API, Istio ambient, agentgateway, an OpenTelemetry Collector, PostgreSQL, and an in-cluster AgentShield. Does not run any evaluation. |
| `make eval-check` | Verifies the cluster, RBAC, CRDs, and that AgentShield has published a graph, then validates the campaign catalog and contracts. No model calls. |
| `make eval-run` | Runs every campaign against the cluster. Accepts `--campaigns id1,id2` when run as `evals/scripts/eval-run.sh`. |
| `make eval-rules` | Runs the rule suite: operator policies, and authored rules unless `AGENTSHIELD_EVAL_DETECTOR_ONLY=1`. Accepts `--campaigns` the same way. |
| `make eval-matrix` | Runs the configured model matrix. |
| `make eval-down` | Deletes the cluster after checking that the scripts created it. |

Requirements: Docker, kind, kubectl, helm, jq, sha256sum, Go, and `OPENAI_API_KEY` in the environment (every eval script checks for it; agentgateway uses it for model calls). The cluster uses its own kubeconfig at `evals/output/kubeconfig`, so your default kubectl context is not changed. Artifacts go to `evals/output/<timestamp>/`.

For Kubernetes or Istio projector changes, `make eval-run` must pass before merging: every campaign's observation contract passed and `summary.json` was written. A failed observation marks the run incomplete instead of counting as a model miss. Because the cluster takes about 30 minutes to set up and every run makes billed model calls, external contributors are not expected to run it; a maintainer runs it on projector pull requests.
