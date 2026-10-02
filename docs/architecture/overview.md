# Architecture overview

This page maps the runtime: what runs inside the `agentshield` process, how data moves between components, and which page owns each subsystem. The end-to-end pipeline diagram is in [What AgentShield does](../concepts/overview.md#pipeline). Terms are defined in the [glossary](../concepts/glossary.md).

## One process, one database

`cmd/agentshield` is a single binary. It needs PostgreSQL and, optionally, ClickHouse and a model endpoint. At startup it:

1. Registers the identity schemes declared by the compiled-in plugin descriptors. Today only Kubernetes and AWS declare schemes; Istio, agentgateway, Cilium, and Falco reuse the Kubernetes scheme. Schemes are registered even for plugins that are not enabled, so contributions stored by earlier runs still compile.
2. Opens PostgreSQL and applies any pending migrations, within 5 minutes (see [Publication and storage](publication-and-storage.md#schema-migrations)). The remaining startup steps that call external services share a 30-second budget.
3. Builds the discovery plugins:
   - `aws`, if `--aws-region` is set.
   - `kubernetes`, `istio`, `agentgateway`, `cilium`, and `falco`, unless `--kubernetes-disable` is set.
   - None, if `--disable-discovery` is set. The process then only serves what is already stored.
4. Opens the raw telemetry sink (JSONL by default, ClickHouse with `--clickhouse-url`) and restores telemetry rollups from the current graph.
5. Builds the HTTP API. Live remediation is enabled only when discovery is running and `--listen` is a loopback address.
6. If `--agentic-investigation` or `--deployment-rule-authoring` is set, loads detection rules and starts the detection service, plus the investigation worker and the Deployment rule-authoring worker for whichever features are enabled.

Then it runs these loops concurrently until it receives SIGINT or SIGTERM. If any loop fails, the process shuts down.

```mermaid
flowchart TB
    subgraph process["agentshield process"]
        MGR["Discovery manager<br/>(one goroutine per plugin)"]
        HUB["Collection hub<br/>(in memory)"]
        TP["Telemetry pipeline<br/>(queue, batches, rollup)"]
        HTTP["HTTP server<br/>API, OTLP, plugin receivers, UI"]
        RS["Detection service"]
        IW["Investigation worker"]
        DR["Detector rule reloader"]
        DA["Deployment rule author"]
    end
    PG[("PostgreSQL")]
    SINK[("JSONL or ClickHouse")]
    MODEL["Model endpoint"]

    MGR <--> HUB
    MGR -->|"event receipts, contributions"| PG
    HTTP -->|"OTLP logs, Firehose records"| TP
    TP --> SINK
    TP -->|"rollup contributions"| PG
    HTTP -->|"reads, approvals"| PG
    RS -->|"change feed, signals, rule findings, cursor"| PG
    RS -->|"investigation jobs"| PG
    IW -->|"jobs, findings"| PG
    IW <--> MODEL
    DR -->|"active ruleset, Deployment rules"| PG
    DA -->|"jobs, drafts"| PG
    DA <--> MODEL
```

The detection service and detector reloader run when `--agentic-investigation` or `--deployment-rule-authoring` is set; the investigation worker and the rule author run only for their own flag. The detection service never calls a model. `--model-provider=anthropic` applies only to the rule author (see [Change feed and reasoning](change-feed-and-reasoning.md#detection-and-investigation)).

## How data moves

1. **Discovery.** Each plugin runs in its own goroutine under `discovery.Manager`. Source plugins publish provider objects as changes to named collections through the `Runtime`. `Runtime.Publish` stores identity, provenance metadata, and a content digest as a durable receipt, then fans the provider payload out through the in-memory collection hub. Semantic plugins subscribe to those collections. Every plugin runs its projector and calls `ReplaceContribution` with its complete output. See [Plugins](../plugins/README.md).
2. **Publication.** `ReplaceContribution` validates and stores the contribution, updates the current graph tables, and appends a change-feed row, all in one transaction. See [Publication and storage](publication-and-storage.md).
3. **Telemetry.** The OTLP receiver (`POST /v1/logs`) and plugin-registered native receivers turn records into normalized events. The pipeline writes each batch to the raw sink, then updates per-minute rollups and publishes them under provider ownership. Events without a provider mapping are discarded instead of receiving a synthetic host owner. See [Telemetry](telemetry.md).
4. **Detection and investigation.** The detection service polls the change feed, builds the graph before and after each change window, and runs detectors. Active rule matches become findings directly; eligible novelty signals are queued for the investigation worker, which samples them, asks the model to investigate, and records validated results as findings. See [Change feed and reasoning](change-feed-and-reasoning.md) and [Detection rules](detection-rules.md).
5. **Remediation.** A user picks a suggested remediation in the UI, prepares it (plan and dry-run), and approves it. Only then does the selected plugin write to the provider. See [Remediation](remediation.md).

Some things never flow backwards. Findings and remediation state are never published as graph contributions or collection changes, so reasoning cannot trigger itself, and there is no command channel from the graph to discovery.

## Plugin wiring

`cmd/agentshield/main.go` wires plugins explicitly; there is no dynamic plugin loading. The Kubernetes plugin is built last because it needs the resource requirements of collection consumers: it collects every `ResourceRequirement` from `istio`, `agentgateway`, and `cilium` (`falco` needs none; it only maps telemetry), and opens one shared informer per unique resource type. The informer client has no request timeout, because client-go applies it to watch streams too; API discovery and remediation actions use a separate client with a 30-second timeout. Both allow 50 requests per second with a burst of 100. Each plugin owns its own prefixed flags, including a `--<plugin>-cluster-id`; use matching authority values when their assertions need to refer to the same Kubernetes objects. Flag registration enforces the plugin prefix and rejects duplicate names.

The manager checks that each `(plugin, source)` pair is registered once, that each collection has one publisher per source, and that every consumed collection has a publisher on the same source. It starts all plugins concurrently, in a deterministic order, and scopes each plugin's runtime to its source ID so two instances cannot read or overwrite each other's collections. A plugin instance that fails or panics is restarted on its own with backoff while the others keep running; see [Errors](../plugins/README.md#errors).

## HTTP surface

The API and OTLP route are served by `pkg/api` on `--listen` (default `127.0.0.1:8088`). Plugins register their own native telemetry routes with the host; AWS supplies the Firehose route.

| Route | Purpose |
| --- | --- |
| `GET /healthz` | Liveness. Always `204`. |
| `GET /readyz` | `204` when PostgreSQL answers a ping and the graph revision can be read. It never compiles the graph and does not wait for a first publication or for discovery to sync; graph routes return `503` until a graph is published. |
| `GET /api/v1/graph` | The current graph and its SHA-256 digest. |
| `GET /api/v1/manifest` | Creates or reuses a manifest for the current contribution versions. |
| `GET /api/v1/neighborhood` | Resources around an anchor (`depth`, `limit`, `direction`). |
| `GET /api/v1/overview` | Graph counts, the current manifest, and the newest active findings. |
| `GET /api/v1/resources`, `/api/v1/resources/{id}` | Paged, filterable resources; detail includes assertions, provenance, and evidence. |
| `GET /api/v1/relationships`, `/api/v1/relationships/{id}` | Same, for relationships. |
| `GET /api/v1/exposures` | Facets and relationships whose security semantics have `class=exposure`. |
| `GET /api/v1/events` | Server-sent events: a `graph` event with the digest on connect and whenever it changes, and a keepalive comment every 25 seconds. |
| `GET /api/v1/findings`, `/api/v1/findings/{id}` | Paged findings, filterable by `status`, `severity`, `category`, and `affectedEntityId`. |
| `GET .../remediations/{proposalID}/candidates` | Actions that can implement a proposal. |
| `POST .../remediations/{proposalID}/prepare` | Plan and dry-run one action. |
| `POST .../remediations/{proposalID}/approve` | Execute and verify a prepared action. |
| `POST /v1/logs` | OTLP/HTTP logs receiver. |
| `POST /v1/aws/firehose/vpc-flow-logs` | Firehose receiver, only when `--aws-firehose-stream-arn` is set. |
| `GET /`, `GET /assets/` | The embedded web UI. |

Each `/api/v1/events` stream polls a cheap graph revision every 500 ms and reads the shared revision-validated graph only when it changes. The stream is exempt from the server's 30-second write timeout; instead each write has its own 30-second deadline, so a stalled client is still dropped.

Errors are JSON objects of the form `{"error": "<action>: <reason>"}`. For `4xx` responses the reason says what is wrong with the request. For `5xx` responses it is generic (for example `internal server error; see the server log`), apart from a few fixed messages such as `graph is not materialized`; the details go to the server log.

The three remediation routes are always registered and return `503 Service Unavailable` unless live remediation is enabled. Every response carries a same-origin Content-Security-Policy, `Referrer-Policy: no-referrer`, and `X-Content-Type-Options: nosniff`. There is no authentication; see the [security model](../operations/security-model.md).

## Reading the graph

`GET /api/v1/graph` reads the compiled graph cached for the current database revision. Indexed list and detail endpoints read the current projection tables directly. The neighborhood endpoint currently filters the compiled graph in memory.

## Web UI

The UI is a React app in `ui/`, built with Vite into `ui/dist` and embedded into the binary by `ui/embed.go`. If it was not built, `/` shows a "UI is not built" page and the API still works. The UI only calls same-origin `/api` routes. See [Getting started](../getting-started.md) and [Testing](../development/testing.md#web-ui).

## Failure behavior

Discovery restarts a failed plugin instance on its own (see [Errors](../plugins/README.md#errors)); otherwise the process has no supervisor inside it. The discovery manager, telemetry pipeline, detector rule reloader, detection service, and HTTP server run in one `errgroup`; when any of them returns an error or panics, the others are cancelled and `agentshield` exits non-zero. A panic in one of those top-level goroutines becomes an error carrying its stack; a panic in a goroutine a component starts itself still crashes the process. Shutdown, on a signal or a failure, runs in order: the HTTP server stops accepting requests, closes open `/api/v1/events` streams, and gets 10 seconds for in-flight requests; only then is the telemetry pipeline cancelled, and it drains its queue (see [Telemetry](telemetry.md#failure-behavior)). Run it under something that restarts it (systemd, a Kubernetes Deployment). The investigation worker and the Deployment rule author report their errors, retry their jobs, and keep running; a model outage never stops the process or detection.

| Failure | Behavior |
| --- | --- |
| PostgreSQL unreachable at startup | Exits before starting anything. There is no connection retry. |
| A plugin's `Run` returns an error or panics (failed required sync, unexpected subscription closure, publication failure) | The manager logs it, republishes that instance's last healthy output as `degraded`, and restarts only that instance with backoff (1 s doubling to 2 min). Other plugins keep running. See [Errors](../plugins/README.md#errors). |
| A subscriber falls behind its collection | Not a failure. The hub coalesces that subscriber's pending changes to the latest per key and logs a warning; publishers never block. See the [tutorial](../plugins/tutorial.md#2-receive-observations). |
| A provider becomes unavailable after the first publication | Plugins republish their last good input as `degraded` or stale and keep running. See [Lifecycle](../plugins/README.md#lifecycle). |
| Telemetry sink or graph publication failure | See [Telemetry](telemetry.md#failure-behavior). |

On restart, plugins recover their generations, the in-memory hub is rebuilt from fresh provider snapshots, and reasoning either continues from its stored cursor or records a rebase (see [Startup and restarts](change-feed-and-reasoning.md#startup-and-restarts)).

## Known limits

These are the main constraints of the current design:

- **Whole-graph candidate.** Publications compile a complete in-memory candidate before a short compare-and-swap transaction. The transaction writes only affected projection rows, but candidate construction remains O(graph size) and each process keeps its own materialization.
- **No historical graph reconstruction.** Manifests retain contribution version references for audit correlation, but historical membership is not stored. Reasoning cannot analyze changes that happened while it was down; it records a rebase instead.
- **In-process state.** Prepared remediations, the collection hub, and the telemetry rollup live in memory in one process. Replicas do not coordinate.
- **No authentication.** See the [security model](../operations/security-model.md).
- **Kubernetes identity includes the requested API version.** Changing the version a plugin watches for a resource type re-keys every object of that type: old resources are retracted and new ones asserted. A CRD storage-version change in the cluster does not do this. See [Kubernetes objects](../concepts/data-model.md#kubernetes-objects).
- **Kubernetes Helm chart.** [`deploy/kubernetes`](../../deploy/kubernetes/README.md) provides a chart with read-only discovery RBAC and configurable storage. The project does not publish a container image yet; configure an image built or hosted by your organization.
