# Configuration

Every command-line flag and environment variable AgentShield reads. Flags use pflag; discovery options are registered by their owning plugin and always carry that plugin's name as a prefix.

Flags accept `-flag` or `--flag`. When a flag's default comes from an environment variable, an explicit flag wins.

Every binary prints its version and commit and exits with `--version` (for `agentshield-detector-rules`, as the only argument). Release builds carry the tag and commit; a `go build` from a checkout reports the module version or `dev` and the VCS revision when Go recorded one.

## `agentshield`

The main service: discovery, telemetry, API, UI, and (optionally) detection with agentic investigation and Deployment rule authoring.

### Server and storage

| Flag | Default | Description |
| --- | --- | --- |
| `--version` | (flag) | Print the version and commit, then exit. |
| `--listen` | `127.0.0.1:8088` | HTTP listen address. The API has no authentication: a non-loopback address exposes it to anyone who can reach the port, and disables live remediation. See the [security model](security-model.md). |
| `--database-url` | `$AGENTSHIELD_DATABASE_URL` | PostgreSQL URL. Prefer the environment variable; a flag value is visible in the process list. Required. |
| `--database-max-conns` | `$AGENTSHIELD_DATABASE_MAX_CONNS` or `20` | Maximum pool connections. |
| `--database-min-conns` | `$AGENTSHIELD_DATABASE_MIN_CONNS` or `2` | Minimum pool connections. |

### Telemetry sink

| Flag | Default | Description |
| --- | --- | --- |
| `--telemetry-jsonl` | `.agentshield/telemetry.jsonl` | Raw telemetry file, used when `--clickhouse-url` is empty. |
| `--clickhouse-url` | empty | ClickHouse HTTP endpoint, for example `http://clickhouse:8123`. Enables the ClickHouse sink. |
| `--clickhouse-database` | `agentshield` | ClickHouse database. |
| `--clickhouse-table` | `telemetry_events` | ClickHouse raw table. |
| `--clickhouse-username` | `default` | ClickHouse user. The password comes from `AGENTSHIELD_CLICKHOUSE_PASSWORD`. |

### Discovery

| Flag | Default | Description |
| --- | --- | --- |
| `--disable-discovery` | `false` | Run no plugins. Serve what is already in PostgreSQL. Also disables live remediation. |
| `--kubernetes-disable` | `false` | Do not start the Kubernetes source. Kubernetes-backed consumer plugins then have no shared collection source. |
| `--kubernetes-kubeconfig` | empty | Kubeconfig path. Empty means in-cluster config when `KUBERNETES_SERVICE_HOST` is set, otherwise the standard loading rules (`KUBECONFIG`, `~/.kube/config`). |
| `--kubernetes-cluster-id` | `local` | Stable Kubernetes source authority; never change it for an existing cluster. |
| `--kubernetes-network-id` | Kubernetes cluster ID | Network realm for network-destination and peer-class identities. |
| `--kubernetes-source-id` | `kubernetes/local` | Stable source ID for the Kubernetes inventory plugin. |
| `--istio-cluster-id` | `local` | Stable cluster authority used by Istio. Match this with the Kubernetes source when referring to the same objects. |
| `--istio-network-id` | Istio cluster ID | Network realm used by Istio. |
| `--istio-source-id` | `kubernetes/local` | Stable source ID for Istio contributions and telemetry. |
| `--istio-root-namespace` | `istio-system` | Istio mesh root namespace. |
| `--agentgateway-cluster-id` | `local` | Stable cluster authority used by agentgateway. Match the Kubernetes source when referring to the same objects. |
| `--agentgateway-source-id` | `kubernetes/local` | Stable source ID for agentgateway contributions. |
| `--cilium-cluster-id` | `local` | Stable cluster authority used by Cilium. Match the Kubernetes source when referring to the same objects. |
| `--cilium-source-id` | `kubernetes/local` | Stable source ID for Cilium contributions. |
| `--falco-cluster-id` | `local` | Stable cluster authority used by Falco alert telemetry. Match the Kubernetes source so Pod identities converge. |
| `--falco-source-id` | `kubernetes/local` | Stable source ID for Falco telemetry. |
| `--aws-region` | empty | Enables the AWS plugin in this region. |
| `--aws-events-queue-url` | empty | SQS queue that receives CloudTrail events from EventBridge. Optional. |
| `--aws-firehose-stream-arn` | empty | Enables the plugin-owned Firehose VPC Flow Log receiver. Requires `--aws-region` and `AGENTSHIELD_AWS_FIREHOSE_ACCESS_KEY`. |
| `--aws-firehose-access-key` | `$AGENTSHIELD_AWS_FIREHOSE_ACCESS_KEY` | Firehose shared key. Prefer the environment variable. |

Discovery needs at least one source: startup fails if `--kubernetes-disable` is set without `--aws-region` (unless `--disable-discovery` is set).

### Detection and model-calling features

Nothing calls a model unless one of the two feature flags below is set. Detection runs when either is enabled and makes no model calls itself; there is no detection-only mode. See [Detection and investigation](../architecture/change-feed-and-reasoning.md#detection-and-investigation).

| Flag | Default | Description |
| --- | --- | --- |
| `--agentic-investigation` | `$AGENTSHIELD_AGENTIC_INVESTIGATION` or `false` | Investigate built-in novelty signals with a model agent that may promote findings. Runs in its own sampled queue. Requires an OpenAI Responses-compatible `--model-endpoint`; rejected with `--model-provider=anthropic`. |
| `--deployment-rule-authoring` | `$AGENTSHIELD_DEPLOYMENT_RULE_AUTHORING` or `false` | Draft a detection rule for each Kubernetes Deployment Pod template revision with a model agent, from the Deployment's observed behavior. Drafts run in shadow mode until approved. Requires `--model-endpoint` or `--model-provider=anthropic`. |
| `--model-endpoint` | `$AGENTSHIELD_MODEL_ENDPOINT` or selected provider default | Model API base URL. The provider client selects its supported request endpoint. Setting it alone enables nothing. |
| `--model-api-key` | see below | Model API key. Prefer the environment. |
| `--model-provider` | `openai` | Provider for the model-calling features: `openai` or `anthropic`. `anthropic` uses the Messages API, defaults the endpoint to `https://api.anthropic.com`, and supports only Deployment rule authoring; it cannot be combined with `--agentic-investigation`, which requires the Responses API. |
| `--model` | `$AGENTSHIELD_MODEL` or `gpt-6-astra` | Model name. With Anthropic and no override, the author uses its provider default. |
| `--model-reasoning-effort` | `$AGENTSHIELD_MODEL_REASONING_EFFORT` | Reasoning effort for compatible providers (for example `low`), for both features. Empty sends none. |

#### Detection

| Flag | Default | Description |
| --- | --- | --- |
| `--detection-interval` | `1s` | Change-feed polling interval. |
| `--detection-consumer` | `reasoning/default` | Durable consumer ID for the change-feed cursor. The default keeps cursors from earlier releases. |
| `--detection-signal-retention` | `168h` | How long recorded detection signals and finished investigation jobs are kept. Minimum `1h`. |
| `--detector-reload-interval` | `10s` | Polling interval for the active CEL ruleset and Deployment rules. Must be positive. |

#### Agentic investigation

| Flag | Default | Description |
| --- | --- | --- |
| `--agentic-investigation-retrieval` | `$AGENTSHIELD_AGENTIC_INVESTIGATION_RETRIEVAL` or `model_selected` | `model_selected` or `deterministic`. See [investigation tools](../architecture/change-feed-and-reasoning.md#investigation-tools). |
| `--agentic-investigation-batch-window` | `30s` | How long a queued investigation waits so later windows that share a resource join it. `0` to `10m`. |
| `--agentic-investigation-sample-rate` | `1` | Fraction of medium-risk investigations run, `0` to `1`. High and critical always run. |
| `--agentic-investigation-dedup-window` | `1h` | Skip an investigation whose signal pattern was already investigated within this window. `0` disables. |
| `--agentic-investigation-max-per-hour` | `0` (unlimited) | Investigations started in any trailing hour. Over budget, medium-risk jobs are skipped and high-risk jobs wait. |
| `--agentic-investigation-max-attempts` | `5` | Failed attempts before a job fails permanently. |
| `--agentic-investigation-poll-interval` | `1s` | Investigation queue polling interval. |

#### Deployment rule authoring

| Flag | Default | Description |
| --- | --- | --- |
| `--deployment-rule-authoring-poll-interval` | `1s` | Rule-authoring queue polling interval. Must be positive. |
| `--deployment-rule-authoring-timeout` | `5m` | Maximum duration of one rule-authoring model call. Minimum `30s`. |
| `--rule-review-api` | `$AGENTSHIELD_RULE_REVIEW_API` or `false` | Serve the unauthenticated rule review and regenerate routes on a non-loopback listener. They are always served on a loopback listener. Set only behind an authenticating proxy or in a disposable environment. See [Reviewing over HTTP](../architecture/detection-rules.md#reviewing-and-regenerating-over-http). |
| `--deployment-rule-baseline-window` | `6h` | How long a new Deployment or Pod template revision is observed before its rule is drafted. `0` to `24h`, the telemetry retention. See [Detection rules](../architecture/detection-rules.md#worker). |

API key lookup order: `--model-api-key`, then `AGENTSHIELD_MODEL_API_KEY`, then the conventional key for the selected provider (`OPENAI_API_KEY` or `ANTHROPIC_API_KEY`).

Renamed in this release: `--reasoning-effort` is `--model-reasoning-effort`, `--reasoning-retrieval` is `--agentic-investigation-retrieval`, `--reasoning-consumer` is `--detection-consumer`, `--reasoning-interval` is `--detection-interval`, and `--deployment-author-poll-interval` and `--deployment-author-timeout` are `--deployment-rule-authoring-poll-interval` and `--deployment-rule-authoring-timeout`. Setting `--model-endpoint` no longer enables any feature by itself.

## `agentshield rules`

Manages CEL rulesets, reviews Deployment rules, and inspects detection signals and queues through `agentshield rules <validate|save|activate|show|jobs|job|review|workload-rules|signals|investigations> [flags]`. The `agentshield-detector-rules` executable remains as a compatibility entry point using the same implementation. See [Detection rules](../architecture/detection-rules.md#managing-rulesets).

| Flag | Default | Used by | Description |
| --- | --- | --- | --- |
| `--file` | empty | `validate`, `save` | Ruleset JSON file. Required for those actions. |
| `--id` | empty | `activate`, `show` | Ruleset ID. Required for `activate`; optional for `show`. |
| `--actor` | empty | `save`, `activate`, `review` | Audit name. Required for those actions. Not authentication. |
| `--expected-revision` | `0` | `activate` | Current activation revision; `0` means none is active. |
| `--job-id` | `0` | `job`, `review` | Deployment rule-authoring job ID. |
| `--decision` | empty | `review` | `approved` runs the job's rule in active mode; `rejected` stops loading it. Requires `--actor`. |
| `--rule-id` | empty | `signals` | Only signals from this rule. |
| `--investigation` | empty | `signals` | Only signals in this state: `rule_finding`, `shadow`, `queued`, `below_threshold`, `disabled`, or `investigated`. |
| `--limit` | `100` | `signals`, `investigations` | Maximum rows, newest first. |
| `--database-url` | `$AGENTSHIELD_DATABASE_URL` | all except `validate` | PostgreSQL URL. |

The command has a 30-second overall timeout. `validate` does not open a database; other actions require `AGENTSHIELD_DATABASE_URL`.

## `agentshield-deployment-author`

Runs the Deployment rule author once against a local JSON context. No database. See [Detection rules](../architecture/detection-rules.md#trying-the-author-without-a-cluster).

| Flag | Default | Description |
| --- | --- | --- |
| `--version` | `false` | Print the version and commit, then exit. |
| `--input` | empty | Authoring context JSON file. Required. |
| `--model-endpoint` | `$AGENTSHIELD_MODEL_ENDPOINT` | Model API base URL. Required for OpenAI unless `--dry-run`. |
| `--model-api-key` | see above | API key, same lookup order as `agentshield`. |
| `--model` | provider default | Model override. |
| `--model-provider` | `openai` | Provider: `openai` or `anthropic`; endpoint defaults to the selected provider's API. |
| `--timeout` | `5m` | Maximum model request duration. |
| `--dry-run` | `false` | Print the exact first request body that would be sent and exit without making a provider request. Needs no endpoint or key. |
| `--verbose` | `false` | Log each `add_rule` call and a run summary (calls and accepted rules) to stderr at debug level. The proposal on stdout is unchanged. |

## `agentshield-reasoning-mcp`

Serves MCP tools over streamable HTTP at `/mcp`. The default listener is
`127.0.0.1:8090`; use `--listen` to change it only behind authenticated
infrastructure. The server reads the packet and optional pinned telemetry
context files and does not contact a database or model.

| Flag | Default | Description |
| --- | --- | --- |
| `--version` | (standalone option) | Print the version and commit, then exit. |
| `--packet` | empty | Path to an immutable reasoning packet. Required. |
| `--telemetry-context` | empty | Optional pinned telemetry and candidate-path context. |
| `--listen` | `127.0.0.1:8090` | HTTP listen address. Non-loopback exposure requires an authenticating proxy or equivalent. |

## Environment variables

| Variable | Read by | Purpose |
| --- | --- | --- |
| `AGENTSHIELD_DATABASE_URL` | `agentshield`, `agentshield rules`, `agentshield-detector-rules`, `evals/cmd`, `make run`, `make graph-ui` | PostgreSQL URL. |
| `AGENTSHIELD_DATABASE_MAX_CONNS`, `AGENTSHIELD_DATABASE_MIN_CONNS` | `agentshield` | Pool size defaults. Invalid integers fall back to the defaults. |
| `AGENTSHIELD_CLICKHOUSE_PASSWORD` | `agentshield` | ClickHouse password. |
| `AGENTSHIELD_AWS_FIREHOSE_ACCESS_KEY` | `agentshield` | Firehose delivery stream access key. Required with `--aws-firehose-stream-arn`. |
| `AGENTSHIELD_MODEL_ENDPOINT` | `agentshield`, `agentshield-deployment-author`, `evals/cmd` | Model API base URL. |
| `AGENTSHIELD_MODEL_API_KEY` | `agentshield`, `agentshield-deployment-author` | Model API key for either provider. |
| `OPENAI_API_KEY` | `agentshield`, `agentshield-deployment-author`, eval scripts | OpenAI key fallback. The eval scripts require it unless `AGENTSHIELD_EVAL_DETECTOR_ONLY=1`. |
| `ANTHROPIC_API_KEY` | `agentshield`, `agentshield-deployment-author` | Anthropic key fallback when `--model-provider=anthropic`. |
| `AGENTSHIELD_MODEL` | `agentshield`, `evals/cmd` | Model name. |
| `AGENTSHIELD_AGENTIC_INVESTIGATION`, `AGENTSHIELD_DEPLOYMENT_RULE_AUTHORING` | `agentshield` | Boolean defaults for the two feature flags. |
| `AGENTSHIELD_MODEL_REASONING_EFFORT` | `agentshield`, `evals/cmd` | Reasoning effort for compatible providers. |
| `AGENTSHIELD_AGENTIC_INVESTIGATION_RETRIEVAL` | `agentshield`, `evals/cmd` | `model_selected` or `deterministic`. |
| `AGENTSHIELD_EVAL_DETECTOR_ONLY` | eval scripts, `evals/cmd` | `1` runs evals without agentgateway, an API key, or model calls. |
| `KUBERNETES_SERVICE_HOST` | `agentshield` | When set and `--kubernetes-kubeconfig` is empty, use in-cluster Kubernetes config. |
| `KUBECONFIG` | client-go loading rules, `evals/cmd` | Kubeconfig path(s). |
| `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, ... | AWS SDK | Standard AWS SDK credential chain. |
| `AGENTSHIELD_EVAL_VARIANT`, `AGENTSHIELD_EVAL_OBSERVATION_ADAPTER` | `evals/cmd` | Evaluation labels and observation adapter. See [`evals/README.md`](../../evals/README.md). |
| `AGENTSHIELD_TEST_DATABASE_URL` | `pkg/state` and `pkg/api` tests | Disposable test database. **Tests truncate it.** |

### Makefile and Docker Compose

| Variable | Default | Purpose |
| --- | --- | --- |
| `LISTEN` | `127.0.0.1:8088` | `--listen` for `make run` and `make graph-ui`; proxy target for `make ui-dev`. |
| `DEMO_PORT` | `5173` | Browser-only playground port for `make demo`. |
| `DATABASE_URL` | `$AGENTSHIELD_DATABASE_URL` | Database URL for `make run` and `make graph-ui`. |
| `UI` | `1` | `UI=0` skips the Node/pnpm UI build for `make build`, `make run`, and `make graph-ui`. |
| `GO`, `PNPM` | `go`, `pnpm` | Tool overrides. |
| `POSTGRES_PASSWORD` | none (required) | Password for `make postgres-up` (`deploy/postgres/compose.yaml`). |
| `POSTGRES_USER`, `POSTGRES_DB` | `agentshield` | Compose database user and name. |
| `POSTGRES_BIND`, `POSTGRES_PORT` | `127.0.0.1`, `5432` | Compose port binding. |

The eval scripts in `evals/scripts/` read more variables (cluster name, tool versions, output directory); see `evals/scripts/lib.sh`.

## Status logs

Each long-running loop in `agentshield` logs what it is doing at Info level, without a line per iteration. Rare events get their own line: a plugin starting, a Deployment rule job being claimed and drafted, an investigation job starting and finishing, detection rules matching, and the detector loading a changed ruleset or workload rule set. Each loop also logs one status line with its counters since the previous line: at most every 15 seconds while it does work, and at most once a minute while it is idle.

| Loop | Status line | Counters and fields |
| --- | --- | --- |
| Discovery plugin | `discovery plugin` | `plugin`, `source`, `observations`, `contributions` |
| Telemetry pipeline | `telemetry pipeline` | `accepted`, `written`, `batches`, `queued`, `queue_capacity` |
| Detection service | `detection service` | `windows`, `changes`, `novelty_signals`, `rule_signals`, `shadow_signals`, `cursor`, `ruleset` |
| Deployment rule authoring | `Deployment rule authoring worker` | `completed`, `failed`, `ready`, `running`, `retrying`, `waiting_for_baseline`, `baseline_window`, `next_baseline_ends_in` |
| Agentic investigation | `investigation worker` | `processed`, `failed` |

A Deployment rule draft that stays queued is usually inside its baseline window; `waiting_for_baseline` and `next_baseline_ends_in` show it. **Author now** in the UI, or `POST /api/v1/workloads/{id}/rule-drafts`, skips the wait.
