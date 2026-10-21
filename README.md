<!-- markdownlint-disable MD033 MD041 -->
<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/agentshield-logo-light.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/images/agentshield-logo-color.svg">
    <img src="docs/images/agentshield-logo-color.svg" alt="agentshield" width="400">
  </picture>
  <p>
    <a href="https://github.com/agentshield-dev/agentshield/actions/workflows/ci.yml"><img src="https://github.com/agentshield-dev/agentshield/actions/workflows/ci.yml/badge.svg" alt="Build status"></a>
    <a href="https://github.com/agentshield-dev/agentshield/blob/main/LICENSE"><img src="https://img.shields.io/github/license/agentshield-dev/agentshield?style=flat" alt="License: Apache 2.0"></a>
    <a href="https://github.com/agentshield-dev/agentshield"><img src="https://img.shields.io/github/stars/agentshield-dev/agentshield?style=flat&amp;logo=github&amp;label=Stars" alt="GitHub stars"></a>
    <a href="https://discord.gg/Anq24jH8Kp"><img src="https://img.shields.io/badge/Discord-Join-5865F2?style=flat&amp;logo=discord&amp;logoColor=white" alt="Join Discord"></a>
  </p>
</div>
<!-- markdownlint-enable MD033 MD041 -->

Agentshield finds evidence-backed lateral-movement paths and risky security changes in Kubernetes environments that run Istio ambient mesh, Cilium, and agentgateway, and in AWS. It builds one graph of your workloads, identities, network policies, and observed traffic, flags changes that open new paths or remove protection, has a language model investigate them against the graph, and proposes fixes that a person must approve before anything changes.

![agentshield findings view with a selected finding, evidence, and proposed remediations.](docs/images/ui-finding-detail.png)

*Finding details, evidence, and proposed remediations, shown with synthetic demo data.*

![agentshield environment graph showing a selected workload and its neighboring resources.](docs/images/ui-graph-neighborhood.png)

*A selected workload and its relationships in the environment graph.*

![agentshield explicit approval dialog showing a Kubernetes NetworkPolicy change before it is applied.](docs/images/ui-remediation-approval.png)

*The approval step displays the exact change before it is applied.*

## See it in 60 seconds

The web UI ships with an interactive playground that runs the real UI against a fake in-browser backend. It needs only `make`, Node.js 22.12 or later (`ui/.nvmrc` pins 24), and pnpm 11 (`corepack enable` provides it). No Go, database, cluster, or model.

```bash
git clone https://github.com/agentshield-dev/agentshield.git
cd agentshield
make demo
```

Open <http://127.0.0.1:5173>. Choose a scenario, trigger its observation, and prepare and approve the proposed remediation. Reset restores the clean environment. The first run spends most of its time on `pnpm install`, and everything stays in your browser. More in [Getting started](docs/getting-started.md#1-explore-the-ui-with-fake-data).

## Why

Who can reach what in a modern cluster is spread across NetworkPolicies, CiliumNetworkPolicies, Istio AuthorizationPolicies and PeerAuthentications, Gateway API routes, and cloud Security Groups. Attackers moving laterally use ordinary-looking traffic and ordinary-looking configuration changes. No single tool joins these sources and asks, on every change: *did this just open a path that was not there before, and what evidence says so?* agentshield is built to answer that.

It is for platform and security engineers running Kubernetes with Istio ambient, Cilium, or agentgateway (optionally on AWS), and for contributors who want to add providers, detectors, or evaluation scenarios.

## What it does

- **Discovers** your environment into one graph:
  - Kubernetes: workloads, Pods, Services, ServiceAccounts, Nodes, RBAC, admission configuration, NetworkPolicies, Ingress, and Gateway API, through one shared informer per resource type.
  - Istio: AuthorizationPolicy, PeerAuthentication, ambient enrollment, waypoints, ServiceEntry, VirtualService.
  - Cilium: CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, CiliumEndpoint, CiliumNode.
  - agentgateway: Gateway API resources managed by agentgateway.
  - AWS: EC2 instances, ENIs, and Security Groups, with optional CloudTrail change events through EventBridge and SQS.
- **Records where every fact came from.** Each resource has a stable identity (for example, cluster ID plus Kubernetes UID), and each fact records the plugin, rule, and observation that produced it. The graph is stored in PostgreSQL as versioned, atomically replaced contributions with an ordered change feed.
- **Ingests traffic telemetry**: Istio waypoint access logs over OTLP/HTTP and AWS VPC Flow Logs through Firehose. Raw events go to JSONL or ClickHouse; per-minute summaries and `communicates-with` edges go into the graph.
  Istio logs need a custom `envoyOtelAls` extension provider that emits `agentshield.*` attributes; the example labels every caller as a Deployment, so traffic from other workload kinds is rejected. See [Istio telemetry](docs/plugins/istio.md#telemetry).
- **Detects risky changes.** Built-in detectors look for new exposure, lost governance, changed policy, new RBAC bindings, and workloads reaching destinations they never reached before, while ignoring rollouts and scaling. You can add versioned CEL rules with audited activation and hot reload, and have a model draft a rule for each new Deployment (shadow mode until you approve it). Active rule matches become findings without a model call.
- **Investigates with a model.** A model looks into each signal through six read-only MCP graph tools. Agentshield accepts a finding only if it cites facts and evidence the graph actually returned, and invalidates it when those resources change.
- **Proposes fixes behind an approval gate.** Findings can suggest a Kubernetes NetworkPolicy, CiliumNetworkPolicy, or Istio `STRICT` PeerAuthentication. A person prepares (plans and dry-runs) and approves each one, and agentshield verifies the result.
- **Serves a web UI and HTTP API** from the same binary.

## What needs a model

Detection itself never calls a model. It runs whenever one of the two model-calling features is enabled, and nothing calls a model unless you enable it:

| Flag | Default | Calls a model | What it adds |
| --- | --- | --- | --- |
| `--agentic-investigation` | off | at most once per admitted investigation | A model agent investigates built-in novelty signals (new communication paths, exposure, lost governance) and may promote findings. Runs in its own sampled queue. Requires an OpenAI Responses-compatible endpoint. |
| `--deployment-rule-authoring` | off | once per Kubernetes Deployment Pod template revision | A model agent drafts a detection rule for each Deployment from its observed behavior, after `--deployment-rule-baseline-window` (default 6h). Drafts run in shadow mode until an operator approves them. |

When detection runs, a match of an active rule (an operator-activated CEL rule or an approved Deployment rule) becomes a finding directly, with no model call. Built-in novelty signals become findings only through agentic investigation, which records a finding only when the model's answer passes validation: it must cite facts and evidence the graph returned, including at least one medium-or-higher-risk signal. Agentic investigation drains its own durable queue, so a slow or failing model never delays detection. Batching, sampling, deduplication, and an hourly budget bound its spend; see [Change feed and reasoning](docs/architecture/change-feed-and-reasoning.md#the-investigation-queue).

Without either feature you still get discovery, the graph and its change history, telemetry ingestion and rollups, and the HTTP API and UI for browsing resources, relationships, and sources. You get no findings, and so no remediation proposals, because proposals are attached to findings.

Graph data is sent to the model endpoint; see the [security model](docs/operations/security-model.md#model-endpoints). Telemetry detection rules currently run only when a graph change opens a detection window; see [Detection rules](docs/architecture/detection-rules.md#inputs).

## Status

Agentshield is an early, pre-1.0 project. Expect breaking changes to APIs, the database schema, and flags.

- The HTTP API and UI have **no authentication**, so the server binds to `127.0.0.1:8088` by default; read the [security model](docs/operations/security-model.md) before changing that.
- One process per database; no high availability.
- Tagged releases publish binaries on GitHub. Build a container image from the `Dockerfile` and deploy it with the [Helm chart](deploy/kubernetes/README.md); no container image is published yet.
- Hubble flow and agentgateway access-log normalizers exist, but no transport feeds them yet. Today's telemetry sources are Istio waypoint access logs (via OpenTelemetry) and AWS VPC Flow Logs (via Firehose).

## How it works

1. Source plugins (`kubernetes`, `aws`) watch provider APIs; semantic plugins (`istio`, `cilium`, `agentgateway`) read the same watches and add meaning.
2. Each plugin publishes its complete current output as a contribution to PostgreSQL, which keeps the current graph and an ordered change feed.
3. Telemetry (OTLP logs, VPC Flow Logs) goes to a raw sink (JSONL or ClickHouse) first; per-minute summaries then join the graph.
4. Detectors turn graph changes into signals, a model investigates each signal through read-only graph tools, and only answers that cite real graph evidence become findings.
5. A finding can propose a fix, which runs only after a person prepares and approves it.

The [pipeline diagram](docs/concepts/overview.md#pipeline) shows this flow. More detail: [What agentshield does](docs/concepts/overview.md) and the [architecture overview](docs/architecture/overview.md).

## How well does it work?

There are no published results yet. The evidence today is the evaluation suite in [`evals/`](evals/README.md): six campaigns, run against a disposable kind cluster with Cilium, Istio ambient, and agentgateway. They come in three attack/benign pairs, one per threat model:

- a compromised checkout service reading a payment signing key from a secrets manager, against a governed secret-rotation controller;
- a compromised ML workspace build worker reading workspace secrets, against the governed workspace secrets controller;
- a compromised single sign-on server enumerating private repositories, against a governed repository-inventory controller.

Each campaign generates real traffic in the cluster and waits until the plugin-produced observation reaches the graph before scoring; the expected outcome is never shown to the model. An attack campaign counts as a true positive if it produces a promoted finding, and a benign campaign counts as a true negative if it produces none. Each campaign report also records whether the finding category matched. A complete run reports security recall and benign specificity in `summary.json`, along with token usage and model latency. Six campaigns are a smoke test of the end-to-end path, not a measure of detection rates in general.

To reproduce, run `make eval-up`, `make eval-check`, and `make eval-run`. The run makes real, billed model calls; [evals/README.md](evals/README.md) has the requirements and the output format.

A separate rule suite (`make eval-rules`) scores detection rules on nine campaigns built for them, each attack paired with benign controls. It scores operator rule policies, which need no model, and the rules the Deployment rule author drafts. See [rule evals](evals/README.md#rule-evals).

## Quickstart

You need:

- Go 1.27 or later (`go.mod`)
- Docker with Compose v2, for PostgreSQL 16 and kind
- [kind](https://kind.sigs.k8s.io) and kubectl, or any Kubernetes 1.30+ cluster in your current kubectl context
- To build the web UI: Node.js 24 (`ui/.nvmrc`; `ui/package.json` accepts 22.12 or later) and pnpm 11 (`packageManager` in `ui/package.json`). pnpm installs TypeScript and Vite. Skip the UI with `make run UI=0`.

```bash
kind create cluster --name agentshield-demo

export POSTGRES_PASSWORD='development-only-password'
make postgres-up    # returns once PostgreSQL is healthy
export AGENTSHIELD_DATABASE_URL="postgres://agentshield:${POSTGRES_PASSWORD}@127.0.0.1:5432/agentshield?sslmode=disable"

make run    # discovers the current kubectl context
```

Open `http://127.0.0.1:8088` to browse the cluster graph. To get findings, also set `AGENTSHIELD_MODEL_ENDPOINT=https://api.openai.com`, `OPENAI_API_KEY`, and `AGENTSHIELD_AGENTIC_INVESTIGATION=true` (and optionally `AGENTSHIELD_DEPLOYMENT_RULE_AUTHORING=true`) before `make run` (see [What needs a model](#what-needs-a-model)).

Discovery only reads, but `make run` enables live remediation with your kubectl credentials, so a fix you approve in the UI is applied to the cluster. Use a read-only context if you only want to look.

[Getting started](docs/getting-started.md) covers this path in detail and a full evaluation cluster with Cilium, Istio ambient, and agentgateway (`make eval-up`).

## Binaries

| Command | Purpose | Docs |
| --- | --- | --- |
| `cmd/agentshield` | The service: discovery, telemetry, graph API, UI, detection, agentic investigation, and remediation | [Configuration](docs/operations/configuration.md#agentshield) |
| `cmd/agentshield-detector-rules` | Validate, save, activate, and show CEL rulesets; review Deployment rules; inspect authoring jobs, detection signals, and the investigation queue | [Detection rules](docs/architecture/detection-rules.md#managing-rulesets) |
| `cmd/agentshield-deployment-author` | Run the Deployment rule author once against a local JSON file, or print its request with `--dry-run` | [Detection rules](docs/architecture/detection-rules.md#trying-the-author-without-a-cluster) |
| `cmd/agentshield-reasoning-mcp` | Serve the reasoning MCP graph tools over streamable HTTP for a saved packet | [Change feed and reasoning](docs/architecture/change-feed-and-reasoning.md#investigation-tools) |

## Documentation

Start with the [documentation index](docs/README.md). Common destinations:

- [Getting started](docs/getting-started.md)
- [Glossary](docs/concepts/glossary.md) and [data model](docs/concepts/data-model.md)
- [Architecture overview](docs/architecture/overview.md)
- [Writing a plugin](docs/plugins/README.md)
- [Configuration](docs/operations/configuration.md) and [Helm deployment](deploy/kubernetes/README.md)
- [Testing](docs/development/testing.md)

## Contributing

See [Contributing](CONTRIBUTING.md) for setup, design docs, and testing.

For vulnerabilities, follow the private reporting guidance in [Security policy](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
