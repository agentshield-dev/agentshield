# Getting started

Three ways to see AgentShield working, from quickest to most complete:

1. [Explore the UI with fake data](#1-explore-the-ui-with-fake-data): an interactive demo environment with findings and remediations. Needs only Node.js and pnpm. About a minute once dependencies are installed.
2. [Run it against a local cluster](#2-run-against-a-local-cluster): build the service, start PostgreSQL, and discover a kind cluster. About 10 minutes. Shows the graph; findings also need a [model endpoint](../README.md#what-needs-a-model).
3. [Run the full evaluation cluster](#3-run-the-full-evaluation-cluster): a kind cluster with Cilium, Istio ambient, agentgateway, and telemetry, plus the lateral-movement evaluation campaigns. Needs an OpenAI API key and about 30 minutes.

## 1. Explore the UI with fake data

Prerequisites: `make`, Node.js 22.12 or later (`ui/.nvmrc` pins 24), and pnpm 11 (`corepack enable` provides the version pinned in `ui/package.json`). You do not need Go, Docker, a cluster, or a model.

```bash
make demo
```

This runs `pnpm install` in `ui/` and starts the real UI against an in-browser fake backend. Open <http://127.0.0.1:5173>, choose a scenario, and click **Trigger observation**. Nothing leaves your machine.

The playground starts with a clean findings view. Triggering a scenario adds its evidence-backed finding and proposed actions. Click **Prepare** to inspect the exact change, then **Approve and apply** to watch the simulated graph update invalidate the finding. **Reset** restores the clean environment. For isolated component states, `make ui-storybook` includes:

- **Overview**: inventory counts, priority findings, and source health.
- **Finding With Remediations**: a finding with its evidence and two proposed actions. Click **Prepare** to see the approval step:

  ![The approval sheet for network.declare-ingress-isolation, showing the provider, the target Pod, the NetworkPolicy that would be applied, and Cancel and Approve and apply buttons.](images/ui-remediation-approval.png)

  *The remediation approval sheet, shown with Storybook demo data.*

- **Catalog Resource**: one resource, its sources, and its graph neighborhood.
- **Fresh Install**, **Api Failure**, and **Reconnecting**: what the UI shows when there is no data yet or the service is unreachable.

Storybook remains available to contributors through `make ui-storybook`. See [Testing](development/testing.md#storybook-and-the-fake-backend).

## 2. Run against a local cluster

### Prerequisites

- Go 1.27 or later
- Docker with Compose v2 (for PostgreSQL and kind)
- [kind](https://kind.sigs.k8s.io) and kubectl, or any Kubernetes 1.30+ cluster in your current kubectl context
- Node.js 24 (`ui/.nvmrc`) and [pnpm](https://pnpm.io) 11 to build the web UI (optional; see below)

### Steps

Create a cluster. Skip this if your current kubectl context already points at a cluster you want to inspect.

Discovery only reads from the cluster. Remediation can write to it: because `make run` listens on loopback with discovery on, live remediation is enabled with your kubectl credentials, and a fix you prepare and approve in the UI is applied to the cluster. If you only want to look, point AgentShield at a read-only context or pass `--kubernetes-kubeconfig` with read-only credentials. See the [security model](operations/security-model.md#remediation-is-gated-by-people-not-by-policy).

```bash
kind create cluster --name agentshield-demo
```

Start PostgreSQL and point AgentShield at it:

```bash
export POSTGRES_PASSWORD='development-only-password'
make postgres-up
export AGENTSHIELD_DATABASE_URL="postgres://agentshield:${POSTGRES_PASSWORD}@127.0.0.1:5432/agentshield?sslmode=disable"
```

`make postgres-up` starts PostgreSQL 16 in Docker on `127.0.0.1:5432` and returns once the container's `pg_isready` health check passes. AgentShield checks the database once at startup and exits if it cannot connect. If port 5432 is taken, set `POSTGRES_PORT` before `make postgres-up` and use the same port in the URL.

Run AgentShield against your current kubectl context:

```bash
make run
```

`make run` builds the web UI, applies database migrations, starts discovery, and listens on `http://127.0.0.1:8088`. Without Node and pnpm, run `make run UI=0`: the API works, and `/` says the UI is not built.

Open `http://127.0.0.1:8088`. Within a few seconds you should see the cluster's namespaces, workloads, Pods, Services, ServiceAccounts, and Nodes, and the relationships between them. A fresh kind cluster has roughly 250 resources. Select a resource in **Environment graph** to see its neighborhood, identity, and where each fact came from:

![The Environment graph view: a Service's neighborhood on the left, and its kind, namespace, identity claim, and assertions on the right.](images/ui-graph-neighborhood.png)

*The graph view, shown with Storybook demo data.*

You can also query the API:

```bash
curl -s http://127.0.0.1:8088/readyz -o /dev/null -w '%{http_code}\n'   # 204 once PostgreSQL is reachable
curl -s http://127.0.0.1:8088/api/v1/overview                         # 503 until discovery first publishes
```

Create or change something (for example `kubectl create deployment web --image=nginx`) and watch the graph update.

### Optional: enable detection

Detection runs when one of the two model-calling features is enabled ([why](../README.md#what-needs-a-model)). With an OpenAI API key:

```bash
export AGENTSHIELD_MODEL_ENDPOINT=https://api.openai.com
export OPENAI_API_KEY=...
export AGENTSHIELD_AGENTIC_INVESTIGATION=true
export AGENTSHIELD_DEPLOYMENT_RULE_AUTHORING=true   # optional
make run
```

This starts detection, agentic investigation, and, if enabled, Deployment rule authoring. To bound model spend on a busy cluster, add `--agentic-investigation-sample-rate` and `--agentic-investigation-max-per-hour` (see [Configuration](operations/configuration.md#agentic-investigation)). The default model is `gpt-6-astra`; set `AGENTSHIELD_MODEL` to change it. The endpoint must support the OpenAI Responses API. Your graph data is sent to that endpoint; see the [security model](operations/security-model.md#model-endpoints).

On a plain kind cluster without a mesh or traffic telemetry, reasoning will mostly see inventory changes. Path 3 sets up the policies and traffic that produce meaningful findings.

### Options

- `--kubernetes-cluster-id` should be a stable name for the cluster. It is part of resource identities, so pick it once. `make run` uses the default, `local`.
- To target a specific kubeconfig: `go run ./cmd/agentshield --kubernetes-kubeconfig /path/to/kubeconfig --kubernetes-cluster-id my-cluster --kubernetes-source-id kubernetes/my-cluster`.
- To view what is already stored without running discovery: `make graph-ui`.
- AWS: see [AWS](plugins/aws.md#running).
- Every flag: [Configuration](operations/configuration.md).

### Clean up

```bash
make postgres-down                         # stops PostgreSQL; data stays in a Docker volume
kind delete cluster --name agentshield-demo
```

## 3. Run the full evaluation cluster

The evaluation cluster is a disposable kind cluster with Cilium (and Hubble), MetalLB, Gateway API, Istio ambient mode, agentgateway, an OpenTelemetry Collector, PostgreSQL, and AgentShield running in the cluster. It exists to measure whether AgentShield catches lateral movement; see [`evals/README.md`](../evals/README.md).

### Prerequisites

- Docker, kind, kubectl, helm, jq, sha256sum, and Go
- `OPENAI_API_KEY` in the environment. The setup scripts refuse to run without it (agentgateway in the cluster uses it), and `make eval-run` makes real, billed model calls.
- Enough local resources for a multi-component cluster

### Steps

```bash
export OPENAI_API_KEY=...
make eval-up      # create and configure the cluster; runs no evaluations
make eval-check   # verify the cluster and evaluation contracts; no model calls
```

The cluster uses its own kubeconfig at `evals/output/kubeconfig`; your current kubectl context is not changed.

To look at the graph AgentShield built inside the cluster:

```bash
kubectl --kubeconfig evals/output/kubeconfig -n agentshield-system port-forward service/agentshield 8088:8088
```

Then open `http://127.0.0.1:8088`. The in-cluster binary embeds the UI only if `ui/dist` was built (`make ui`) before `make eval-up`. Because the in-cluster service listens on a non-loopback address, live remediation is disabled there.

To run the evaluation campaigns and score them:

```bash
make eval-run
```

Results are written to `evals/output/<timestamp>/`.

### Clean up

```bash
make eval-down
```

## Next steps

- [What AgentShield does](concepts/overview.md): the problem and the pipeline.
- [Data model](concepts/data-model.md): identities, assertions, contributions.
- [Plugins](plugins/README.md): add a provider.
