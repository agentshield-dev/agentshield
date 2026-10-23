# AgentShield Helm chart

This Helm chart deploys one AgentShield process with a read-only Kubernetes
ClusterRole, a `ClusterIP` Service, health probes, and
a local JSONL telemetry sink. PostgreSQL is required and is supplied through a
Secret you create. AgentShield is pre-1.0; no container image is published.

Read the [security model](https://agent-shield.dev/docs/operations/security/) before
installing. The HTTP API has no authentication.

## Install

Build and push the root Dockerfile to a registry accessible by your cluster.
Then create a namespace and its restricted Pod Security labels:

```bash
kubectl create namespace agentshield-system
kubectl label namespace agentshield-system \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest
kubectl -n agentshield-system create secret generic agentshield-database \
  --from-literal=url='postgres://agentshield:REDACTED@postgres.example.internal:5432/agentshield?sslmode=verify-full'
```

Install the chart, setting the image built above:

```bash
helm upgrade --install agentshield deploy/kubernetes \
  --namespace agentshield-system \
  --set image.repository=registry.example.com/agentshield \
  --set image.tag=v0.1.0
kubectl -n agentshield-system rollout status deployment/agentshield-agentshield
```

The sample defaults use stable `example-cluster` IDs for the Kubernetes,
Istio, agentgateway, and Cilium plugin configurations. Override each
independently through `values.yaml` or `--set
discovery.<plugin>.clusterID=...`; plugins that must refer to the same
Kubernetes object need the same stable cluster authority. Do not change an
authority ID for a database that already contains graph data.

## PostgreSQL

Use a dedicated database for each AgentShield process. PostgreSQL 16 is used
in development and CI; other versions are untested. Provision the database
and role before installing the chart, and store the connection URL in the
Secret referenced by `database.existingSecret` (key `url` by default).
Use TLS outside loopback.

The role needs DDL rights at startup to apply pending
[migrations](https://agent-shield.dev/docs/architecture/publication-and-storage/#schema-migrations).
Never use this database for integration tests; those tests truncate their
target. Change-feed and contribution history have no retention policy yet.

## Telemetry storage

The default raw sink is the local file
`/var/lib/agentshield/telemetry.jsonl`, mounted on a size-limited `emptyDir`.
It is lost when the Pod is replaced. For durable local storage, customize the
Deployment with a PersistentVolumeClaim; the chart intentionally does not
provision one because storage classes and retention requirements vary.

ClickHouse is opt-in. Create the schema from
[`deploy/clickhouse/schema.sql`](../clickhouse/schema.sql), create a Secret
with the password, then enable the sink:

```bash
helm upgrade --install agentshield deploy/kubernetes \
  --namespace agentshield-system \
  --set image.repository=registry.example.com/agentshield \
  --set image.tag=v0.1.0 \
  --set telemetry.clickhouse.enabled=true \
  --set telemetry.clickhouse.url=http://clickhouse.example.internal:8123 \
  --set telemetry.clickhouse.existingSecret=agentshield-clickhouse
```

The Secret key defaults to `password`; set
`telemetry.clickhouse.secretKey` to use another key. No database URL or
password belongs in Helm values or source control.

The schema creates the `agentshield` database, a raw event table with a
30-day TTL, and per-minute rollups with a 180-day TTL. Adjust the schema if
you choose a different database name. If ClickHouse is unavailable, ingestion
applies backpressure rather than dropping events; see
[Telemetry](https://agent-shield.dev/docs/architecture/telemetry/#failure-behavior).

## Process requirements

Run one AgentShield process per database and leave `replicaCount` at `1`.
One process can discover one Kubernetes cluster and one AWS region.
Multiple replicas would duplicate provider rollups and share the default
reasoning consumer ID. Prepared remediations, the collection hub, and
telemetry rollups are held in process memory, not shared between replicas.
Only migrations and Deployment rule-author queue leases coordinate across
processes.

The chart checks `/healthz` for liveness and `/readyz` for database
connectivity. Readiness does not wait for a published graph, so telemetry can
reach the Pod before discovery's first publication; graph routes return `503`
until then. The startup probe allows 6 minutes for migrations, and the
termination grace period of 45 seconds covers the HTTP shutdown and the
telemetry drain. The process logs to stderr.

## Access and security

The Pod listens on `0.0.0.0:8088` so kubelet probes and the Service can reach
it. The Service is cluster-internal, but the chart does not install a
NetworkPolicy or restrict which Pods can reach the unauthenticated API.
Supply your own network controls to restrict access. Use
`kubectl port-forward service/agentshield-agentshield
8088:8088` for local access. Do not add an Ingress, LoadBalancer, or NodePort
without an authenticating and authorizing proxy. The path from an OTLP
collector to AgentShield is also unauthenticated.

The ClusterRole includes Secrets because Kubernetes RBAC cannot grant
metadata-only Secret watches. The plugin discards values before persistence,
but its service account can read all cluster Secrets. The ClusterRole does not
grant write permissions, and live remediation remains disabled on this
non-loopback listener.

See [Configuration](https://agent-shield.dev/docs/operations/configuration/) for every flag,
and the [AWS plugin](https://agent-shield.dev/docs/plugins/aws/#vpc-flow-log-telemetry) for
Firehose ingestion setup.
