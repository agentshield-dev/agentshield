# Falco plugin

## Contract

The `falco` plugin is a telemetry-only capability. It maps Falco runtime-security
alerts that an existing OpenTelemetry Collector forwards to the shared OTLP
receiver. It opens no provider connection, consumes no collection, and owns no
contribution; the telemetry runtime owns the bounded rollup contribution.

- Plugin ID and version: `falco`, `0.1.0`.
- Downstream authority: `--falco-cluster-id`. Match the Kubernetes source so
  Pod identities converge.
- Source ID: `--falco-source-id`.
- Identity schemes: Kubernetes `kubernetes.io/v1, Kind=Object` for the Pod
  subject and core `agentshield.io/v1, Kind=ProcessClass` for the object.
- Telemetry kind: `process-exec`, registered in `telemetry.EventKinds()`.
- Projected predicate: `executes`, a rollup-owned lease from the Pod to the
  process class.
- Downstream cursor: none. Falco does not expose a resumable stream; the
  collector's file offset is the delivery cursor.

The initial scope is one use case: a Pod started an interactive shell.

## Ingestion routes

Both routes deliver the same Falco JSON alert as an OTLP log body with resource
`service.name=falco`, so the same mapper handles either. Neither requires
AgentShield code or configuration beyond the shared OTLP receiver.

| Route | Deploys | Delivery |
| --- | --- | --- |
| HTTP output (default) | a `webhook_event` receiver on an existing collector Deployment | Falco does not retry; alerts sent while the collector is unavailable are lost |
| Container logs | a collector DaemonSet with a read-only `/var/log/pods` hostPath | the collector resumes from its file offset |

Use the HTTP route when an installation already runs a collector Deployment and
should not add a node-level DaemonSet. Use the container-log route when alert
loss during collector restarts is unacceptable.

Both routes need JSON alerts with the Pod UID appended to every syscall rule.
`k8s.pod.uid` comes from container runtime labels and needs no Kubernetes API
access from Falco:

```yaml
falco:
  json_output: true
  json_include_output_property: true
  append_output:
    - match:
        source: syscall
      extra_fields:
        - k8s.pod.uid
        - container.id
```

The mapper trusts `service.name=falco`. Restrict who can produce it: on the
HTTP route, admit only Falco pods to the receiver port; on the container-log
route, read only the Falco container's log files.

Do not use Falcosidekick's `otlp/logs` output. As of Falcosidekick 2.31 it
forwards only the rendered output string, rule, priority, and hostname. It
drops `output_fields`, so no Pod UID reaches AgentShield, and it carries the
event time only as a string attribute.

### HTTP output route

Falco posts one alert per request. The collector's `webhook_event` receiver
(contrib distribution) places the whole request body in the log body.

```yaml
# Falco values
falco:
  http_output:
    enabled: true
    url: http://opentelemetry-collector.observability.svc.cluster.local:8080/falco
```

```yaml
# Collector (otel/opentelemetry-collector-contrib)
receivers:
  webhook_event/falco:
    endpoint: 0.0.0.0:8080
    path: /falco

processors:
  resource/falco:
    attributes:
      - key: service.name
        value: falco
        action: upsert

exporters:
  otlp_http/agentshield:
    endpoint: http://agentshield.agentshield-system.svc.cluster.local:8088
    encoding: proto

service:
  pipelines:
    logs/falco:
      receivers: [webhook_event/falco]
      processors: [resource/falco, batch]
      exporters: [otlp_http/agentshield]
```

The receiver is unauthenticated. Add a NetworkPolicy that admits only Falco
pods to its port. The eval collector in `evals/manifests/otel-collector.yaml`
and `evals/config/falco-values.yaml` implement this route:

```bash
kubectl apply -f evals/manifests/otel-collector.yaml
helm upgrade -i falco oci://ghcr.io/falcosecurity/charts/falco --version 9.2.0 \
  --namespace falco --create-namespace --set tty=true -f evals/config/falco-values.yaml
```

### Container-log route

Leave Falco's default stdout output enabled. Run a collector DaemonSet that
mounts `/var/log/pods` read-only and reads the Falco container's logs:

```yaml
receivers:
  filelog/falco:
    include: [/var/log/pods/falco_falco-*/falco/*.log]
    start_at: end
    operators:
      - type: container

processors:
  resource/falco:
    attributes:
      - key: service.name
        value: falco
        action: upsert

service:
  pipelines:
    logs/falco:
      receivers: [filelog/falco]
      processors: [resource/falco, batch]
      exporters: [otlp_http/agentshield]
```

Falco's own non-JSON log lines share that file and are rejected by the mapper.

### Unmapped alerts

Every alert reaches AgentShield. Alerts from rules other than the configured
shell rules are skipped: they are neither ingested nor reported as rejected,
so normal Falco output causes no partial-success warnings. To save the traffic,
forward only shell alerts by adding a filter to either pipeline:

```yaml
processors:
  filter/falco-shell:
    error_mode: ignore
    logs:
      log_record:
        - 'not IsMatch(body, "\"rule\":\"Terminal shell in container\"")'
```

## Mapping

A record matches when its resource `service.name` is `falco`. The body may be
the raw JSON line or a collector-parsed map.

| Normalized field | Value |
| --- | --- |
| `eventId` | `falco/` plus the SHA-256 of the canonical alert JSON (sorted keys, exact numbers) |
| `observedAt` | the alert's `time` field, the original Falco event time |
| `kind` | `process-exec` |
| `subject` | the Pod, by `output_fields["k8s.pod.uid"]` |
| `object` | `ProcessClass` `shell`, authority = cluster ID |
| `operation` | `spawn-shell` |
| `outcome` | `observed`; Falco detects but does not block |
| `coverage` | `falco-runtime-alert` |
| `properties` | `falco/rule`, `falco/priority`, and `container-id` when present; raw sink only |

The event ID is stable across collector retries and across raw versus parsed
bodies. Distinct alerts differ at least in `evt.time` or `time`.

Alerts from rules other than the configured shell rules (default
`Terminal shell in container`) are skipped with `telemetry.ErrSkipRecord`,
not rejected.

The mapper rejects, without echoing payload values such as the rule or
source:

- alerts without a `source`;
- shell-rule alerts whose source is not `syscall`;
- alerts without a Pod UID, including host processes and non-Kubernetes
  containers (`<NA>`);
- alerts without an RFC 3339 `time`;
- bodies that are not one JSON object.

Process command lines, user names, file paths, and environment details are not
copied into normalized properties because they can contain credentials. The
rollup carries no adapter properties, so graph cardinality is one series per
Pod and minute while shells are observed.

## Graph output and detection

The rollup emits a `process-exec` telemetry assertion from the Pod to the
`process/class` `shell` resource, materializes that class resource while a
retained series references it, and projects a Pod `executes` shell lease
relationship with rule ID `telemetry.process-execution-lease`. The lease
follows the same lifecycle as `communicates-with`: it is created by the first
observation, unchanged by later shells, refreshed in the final quarter of
retention while shells continue, and retracted after retention without shells.
It never implies network reachability. The graph explorer and neighborhood
queries therefore show which Pods spawned shells as edges into the `shell`
node. Series and leases whose Pod is absent from inventory are omitted from
publication until it appears or retention expires.

Creating the lease advances the graph change feed. The detector evaluates the
new edge together with the series that created it, and their Pod anchor gains
the owning Deployment through `instantiates`. A Deployment rule selects either
`telemetry:process-exec` or `relationship:executes`, with
`process_class == 'shell'`; see [Detection rules](../architecture/detection-rules.md). Both
selectors and the `shell` class appear in the Deployment rule author's
generated schema, so the model can propose a no-shell rule alongside other
rules for a new workload.
Detection fires once per Pod within rollup retention, not once per shell;
every alert remains in the raw sink.

## Tracing a shell alert

Falco's shell rule fires only for an interactive terminal, so open the shell
with `kubectl exec -it`. Without `-it`, no alert is raised. The API rows assume
`kubectl -n agentshield-system port-forward svc/agentshield 8088:8088`.

| Step | Where to look | What you should see |
|---|---|---|
| Falco saw it | `kubectl -n falco logs ds/falco -c falco` | `"rule":"Terminal shell in container"` with `k8s.pod.uid` in `output_fields` |
| AgentShield received it | AgentShield logs | `telemetry pipeline accepted=1 written=1`; alerts from other rules are skipped without a warning, and a `rejected OTLP log records` warning means a malformed shell alert |
| It reached the graph | `GET /api/v1/graph`, `.snapshot.telemetry[]` with `kind == "process-exec"` | one `spawn-shell` entry per Pod and minute, and the Pod's `executes` edge to `shell` |
| A rule fired | AgentShield logs | `detection rules matched rule_signals=1`; `shadow_signals` counts unapproved draft rules, which raise no finding |
| Finding created | UI Findings view, or `GET /api/v1/findings` | a `detection_rule_match` finding whose `detectionRuleId` is the Deployment's rule |

A trace that stops before "A rule fired" usually means one of two things. The
Deployment has no active shell rule, so approve its draft in the Rules view. Or
the Pod already raised a detection within retention, as described above.

## Failure and scale

From the collector onward, delivery, retry, and backpressure follow the shared
OTLP receiver and telemetry pipeline: the receiver acknowledges only enqueued
records, the raw sink commits before projection, and a full queue applies
backpressure to the collector. Loss before the collector depends on the route:
Falco's HTTP output drops alerts it cannot deliver, while the container-log
route resumes from the collector's file offset.

Shell alerts are sparse, human-driven events. Change-feed events are bounded by
lease creation, refresh, and expiry per Pod, not by shell count.

## Typed security semantics

`process-exec` telemetry and the `executes` relationship are provider-native
runtime evidence and carry no `graph.SecuritySemantics` envelope. An
observation does not establish an exposure or governance fact; detection rules
and reasoning interpret it.
