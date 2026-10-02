# Detection rules

Detectors decide which graph changes matter. They emit *signals*. What a signal becomes depends on where it came from: an active rule's match becomes a finding immediately, a built-in novelty signal may be queued for [agentic investigation](change-feed-and-reasoning.md#the-investigation-queue), and a shadow rule's match is only recorded. Detection itself never calls a model.

There are three kinds of detection:

1. **Built-in checks** in Go. They always run. [Below](#built-in-novelty-detection).
2. **CEL rules** written by operators, stored as versioned rulesets in PostgreSQL, and reloaded without a restart. [Below](#cel-rules).
3. **Model-authored Deployment rules**, one per Kubernetes Deployment. Unreviewed drafts run in shadow mode; an operator approves them to make them active. [Below](#model-authored-deployment-rules).

Detectors read normalized graph data only. They never parse provider payloads or open provider connections.

Code: `pkg/detector`, `pkg/deploymentauthoring`, `pkg/state/detector.go`, `pkg/state/deployment_authoring.go`, `cmd/agentshield rules`, `cmd/agentshield-deployment-author`.

## Built-in novelty detection

`Engine.Detect` always adds provider-neutral built-in signals (`pkg/detector/builtin.go`) to rule signals. They are designed so ordinary operational change does not reach agentic investigation. Scores of 3 or more are medium risk and can lead to a finding; a score of 2 is low risk and only recorded; lower scores are dropped (`Config.MinimumScore`).

| Reasons | Trigger | Score |
| --- | --- | --- |
| `new_communication_path`, `established_source` | A resolved `communicates-with` edge creates a workload-level path for a source that already had observed traffic | 3 |
| `new_communication_path`, `first_source_activity` | The same, for a source with no prior observed traffic, such as a newly deployed workload | 2 |
| `novel_telemetry`, `new_communication_pair` | A telemetry fingerprint for a new workload-level pair | 2 |
| `novel_telemetry`, `new_operation_or_outcome` | A new operation or outcome on a known pair | 1 (dropped) |
| `new_public_exposure`, `security_semantics_removed`, `lost_governance` | Security semantics become externally addressable or are removed, or a `governed-by` edge disappears | 4 |
| `security_semantics_changed` | Exposure or governance semantics change | 3 |
| `sensitive_resource_added` plus `rbac_binding` or `admission_webhook` | A Kubernetes RoleBinding, ClusterRoleBinding, or admission webhook configuration is created (`Config.SensitiveResourceKinds`) | 3 |
| `workload_identity_changed` | A workload's instances start using an identity (`uses-identity`) it did not use before | 3 |

Communication paths and telemetry novelty add `sensitive_destination_role` (+3 for `control-plane-api`). Communication paths also add `external_destination` (+1 for a public address or the `external-destination` peer class).

Novelty is compared per workload. A Pod is folded into the controller that instantiates it (hosts, the objects of `runs-on`, are never controllers), so a rollout, restart, or scale-up whose new Pods reach known destinations emits nothing. Several instances of one workload reaching a new destination produce one signal anchored to the instances and the workload. Resource, facet, and structural relationship changes without security semantics emit nothing. Attribute-only changes to sensitive kinds are not signaled, because their projections carry only names and labels.

The mission evals measure this with a detector-only run that needs no model (see [`evals/README.md`](../../evals/README.md)). Compared with the previous detector, the windows that deploy campaign workloads and record their first calls no longer reach the agent (12 agent invocations down to 0), and every security campaign still has an investigation-eligible signal on its observed path.

## CEL rules

### Inputs

`detector.Events` compares the previous and current graph and produces inputs for rules:

| Input type | Kinds | When it fires |
| --- | --- | --- |
| `relationship` | Every registered predicate | Once, when an edge first appears resolved. Lease refreshes and removals produce no input. Unresolved edges are skipped. |
| `telemetry` | `network-flow`, `gateway-request`, `active-probe`, `process-exec` | Once per new combination of kind, endpoints, operation, and outcome, per plugin and source. Count, property, or evidence changes alone do not fire. |

A rule selects inputs by `pluginId` (or `*`), `type`, and `kind`. The valid `type:kind` pairs come from `detector.CELSelectors()`. A rule may also set `workloadResourceId` to match only inputs anchored to one workload resource, including Pods connected to that Deployment by a resolved `instantiates` edge.

The input contract version is `v1`. CEL variables are string fields of `detector.Input`. Each selector compiles in its own CEL environment that declares only the variables that selector fills in, so referencing a variable that would always be empty is a compile error.

| Variable | Available for | Values |
| --- | --- | --- |
| `operation` | Telemetry selectors | Depends on kind, for example `GET /path`, `ingress`, `egress` |
| `outcome` | Telemetry selectors | `allowed`/`denied` for probes and gateway requests; datapath verdicts such as `forwarded` or `dropped` for flows |
| `destination_ip_class` | `telemetry:network-flow`, `relationship:communicates-with` | `public`, `private` (RFC 1918 and IPv6 unique-local), `special` (other non-global ranges such as loopback, link-local, CGNAT, documentation), `unknown` |
| `destination_role` | Communication telemetry selectors (all but `telemetry:process-exec`), `relationship:communicates-with` | `control-plane-api`, `service`, `workload`, or empty when the address belongs to no known resource |
| `process_class` | `telemetry:process-exec`, `relationship:executes` | The object's core process class from `graph.ProcessClasses()`: `shell` |

Raw IP addresses are never exposed to CEL.

Example: alert when a workload talks to a public address that belongs to no known resource:

```cel
destination_ip_class == 'public' && destination_role == ''
```

Example: alert when a Deployment's Pod starts an interactive shell, as reported by the [Falco plugin](../plugins/falco.md). Select `relationship:executes`, which fires when the Pod's `executes` lease to the `shell` process class first appears, or `telemetry:process-exec`:

```cel
process_class == 'shell'
```

Either fires once per Pod and lease lifetime, not once per shell; the raw sink keeps every alert.

Rules that need every raw request, property-only changes, or aggregation over a time window are not supported. They would need a separate telemetry trigger path.

> **Known gap: telemetry rules wait for a graph change.** Rules run only when detection has a change window to evaluate. Telemetry-only rollup updates create no change-feed event, except when a `communicates-with` edge appears or expires. A telemetry rule watching for a new operation or outcome on a pair that already communicates, such as a new `denied` response on an existing path, is therefore evaluated at the next unrelated graph change. If the rollup's 24-hour retention drops the combination first, it is never evaluated. Relationship rules, including `communicates-with`, are not affected. Waking detection when a rollup adds a new telemetry combination is planned follow-up work.

### Ruleset format

```json
{
  "id": "security/v2",
  "rules": [
    {
      "id": "istiod-unknown-public-destination",
      "revision": 1,
      "inputVersion": "v1",
      "pluginId": "*",
      "workloadResourceId": "<istiod Deployment resource ID>",
      "type": "relationship",
      "kind": "communicates-with",
      "expression": "destination_ip_class == 'public' && destination_role == ''",
      "risk": "medium",
      "reasons": ["control_plane_unknown_public_destination"],
      "windowSeconds": 300
    },
    {
      "id": "agentgateway-denied",
      "revision": 1,
      "inputVersion": "v1",
      "pluginId": "agentgateway",
      "type": "telemetry",
      "kind": "gateway-request",
      "expression": "outcome == 'denied'",
      "risk": "medium",
      "reasons": ["gateway_denied_response"],
      "windowSeconds": 60
    }
  ]
}
```

- `expression` must return a boolean.
- `risk` is `low`, `medium`, `high`, or `critical`. It becomes the severity of the rule's findings.
- `windowSeconds` is the half-width of the time window around the observation. `0` uses the detector default of 5 minutes. The maximum is 24 hours.

Signal IDs are derived from the input, the signal content, the rule revision, and the ruleset digest. Each evaluation records the ruleset ID, digest, and activation revision, and the Deployment rule digest, even when no rule matched.

### Rule findings

Every match of an active rule becomes a finding with `origin: detection_rule`, without a model call; the operator's activation or approval is the decision. All matches of one rule revision in one change window form one finding with category `detection_rule_match`, the rule's risk as severity, and the rule's ID and revision. The finding ID is derived from the rule, its signal IDs, and the graph digest, so a repeated window stores it once.

A rule finding records that the rule matched, which later graph changes do not make untrue, so it is never invalidated automatically. It stays active until an acknowledgement workflow exists. Rule signals are recorded in `detection_signals` as `rule_finding` and never sent to agentic investigation.

### Limits

256 rules per ruleset, 30,000 Deployment rules, 8 KiB per expression, 10,000 CEL cost units per evaluation of an expression, 64 KiB per input, 100,000 inputs per evaluation, 1,000 rule signals per evaluation, and 1-16 reasons of up to 128 bytes each. CEL has no I/O functions, and evaluation stops on cancellation.

A window over the input or signal limits does not fail. Inputs are evaluated in ID order up to the limit, oversized inputs are skipped, and signals past the limit are dropped. The counts are logged with the window, so a large rollout cannot stop detection. Deployment rules over their limit are not loaded: active rules are kept before shadow rules, then by rule ID, and `Engine.Status` counts the rest.

Do not put credentials or raw evidence into expressions, reasons, or test fixtures.

### Managing rulesets

PostgreSQL stores immutable rule revisions, immutable rulesets, an audited activation history, and one active pointer. Use the CLI or the state API (`SaveDetectorRuleset`, `ReadDetectorRuleset`, `ReadActiveDetectorRuleset`, `ActivateDetectorRuleset`), never direct SQL.

```bash
export AGENTSHIELD_DATABASE_URL=...   # prefer the environment over --database-url
go run ./cmd/agentshield rules validate --file rules.json
go run ./cmd/agentshield rules save --file rules.json --actor alice
go run ./cmd/agentshield rules show
go run ./cmd/agentshield rules show --id security/v2
go run ./cmd/agentshield rules activate --id security/v2 --expected-revision 1 --actor bob
```

The standalone `agentshield-detector-rules` binary remains as a compatibility
entry point; new workflows should use the `agentshield rules` subcommand.

- `validate` compiles every rule and prints the ruleset digest. It does not touch the database.
- `save` validates and stores the ruleset. It does not activate it. Saving the same ID and revision with different content is rejected; saving identical content again is a no-op.
- `show` prints the active ruleset and activation revision. `show --id` prints a saved ruleset.
- `activate` makes a saved ruleset active if the current activation revision equals `--expected-revision` (`0` means nothing is active yet). If someone else activated in between, it fails; read the current state before retrying.
- To roll back, activate an older saved ruleset. That creates a new activation revision.

A ruleset replaces the whole active ruleset. To keep shared rules, include them in the new set. An empty ruleset disables all CEL rules; the built-in checks still run.

`--actor` is recorded for audit. It is not authentication. There is no HTTP API for rule management. Model-written Deployment rules run in shadow mode until an operator approves them with `review`; they never become active on their own. Enforce the split between authors and approvers through database roles.

Inspect what the rules matched:

```bash
go run ./cmd/agentshield rules signals --limit 50
go run ./cmd/agentshield rules signals --investigation rule_finding
go run ./cmd/agentshield rules signals --investigation shadow --rule-id deployment/<resource-id>/rule-1
```

### Runtime behavior

Detection runs when `--agentic-investigation` or `--deployment-rule-authoring` is enabled; there is no detection-only mode. Startup saves and activates the empty ruleset `builtin/v1` if no ruleset is active, then loads the active ruleset and the Deployment rules. A ruleset that fails to compile at startup stops the process. Deployment rules never stop startup: an invalid rule is skipped and reported, and if they cannot be read, detection starts without them and the next reload retries.

The process polls the active ruleset and the Deployment rules every `--detector-reload-interval` (default 10 s). An unchanged activation is only checksum-checked. A new ruleset is compiled completely, then swapped in atomically; evaluations already running keep the ruleset they started with. If a reload fails (database error, checksum mismatch, compile error), the last good rules stay active and the failure is logged. `Engine.Status` exposes the last error and the active and shadow Deployment rule counts; it is not wired into `/readyz` yet.

If a rule fails at evaluation time, the error stops detection for that window only. The window is recorded as failed and logged with the error. It produces no signals or rule findings, and detection continues with the next window. Rule changes apply to future windows only. They do not re-evaluate history.

## Model-authored Deployment rules

For each Kubernetes Deployment Pod template revision, AgentShield can ask a model to draft up to three narrow CEL rules (`--deployment-rule-authoring`). It waits a baseline window first and drafts from the Deployment's [observed behavior](#observed-behavior), so the rules describe what this workload normally does. The draft runs in shadow mode at once, and an operator approves it to make it active. Authoring is its own queue with its own worker; running the rule is part of detection and makes no model call.

Rules written by an operator without a model, and built-in rules for sensitive destinations, are not supported yet.

### Trigger and queue

A revision is identified by the Kubernetes plugin's `kubernetes/pod-template-sha256` attribute: a digest of the Pod template's spec and labels. Annotations are excluded, so `kubectl rollout restart`, which only stamps one, is not a new revision; a new image, command, environment, or label is.

During publication (step 6 in [the publication transaction](publication-and-storage.md#the-publication-transaction)), the store checks each `kubernetes/deployment` in the newly compiled graph against `deployment_rule_jobs`. It queues one job per (resource ID, template digest) pair that has none:
- **A new Deployment:** queued. A deleted and recreated Deployment has a new UID, so it counts as new.
- **A changed Pod template:** queued, and queued or retryable jobs for the Deployment's other revisions are dropped, because they no longer describe what runs.
- **A return to an earlier revision that already has a job:** queues nothing.
- **Scaling, restarts, and assertions from other plugins:** queue nothing.

If the insert fails, the whole publication rolls back. Jobs created before revisions were tracked have an empty digest, so each existing Deployment is drafted once more after upgrading.

The job stores only the resource ID, kind, name, namespace, Pod template service account (`kubernetes/service-account-name`), and template digest, up to 16 KiB, and its SHA-256. Labels, images, environment, and volumes are never stored or sent.

### Worker

With `--deployment-rule-authoring` and a model endpoint (`--model-provider=anthropic` defaults it to `https://api.anthropic.com`), one worker per process:

1. Claims a job that is at least `--deployment-rule-baseline-window` old (default 6 h), with `FOR UPDATE SKIP LOCKED`; records a 30-second lease; and commits. The window starts when the revision appears, so a new revision is observed before it is drafted.
2. Reads the Deployment's [observed behavior](#observed-behavior) from the current graph. A failed read is retried like a failed model call.
3. Calls the model outside any transaction, renewing the lease while waiting. `--deployment-rule-authoring-timeout` (default 5 min, minimum 30 s) caps the call. A failed renewal is retried until the lease would expire; a lease taken over by another worker cancels the call at once.
4. Validates and stores the proposal, including the observed behavior it was drafted from, on the job.

The window is 0 to 24 h. Telemetry leaves the graph after 24 h, so a longer window would not lengthen the baseline. A short window drafts from little traffic. Behavior that appears only after the window, such as a daily job, is missing from the baseline, so the draft may flag it.

Failures are retried with exponential backoff, from 1 second up to about 4 minutes apart. After 8 attempts, or as soon as the model endpoint rejects the request as invalid (a 4xx status other than 408 or 429), the job is `failed` and is not retried; **Author now** queues it again with a fresh attempt count. A panic while authoring counts as a failed attempt. A job goes stale when its Deployment moves to another Pod template revision or leaves the graph: a stale job is deleted instead of being retried, and the claim deletes stale jobs before choosing one, so no model call is spent on a revision that no longer runs. The newer revision has its own job. Expired leases can be reclaimed after a crash. Without `--deployment-rule-authoring`, jobs stay queued. Authoring is not sampled or budgeted: each Pod template revision gets one draft, including every existing Deployment the first time AgentShield publishes the graph. The queue itself is safe for concurrent workers: leases keep two workers from claiming the same job. That does not make several `agentshield` processes on one database a supported setup; other components still assume a single process (see [Process requirements](../../deploy/kubernetes/README.md#process-requirements)).

Processing is at-least-once: a crash after the model answers but before the proposal is saved causes a second model call.

Job states are `queued`, `running`, `retryable`, `completed`, and `failed`. Inspect them with:

```bash
go run ./cmd/agentshield rules jobs
go run ./cmd/agentshield rules job --job-id 42
```

### What the model sees and returns

The request contains the Deployment's kind, name, namespace, service account, and [observed behavior](#observed-behavior); a neutral system prompt (`pkg/deploymentauthoring/authoring_prompt.txt`); and two tools, `add_rule` and `finish`. The template digest is not sent. Every turn must call a tool (OpenAI `tool_choice: required`, Anthropic `any`) and no response format is requested, so the model can act only through the tools and the request prefix stays identical across turns. The prompt:
- says drafts are inactive and reviewed by an operator
- asks for up to three rules that each detect a distinct behavior, with the narrowest useful expression and a list of expected false positives
- explains, in general terms, how to use a baseline and which deviations from it matter

It names no provider or field.

The model records each rule by calling `add_rule` with `selector`, `expression`, and `rationale`, then ends the run by calling `finish` with the overall `rationale`. A rule described only in the rationale is discarded, and `finish` without any added rule abstains. The `add_rule` input schema is generated from Go: `selector` is an enum of every `type:kind` pair from `detector.CELSelectors()`, or of the author's selector allowlist when one is set, and each selector's description lists its CEL variables and their values. The host sets the rule ID, plugin `*`, the `workloadResourceId`, risk `medium`, reason `workload_rule_match`, and a 300-second window. Rule IDs are `deployment/<resource ID>/template-<first 12 digest characters>/rule-<n>`, so each revision's rules are distinct.

`add_rule` validates the rule together with the rules already added: selector, scoping, CEL compilation, the three-rule limit, and a repeat of an added rule's selector and expression. It returns `added` with the remaining count, or the validation error. A rejected rule is not recorded, so the model can correct it and add it again; an accepted rule cannot be withdrawn. It does not evaluate sample inputs. The proposal is built from the accepted rules only after `finish` succeeds; a run that fails or exceeds its limits stores nothing, and the job retries. The loop is limited to 8 turns, 6 `add_rule` calls plus `finish` (the last turn forces `finish`), 2 KiB per tool argument and result, and 12 KiB of tool results in total. Proposals are capped at 256 KiB. A proposal with no rule is a valid answer.

OpenAI is the default provider and uses the Responses API. `--model-provider=anthropic` uses Anthropic's Messages API; because Anthropic does not accept JSON Schema length and count keywords, the adapter moves them into descriptions and the host still enforces them.

The model has no access to the database, the graph, or rule activation. Deployment names, namespaces, service accounts, and observed request paths are sent to the configured model endpoint.

### Observed behavior

The authoring context has an optional `observedBehavior` field: a baseline of the Deployment's own outbound requests. `state.DeploymentBehaviorFor` builds it from a graph snapshot. It covers the telemetry whose subject is the Deployment and, for each distinct telemetry kind, destination, operation, and outcome, records the event count. Within that:

- **Destinations:** Kubernetes destinations are named as `namespace/name`. Others are described by kind and network role only, never by address.
- **Operations:** query strings and fragments are removed, and path segments that look like identifiers (all digits, or 16 or more hex characters and dashes, such as a UUID) become `{id}`. Rules still evaluate raw operations.
- **Size:** at most 32 requests, keeping the most frequent and marking the profile `truncated`.
- **Collected telemetry:** `collectedTelemetry` lists up to 16 telemetry kinds observed anywhere in the graph. It tells the author which selectors have a producer, so "made no requests" can be told apart from "not visible". It is cluster-wide: a workload outside the mesh can look silent, but then a rule written for it has no input to fire on.

An empty request list means the Deployment made no outbound requests of the collected kinds during the baseline. The authoring worker always sets the field; `agentshield-deployment-author` accepts it in its input file, and a context without it is drafted from identity alone.

Request paths, after normalization, go to the model endpoint. They can still carry identifiers that do not match the patterns above, such as names or emails.

### Trying the author without a cluster

`cmd/agentshield-deployment-author` runs the same author against a local JSON file. It does not open PostgreSQL or activate anything. Start from `examples/deployment-authoring-context.json` or `examples/istiod-authoring-context.json`.

Print the exact first request body without calling a model (no credentials needed):

```bash
go run ./cmd/agentshield-deployment-author --input examples/deployment-authoring-context.json --dry-run
```

Call OpenAI:

```bash
export AGENTSHIELD_MODEL_ENDPOINT=https://api.openai.com
export OPENAI_API_KEY=...
go run ./cmd/agentshield-deployment-author --input examples/deployment-authoring-context.json > proposal.json
```

Call Anthropic (default model `claude-sonnet-4-6`):

```bash
export ANTHROPIC_API_KEY=...
go run ./cmd/agentshield-deployment-author --input examples/deployment-authoring-context.json --model-provider anthropic > proposal.json
```

Add `--verbose` to log each `add_rule` call (selector, expression, and whether it was added or why it was rejected) and a summary of `add_rule` calls and accepted rules to stderr.

The command prints one validated proposal. A run that never calls `finish` within its limits, or a model turn without a tool call, exits non-zero. All flags are in [Configuration](../operations/configuration.md#agentshield-deployment-author).

### Running and reviewing Deployment rules

When detection runs, the engine loads Deployment rules as a workload rule overlay, indexed by Deployment. The publication step marks the job for the Pod template revision each Deployment runs now, so loading follows rollouts and rollbacks. For each Deployment still in the graph, it loads at most two completed proposals:
- **Active:** the current revision's rule if it is approved. Otherwise the newest approved rule of another revision.
- **Shadow:** the current revision's draft while it is pending.

An approved rule therefore keeps running after a template change until the new revision's draft is approved. Approving the new draft retires the older rule; rejecting it leaves the older rule in place. Rolling back to a revision with an approved rule makes that rule active again. Each rule is evaluated only against inputs whose subject is its Deployment or a Pod connected to it by a resolved `instantiates` edge, so cost does not grow with the number of Deployments. A rule describes what the Deployment itself does, so an input where it is only the object, such as a new client calling it, never matches. An operator rule's `workloadResourceId` still matches either endpoint. A rule that does not compile, or a duplicate rule ID, is skipped and counted in `Engine.Status`, and the rest of the overlay still loads. The overlay reloads every `--detector-reload-interval`; removing a Deployment unloads its rules.

The job's review status decides the mode:

| Review status | Mode | Effect of a match |
| --- | --- | --- |
| `pending` (default) | shadow | Recorded in `detection_signals` as `shadow` only |
| `approved` | active | Becomes a [rule finding](#rule-findings); no model call |
| `rejected` | not loaded | None |

Shadow mode lets a draft collect match evidence for review without letting an unreviewed model-written rule create findings.

In the [rule eval suite](../../evals/README.md#rule-evals), drafts written this way caught all four attacks and kept all five benign campaigns quiet, the same as the suite's operator-written policies. Each draft was also correct when replayed against every other campaign for its workload. The drafts were operation allowlists combined with `outcome == 'denied'`, or `true` for a workload that made no requests.

Drafting from identity alone (name, namespace, and service account) caught none of the four attacks. The author fell back to generic "public egress" or "control-plane API" rules. Two things mattered:
- **A baseline that covers the workload's routine calls.** After a one-request baseline, drafts were too narrow or too broad.
- **Visible telemetry collection.** In a cluster with no other traffic, the author could not tell a silent workload from missing coverage.

Results come from one run of nine campaigns, so review each draft against what the workload actually calls.

```bash
go run ./cmd/agentshield rules jobs
go run ./cmd/agentshield rules job --job-id 42
go run ./cmd/agentshield rules signals --rule-id deployment/<resource-id>/template-<digest prefix>/rule-1
go run ./cmd/agentshield rules review --job-id 42 --decision approved --actor alice
go run ./cmd/agentshield rules workload-rules
```

`review` accepts `approved` or `rejected` for a completed job and can change an earlier decision. To change a rule, reject it and add a replacement to a CEL ruleset; drafts are not edited in place.

### Reviewing and regenerating over HTTP

The web UI's Rules view and a Deployment's Inspector panel use these routes:

| Route | Purpose |
| --- | --- |
| `GET /api/v1/rules` | The active operator ruleset (`activation` is null when none is active) and the loaded workload rules with their mode (`active` or `shadow`) |
| `GET /api/v1/rule-drafts` | Up to 500 jobs, newest first, each with its review status, rule count, requester, and whether it is for the Deployment's current revision |
| `GET /api/v1/rule-drafts/{id}` | One job and, once completed, its proposal: rationale, rules, and `add_rule`/`finish` trace |
| `POST /api/v1/rule-drafts/{id}/review` | `{"decision":"approved"}` or `"rejected"`; same rules as `rules review`. `409` when the job is not completed |
| `POST /api/v1/workloads/{id}/rule-drafts` | Author the Deployment's current Pod template revision now; `202` with the job, `409` with the job while a worker is authoring it, `404` when the Deployment has no job for its current revision |

A queued or retrying job is woken: it skips the baseline wait and any retry backoff, and the next worker poll claims it. The UI offers this as **Author now**. A completed job is regenerated in place: its proposal and review are dropped and the job is queued again, skipping the baseline wait. Until the new draft is approved, its rules run in shadow mode, so a previously approved draft for that revision stops creating findings. Decisions and requests are recorded with the actor `api/web-ui`, which is audit metadata, not an identity.

The two `POST` routes change detection and call the model, and the API is unauthenticated. They are served on a loopback listener; on any other listener they return `503` unless `--rule-review-api` is set. Set it only behind an authenticating proxy or in a disposable environment such as the eval cluster. See [Security model](../operations/security-model.md).
