# Evaluation suite

These evals measure whether AgentShield catches lateral movement without alerting on benign changes. Six longitudinal campaigns pair attacks and controls for a compromised application reaching a secrets manager, a compromised hosted ML workspace build worker reading workspace secrets, and a compromised single sign-on server enumerating private source repositories.

Each campaign records baseline and observed traffic from the disposable cluster. Scoring starts only after the exact plugin-produced observation reaches the graph; synthetic telemetry is rejected. Expected outcomes stay in the scorer and never enter the model context.

The runner uses the production detection service and investigator with a compact initial packet and a pinned MCP graph view. It investigates each observed window inline, so production batching and sampling do not apply. Model-selected MCP calls are uncapped, but each result remains bounded. `untruncated` means every matching fact in that pinned view fit within the query bounds; it does not claim that provider observation is complete. Truncated context cannot support promotion.

## Run

Create the disposable cluster, verify it, and run all campaigns with `gpt-6-astra`:

```bash
make eval-up
make eval-check
make eval-run
```

Run selected campaigns or the model matrix:

```bash
evals/scripts/eval-run.sh --campaigns identity-provider-to-source-control,governed-repository-inventory
make eval-matrix
```

`eval-matrix.sh` uses the Responses API with low reasoning effort. It compares model-selected and deterministic retrieval on `gpt-5-mini`, then tests deterministic retrieval on `gpt-5.4-nano`, `gpt-6-luna`, `gpt-5.6-sol`, and `gpt-6-astra`.

Delete the cluster with `make eval-down`. The script verifies local and in-cluster ownership first.

`make eval-run` makes real model calls through the in-cluster agentgateway, which is billed to `OPENAI_API_KEY`. External contributors are not expected to run it; maintainers run it for Kubernetes and Istio projector changes.

The in-cluster AgentShield also runs Deployment rule authoring (`--deployment-rule-authoring`) against OpenAI with the same key, which `make eval-up` stores in the `agentshield-model` Secret. Drafts start after a 10-minute baseline window instead of the 6-hour default. `--rule-review-api` serves the unauthenticated rule review and regenerate routes on the cluster listener so the UI's Rules view works through `kubectl port-forward`. Detector-only runs leave both out.

`make eval-up` also installs Falco (chart 9.2.1, image `0.45.1`, the oldest that works on recent host kernels, unless `FALCO_IMAGE_TAG` overrides it) with [falco-values.yaml](config/falco-values.yaml). It posts alerts to the collector's `webhook_event` receiver, which forwards them to AgentShield as `process-exec` telemetry; see the [Falco plugin](https://agent-shield.dev/docs/plugins/falco/). To try it, open a shell in a Pod, for example `kubectl exec -it deploy/<name> -- sh`, and the Pod gains an `executes` edge to the `shell` process class. [Tracing a shell alert](https://agent-shield.dev/docs/plugins/falco/#tracing-a-shell-alert) shows where each step appears.

## Detector-only runs

Detector-only mode measures deterministic detection without agentgateway, an API key, or model calls. It also lets `make eval-up` run without `OPENAI_API_KEY`; rerun `make eval-up` with the key before a model run.

```bash
AGENTSHIELD_EVAL_DETECTOR_ONLY=1 make eval-up
AGENTSHIELD_EVAL_DETECTOR_ONLY=1 make eval-run
```

Use it for built-in detector changes. A detector change should keep `detection.securityPathRecall` at 1 and should not add agent invocations to the `setup` or `baseline` phases, which contain only expected operational change. Then confirm with a model run.

## Rule evals

The rule suite (`make eval-rules`, or `evals/scripts/eval-run.sh --suite rules`) scores the deterministic rules engine. It is separate from the mission campaigns above, which measure agentic investigation and predate detection rules. Its campaigns, in [`rule-campaigns.json`](rule-campaigns.json), are built around the inputs rules evaluate. Each deploys a source workload whose name implies a narrow role, plus the services it calls, then runs baseline actions (the source's routine calls) and observed actions:

- `request`: an HTTP request from the source to a target, checked against an expected status. Waypoint access logs record it as `active-probe` telemetry with operation `METHOD path` and outcome `allowed` or `denied`. A target's `denyPaths` become an Istio AuthorizationPolicy, so a denied request is a real 403 from the mesh.
- `restart`: a routine rollout of the source, which creates new Pods and edges but no new behavior.

Before the first campaign, the runner deploys a background namespace in the mesh, `aseval-<id>` for the runtime ID of `rule/background`. In it, three clients call three services every few seconds. The runner waits until that namespace's telemetry is in the graph and deletes the namespace after the suite. This gives every baseline a cluster where telemetry is visibly collected, as in production. Rules are scoped to each campaign's source, so background traffic cannot produce rule findings.

The catalog covers four kinds of attack, each paired with benign controls:
- a request outside the workload's API surface
- a write by a read-only workload
- a request the mesh denies
- any outbound call from a workload that should make none

Two rule sources are scored per campaign:

- **`policy`**: the campaign's `policies`, operator-written CEL rules for the source workload, run as the active ruleset. This checks that rule execution works end to end on live telemetry: selectors, the operation and outcome vocabulary, workload scoping, telemetry and edge novelty, and rule-finding construction. It runs in every mode, including detector-only.
- **`authored`**: at the end of the baseline phase, the production Deployment rule author drafts a rule from the context the authoring worker builds once the baseline window has passed. That context is the queued identity plus the [observed behavior](https://agent-shield.dev/docs/architecture/detection-rules/#observed-behavior) read from the current graph through `deploymentauthoring.WithBaseline`. The draft runs as an approved Deployment rule. This measures whether automated rule authoring catches the attack. It needs a model, so it is skipped in detector-only runs. The report records the observed behavior the author saw.

Rules run over the `setup`, `baseline`, and `observed` windows. A security campaign is a true positive when a rule finding in the observed window is anchored to the source and its last observed target. A benign campaign is a true negative when no rule fires in any window. A rule finding in the `setup` or `baseline` window is a false alarm on expected activity and fails the campaign's rule expectation even when the observed window is scored correctly. An authored rule that cannot fire in this environment, for example a `network-flow` rule where nothing produces flows, scores as a true negative on benign campaigns, so read benign authored results together with the security recall.

`--author-selectors` (or `AGENTSHIELD_EVAL_AUTHOR_SELECTORS`) restricts the selectors offered to the author, for example to the selectors this environment has producers for: every `relationship:*` selector and `telemetry:active-probe`. The summary records the list in `authorSelectors`.

`TestRulePoliciesMatchTheirCampaignIntent` replays every campaign's requests through the detector offline before a run: no policy may match baseline activity, and a policy must match observed activity exactly for security campaigns. When you add a campaign, give it a policy that passes that test.

Each rule run writes `campaigns/<campaign-id>.json` and `summary.json` to the artifact directory, like a mission run. A report has a `rules` array with one entry per rule source, listing the rules (and, for `authored`, the author's rationale, observed behavior, or error), the rule signals and findings per window, `observedPathMatch`, `normalPhaseFindings`, `outcome`, and `matchesExpectation`. The summary's `rules` section reports, per rule source, true and false positives and negatives, `securityRecall`, `benignSpecificity`, `normalPhaseFindings`, `abstentions` (the author returned no rule), and `errors`.

## What a run produces

Each run writes to `evals/output/<UTC timestamp>/` (override with `EVAL_ARTIFACT_DIR`):

- `campaigns/<campaign-id>.json`: one report per campaign. It holds the campaign definition, each phase's observation evidence and graph checkpoint, the detector signals, the model's retrievals and assessment, the promotion decision, token usage, model latency, and `matchesExpectation` (whether the decision, and for security campaigns the finding category, matched the expected outcome). If the campaign failed, `error` says why.
- Every report also has a `detection` array with one entry per phase: `setup` (deploying the campaign workloads until the graph is quiet, capped at one minute and marked `unsettled` if the graph kept changing), `baseline` (the source's first call), and `observed` (the scored window). Each entry lists the detector signals, how many are eligible for investigation, whether the window would invoke agentic investigation, and, for `observed`, whether an eligible signal is anchored to both observed endpoints (`pathSignal`).
- `summary.json`: the aggregate, written only when every campaign completed. Its `detection` section reports per-phase windows with signals, agent invocations, and signal counts, and `securityPathRecall`: the share of security campaigns whose observed window has an eligible signal on the observed path. Promotion is impossible without one. The summary counts decisions only, not categories: a security campaign that produced a promoted finding counts as a true positive, otherwise a false negative; a benign campaign that produced a finding counts as a false positive, otherwise a true negative. From these it reports `securityRecall` (true positives over security campaigns) and `benignSpecificity` (true negatives over benign campaigns), plus total token usage and model latency.
- `postgres-port-forward.log`: the port-forward the runner uses to reach the in-cluster database.

The run stops at the first campaign that fails. That campaign's report records the error and no `summary.json` is written, so an observation failure makes the run incomplete instead of counting as a model miss.

`make eval-matrix` writes one subdirectory per variant under `evals/output/<UTC timestamp>-matrix/` (override with `EVAL_MATRIX_DIR`) and combines their summaries into a top-level `summary.json`.

To reproduce a result, run the same commit against a fresh `make eval-up` cluster with the same model and retrieval mode; both are recorded in every report and summary. Model output is not deterministic, so expect some run-to-run variation.
