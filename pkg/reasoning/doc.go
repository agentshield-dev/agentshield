// Package reasoning turns committed graph changes into signals and
// evidence-backed findings, in two independent stages: deterministic detection
// and agentic investigation.
//
// The model is an advisory investigator. This package stays authoritative for
// which graph state is analyzed, what the model may see and retrieve, which
// references a response may cite, and whether a response becomes a finding.
//
// # Pipeline
//
// [Service.Run] is detection. It consumes the contribution change outbox
// written by pkg/state, processes one window at a time, and never calls a
// model:
//
//  1. [ReadChangeWindow] reads a contiguous batch of
//     [state.ContributionChangeEvent] values after the durable cursor, plus
//     the coherent [state.GraphCheckpoint] that contains them. A sequence gap,
//     or a batch that does not reach the checkpoint, is never filled by
//     inference: the window is marked as a rebase to the checkpoint instead.
//  2. A [detector.Detector] compares the previous and current snapshots and
//     emits neutral [detector.InvestigationSignal] values. The window's
//     signals are split by origin: active rule matches, shadow rule matches,
//     and built-in novelty signals.
//  3. [IncidentHistory] accumulates bounded telemetry baselines and an ordered
//     timeline across windows; [IncidentContext] is the pinned view of it.
//  4. When a novelty signal is medium risk or higher, the window yields an
//     [InvestigationRequest]: the change range, novelty signals, topology
//     classification, and incident context scoped to the signals' anchors.
//  5. The [ResultSink] values record the [Evaluation]: [FindingSink] stores
//     [RuleFindings] and invalidates agentic findings grounded in a superseded
//     graph digest, [SignalSink] records every signal, and [InvestigationQueue]
//     enqueues the request, coalescing it with queued requests that share an
//     anchor. Only then does the cursor advance.
//
// [InvestigationWorker] is agentic investigation. It drains the queue
// independently, so a model failure retries a job instead of stopping
// detection:
//
//  1. Claim the highest-risk job, drop anchors that left the graph, and apply
//     the [SamplingPolicy]: deterministic rate sampling of medium risk,
//     deduplication, and an hourly budget.
//  2. Re-read the request's change range and build the canonical [Packet]
//     against the current checkpoint. Its AnalysisID is the SHA-256 of its
//     canonical encoding, so identical inputs analyze identically.
//  3. An [Analyzer] (normally pkg/reasoning/modelanalyzer) runs
//     [AnalyzeCandidateWithTools]. The model retrieves more context through the
//     read-only MCP tools in pkg/reasoning/mcpserver, each answered by a
//     [ContextProvider] pinned to the packet's [AnalysisToken].
//  4. [ValidateClassification] checks the response against the effective
//     packet, with one tool-free repair turn. [Promote] then applies the
//     stricter promotion gate.
//  5. [FindingSink.RecordInvestigation] persists a promoted finding with
//     hydrated remediation proposals, and the worker invalidates it at once if
//     changes committed during the model call touched its entities.
//
// [Service.EvaluateWindow] and [Service.EvaluateWindowWithIncident] run
// detection and then the same [Investigator] inline, for evaluation harnesses.
//
// Remediation is not part of this pipeline. Reasoning may attach validated
// [remediation.Suggestion] values to a promoted finding, but it never selects a
// provider or plans, prepares, executes, or verifies an action; see
// pkg/remediation and pkg/api.
//
// # What reaches the model
//
// The initial packet contains no telemetry facts, provider-native
// configuration, candidate paths, or fixture labels. Packet and context
// construction additionally:
//
//   - replaces evidence IDs with opaque "evidence:sha256:" handles;
//   - drops resource and facet attributes whose key suggests credentials
//     (password, token, authorization, cookie, API or access key, private key)
//     and bounds attribute and name counts and lengths;
//   - forwards only an allowlist of telemetry properties; and
//   - omits telemetry assertion changes from the trigger window.
//
// Eval campaign expectations live in the evals scorer and are never supplied to
// the model. Graph strings are untrusted data; [SystemPrompt] says so, and
// validation never relies on the model having obeyed it.
//
// # Invariants
//
//   - Every retrieval is pinned to one analysis ID and graph digest; a query
//     with another token is rejected.
//   - A candidate that relied on truncated retrieval is rejected, because
//     absence cannot be inferred from a partial view.
//   - Finding identity is a digest of the promoted signal IDs and graph digest,
//     so replaying an evaluation is idempotent.
//   - The cursor advances only after the sinks record the evaluation.
//   - Detection never calls a model; rule findings never depend on one.
//
// See https://agent-shield.dev/docs/architecture/change-feed-and-reasoning/ for
// the design and https://agent-shield.dev/docs/operations/configuration/ for
// runtime flags.
package reasoning
