// Package detector turns graph changes into investigation signals.
//
// It sits between the change feed and pkg/reasoning, which hands it the
// previous and current canonical snapshots for a change window. It returns
// [InvestigationSignal] values. pkg/reasoning turns an active rule's signal
// into a finding directly, queues built-in novelty signals for agentic
// investigation, and only records shadow rule signals (marked
// [RuleModeShadow]).
//
// The detector reads only provider-neutral graph data: resolved relationships,
// typed [graph.SecuritySemantics], network roles, and bounded telemetry
// fingerprints. It never parses provider-native payloads or opens provider
// watches.
//
// # Signal sources
//
// [Engine.Detect] combines three sources and deduplicates them by signal ID:
//
//   - Built-in novelty ([DetectNovelChanges]): new workload-level
//     communication paths, scored telemetry novelty, new external exposure,
//     changed or removed security semantics, lost governance, sensitive
//     resource creation, and workload identity changes. Instances are folded
//     into the controller that instantiates them, so rollouts and scaling are
//     not novel, and ordinary graph churn emits nothing. See [Config] for the
//     scoring.
//   - CEL rules from the active [Ruleset]. [Events] derives one [Event] per new
//     or newly resolved relationship edge and per newly observed telemetry
//     combination; [Engine.Evaluate] matches each against rules selected by
//     plugin, input type, kind, and optional workload. Each (type, kind)
//     selector compiles in its own CEL environment that declares only the
//     [Input] fields that selector populates, so a rule that reads an unset
//     field fails to compile instead of silently never matching.
//   - Workload rules ([WorkloadRule]), such as model-authored Deployment rules,
//     indexed by workload so each input is matched only against the rules of
//     the workload that is its subject ([Event.SubjectIDs]); a workload's
//     rules never match inputs where it is only the object. Each runs in
//     [RuleModeActive] or [RuleModeShadow].
//
// # Rulesets and reload
//
// A compiled ruleset is immutable. [Engine.Reload] compiles a newly activated
// ruleset completely before swapping it in atomically, so every evaluation
// runs against exactly one pinned ruleset and records its ID, digest, and
// activation revision. A reload failure keeps the last known-good ruleset and
// is reported through [Engine.Status]. Invalid workload rules are skipped and
// counted rather than unloading the whole overlay. Evaluation errors are
// returned, never treated as "no match", so reasoning records the window as
// failed instead of claiming it was evaluated.
//
// # Bounds
//
// Rulesets hold at most 256 rules and the workload overlay at most
// [MaxWorkloadRules]. Expressions are at most 8 KiB and 10,000
// CEL cost units, with no host I/O functions. An evaluation reads at most
// [MaxEvaluationEvents] inputs of 64 KiB each and emits at most
// [MaxEvaluationSignals] rule signals; the rest are counted in
// [Result.Omitted] rather than failing the evaluation. Raw IP
// addresses are never exposed to CEL; only their [telemetry] destination class
// is.
//
// See docs/architecture/detection-rules.md for rule authoring and storage.
package detector
