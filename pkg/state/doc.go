// Package state is AgentShield's PostgreSQL store: contribution publication,
// the current graph, the change feed, findings, detection signals, the
// investigation queue, and detector persistence.
//
// # Pipeline position
//
// Discovery plugins and the telemetry rollup produce complete contributions.
// [Store.ReplaceContribution] validates each one with the graph compiler and
// publishes it in one transaction. Publication appends to a transactional
// outbox that the detection service reads with
// [Store.ReadContributionChanges] and [Store.ReadGraphCheckpoint]; detection
// then records [DetectionSignal] values and rule [Finding] values, enqueues
// investigation jobs, and advances a [ReasoningCursor]. The investigation
// worker claims and admits jobs ([Store.ClaimInvestigationJob],
// [Store.AdmitInvestigationJob]) and records agentic findings. Detector
// rulesets, Deployment rule-authoring jobs, and their review status
// ([Store.ReadWorkloadRules]) are stored here as well.
//
// # Contributions and generations
//
// A [Contribution] is the complete assertion set owned by one
// (plugin, source, name) tuple. Each publication is a new generation;
// assertions omitted from it are retracted. Generations must increase: an
// older generation is rejected, the same generation with the same input
// digest is an idempotent retry, and the same generation with a different
// digest is an error. [Store.ContributionGeneration] lets a restarted plugin
// resume above its last durable generation.
//
// # Publication
//
// Publication builds a complete candidate from the revision-validated
// in-memory graph, then uses a compare-and-swap transaction to persist
// content-addressed assertions, advance the contribution head, update active
// membership and affected projection rows, and append at most one outbox
// event. Readers never see a partially published contribution.
//
// # Change feed
//
// Each outbox event carries a monotonic sequence and the non-telemetry
// assertions added and retracted by one contribution version. Telemetry-only
// publications that do not change readiness, health, or status are committed
// without an outbox event, so telemetry cadence does not drive detection.
//
// # Reads
//
// [Store.Latest] and [Store.ReadGraphCheckpoint] read the active assertion
// union inside a repeatable-read transaction and compile it after the
// transaction ends, so the returned graph and its SHA-256 are coherent with
// each other and with the checkpoint sequence. [Store.CreateManifest] pins the active contribution versions for
// reproducible analysis.
//
// Schema files are embedded and verified by checksum at startup. Until the
// first release, baseline changes require recreating the database.
//
// See docs/architecture/publication-and-storage.md and
// docs/concepts/data-model.md.
package state
