// Package deploymentauthoring drafts workload-scoped detector rules for newly
// observed Kubernetes Deployments.
//
// Graph publication enqueues one durable job, in the same transaction, the
// first time a Deployment resource appears (see pkg/state). A [Worker] claims
// jobs under a renewable lease, calls an [Author] outside any database
// transaction, and stores the resulting [Proposal] on the job. Failures are
// retried with bounded exponential backoff, and an expired lease is
// reclaimable after a crash. Processing is at least once: a crash after the
// model responds but before the proposal commits causes another model call.
//
// # Model boundary
//
// [ModelAuthor] sends only the workload's kind, name, namespace, service
// account, and observed-behavior baseline. Labels, images, environment,
// volumes, and the rest of the spec are never stored on the job or sent. The model chooses only a selector,
// expression, and rationale for each of up to three rules; the host sets the
// rule ID, plugin wildcard, workload scope, risk, reason, and window. Every
// model turn must call a tool: add_rule validates a rule against the rules
// already added and records it, and finish ends the run with the overall
// rationale. Validation never evaluates synthetic inputs, and the proposal is
// built only from accepted rules after finish succeeds.
//
// Drafts never change the active ruleset. pkg/detector loads them as workload
// rules in shadow mode, where matches are only recorded, until an operator
// approves the job (state.Store.ReviewDeploymentRuleJob); approved rules run in
// active mode and their matches become findings. The model has no database,
// graph-publication, or review access, and nothing in this package approves
// rules. Running a rule never calls a model. See
// docs/architecture/detection-rules.md.
package deploymentauthoring
