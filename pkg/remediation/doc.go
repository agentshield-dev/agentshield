// Package remediation defines the contract for turning a promoted finding's
// remediation suggestion into an explicitly approved provider action.
//
// Discovery observes; remediation acts. The two are separate host capabilities,
// and nothing in this package travels through discovery collections, graph
// contributions, or the reasoning outbox.
//
// # Lifecycle
//
//  1. Reasoning validates up to [MaxSuggestions] [Suggestion] values per
//     finding. A suggestion names a desired outcome ([Intent]) and one target
//     entity, never a plugin, payload, or command.
//  2. The host hydrates each suggestion into a [Proposal] bound to the finding,
//     analysis, graph digest, canonical target identity, and evidence. Proposal
//     IDs are content digests, so a proposal cannot be altered without changing
//     its ID.
//  3. [Registry.Candidates] lists every registered provider action that can
//     implement the proposal's intent for its target kind, identity scheme,
//     and authority. The user picks one.
//  4. [Executor.Plan] resolves current provider state into a [Plan] with a
//     digest of the desired state. Advisory-only actions stop here.
//  5. [Executor.Prepare] has the provider check every intended write (for
//     Kubernetes, with admission dry-run) and capture bounded canonical
//     [ProviderState] for later comparison.
//  6. [Executor.Execute] requires an approval string equal to the exact plan
//     ID and a recorded successful preparation for that plan. Providers
//     re-read the prepared observations and fail if they changed.
//  7. [Executor.Verify] re-reads the declared configuration.
//
// # Safety model
//
//   - Nothing executes without explicit approval of one prepared plan.
//     Reasoning, finding persistence, discovery, candidate enumeration,
//     planning, and preparation never apply a proposal.
//   - Plan, preparation, and execution result IDs are digests of their
//     content and are rechecked at every step, so a provider or caller cannot
//     substitute a different plan, preparation, or result.
//   - The target is checked against the current graph before planning,
//     preparation, and execution. A target that is gone, has changed kind, or
//     has conflicting kinds stops the action. The finding's graph digest is
//     audit context, not an execution lock, so unrelated graph churn does not
//     block remediation.
//   - Execution is single-flight per plan: concurrent approvals wait for the
//     first, and a successful result is returned again instead of re-running.
//   - A satisfied [Verification] proves the declared configuration is present.
//     It does not prove controller acceptance, dataplane rollout, or effective
//     enforcement.
//   - Preparations and execution state are held in memory by one [Executor].
//     A restart requires preparing again, and replicas do not coordinate.
//   - Provider credentials and permissions stay in host configuration and
//     never appear in suggestions, proposals, or plans.
//
// The HTTP surface for this lifecycle is in pkg/api. Its routes are always
// registered but return 503 unless live discovery runs on a loopback
// listener. See docs/architecture/remediation.md and
// docs/operations/security-model.md.
package remediation
