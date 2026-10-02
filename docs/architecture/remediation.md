# Remediation

A finding can suggest ways to fix what it found. Remediation turns one of those suggestions into a provider change, but only through explicit user steps: choose an action, prepare it (plan plus dry-run), review it, and approve it. Nothing in discovery, detection, or reasoning ever applies a change.

Code: `pkg/remediation` (types, registry, executor), `pkg/api/remediations.go` (HTTP), and each provider's `remediation.go` in `plugins/kubernetes`, `plugins/cilium`, and `plugins/istio`.

## From suggestion to action

1. **Suggestion.** The model may attach up to eight suggestions to a candidate finding. Each names a provider-neutral *outcome* and one target resource, and cites the same evidence as a validated claim. See [Change feed and reasoning](change-feed-and-reasoning.md#remediation-suggestions).
2. **Proposal.** When a finding is promoted, each valid suggestion becomes a *proposal* stored on the finding: finding ID, analysis ID, graph digest, target resource ID, identity and kind, and supporting fact and evidence IDs.
3. **Candidates.** The UI asks the live plugin registry which actions can implement a proposal (`GET .../candidates`). Several plugins, or several configured sources of one plugin, may offer actions for the same outcome. The user picks one.
4. **Prepare.** `POST .../prepare` plans and dry-runs the chosen action. Nothing is written.
5. **Approve.** `POST .../approve` with the plan ID executes the prepared action and verifies the result. See [Approval outcomes](#approval-outcomes).

The browser only ever sends IDs and a selection. It never sends a proposal or provider payload; the server uses the proposals it stored.

## Outcomes and actions

| Outcome | Provider | Action ID | Target | What it writes |
| --- | --- | --- | --- | --- |
| `network.declare-ingress-isolation` | `kubernetes` | `network-policy/v1` | `kubernetes/pod` | A Pod label plus a NetworkPolicy that isolates ingress to that Pod |
| `network.declare-ingress-isolation` | `kubernetes` | `service-network-policy/v1` | `kubernetes/service` | A NetworkPolicy that isolates ingress to Pods selected by that Service |
| `network.declare-ingress-isolation` | `cilium` | `cilium-network-policy/v1` | `kubernetes/pod` | A Pod label plus an ingress-isolating CiliumNetworkPolicy |
| `transport.require-mutual-tls` | `istio` | `peer-authentication/v1` | `kubernetes/pod` | A Pod label plus a `STRICT` PeerAuthentication |

`gateway.prevent-route-delivery` is a valid outcome, but no plugin implements it yet, so it has no candidates.

A plugin offers actions by implementing `discovery.RemediationProvider`. The discovery manager registers remediation providers separately from discovery, keyed by plugin and source. Remediation state never travels through collections, contributions, or the change feed.

## Stages

- **Plan** reads current provider state and returns the deterministic desired state.
- **Prepare** is required before execution. Kubernetes-backed providers run a server-side dry-run (`dryRun=All`) of every intended write and record the current and admitted state of the fields they control.
- **Execute** re-reads that state, stops if it changed, and performs the writes. If the policy write fails, or a conflict appears after the label is written, it tries to remove the new Pod label again. The rollback runs on its own 30-second deadline, detached from the execution context, so it still runs when execution was canceled or timed out.
- **Verify** re-reads the provider objects and compares them with the execution result.

The Pod actions of all three providers share one implementation of these stages, `PodPolicyAction` in `plugins/kubernetes/pod_remediation.go`. Each provider supplies only its policy object, its digest of the controlled fields, and its conflict check.

### Approval outcomes

Execution and verification run detached from the HTTP request, with a two-minute deadline, so a client that disconnects cannot cancel a write or its rollback partway through.

- If execution fails, the response is `409` and the provider was not changed, or the error says that the label rollback failed.
- If execution succeeds, the server records the result on the prepared session before it verifies. When verification then fails or is not satisfied, the response is still `200`, because the provider was changed. It carries the execution result, `verification.satisfied: false`, and a `verificationError`.
- Approving the same plan again never executes again. It returns the recorded verified result, or re-runs only verification.

### What verification proves

A successful verification proves that the declared policy and any target label required by the action exist. It does not prove that a controller accepted the policy, that the dataplane enforces it, that traffic is denied, or that traffic is encrypted.

### Conflicts

Providers check for overlapping policies using the labels selected by the target Pod or Service:

- Kubernetes checks NetworkPolicies.
- Cilium checks NetworkPolicies, CiliumNetworkPolicies, and CiliumClusterwideNetworkPolicies, including `spec`, `specs`, `matchLabels`, and `matchExpressions`.
- Istio checks PeerAuthentications. An AuthorizationPolicy on the same workload is not a conflict.

Each provider checks before writing and actions that label a target check again after the label write. Malformed selectors and list or RBAC errors fail closed. An existing policy with the expected name is reused only if its target and controlled content match exactly; otherwise it is treated as a collision.

## Staleness

A finding records what reasoning saw; later graph changes do not delete it. Its graph digest is audit context, not a lock, so unrelated graph changes do not block a remediation.

Each stage checks current state instead. An action stops if the target resource is gone, changed kind, has a kind conflict, or if provider state no longer matches what was prepared. The UI shows the failure on the remediation and keeps the finding.

A finding that was invalidated by a later change to its affected resources cannot start a remediation.

## Operational limits

- Live remediation needs discovery and a loopback listener; otherwise its endpoints return `503` while findings and the graph are still served. See the [security model](../operations/security-model.md#the-http-api-has-no-authentication).
- Prepared actions and approval outcomes live in process memory. They do not expire on a timer, but a restart discards them; prepare again after a restart. Replicas do not share them. Each execution is also logged with its finding, plan, provider, and result IDs, but there is no durable remediation record yet.
- The `agentshield` process needs RBAC permission to write NetworkPolicies, CiliumNetworkPolicies, PeerAuthentications, and Pod labels for these actions to succeed. Credentials stay in host configuration and never appear in suggestions or proposals.
- Production use would need authenticated authorization, durable approval and audit records, a complete CSRF policy beyond today's content-type and Host checks, recovery, and coordination across replicas. None of these exist yet. See the [security model](../operations/security-model.md).
