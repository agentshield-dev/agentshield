# Plugin style guide

How we usually write plugin code. The rules are in the [plugin contract](README.md). A provider page may depart from a convention here if it says why.

## Package layout

Keep a plugin in one Go package until a real ownership boundary needs more. Name files by responsibility:

| File | Owns |
| --- | --- |
| `plugin.go` | Configuration, descriptor, `Run` lifecycle, readiness, publication |
| `adapter.go` or provider-named files | Provider I/O: discovery, list/watch, polling, streaming, snapshots |
| `index.go` | Indexes built once per reconciliation, and typed lookup results |
| `project.go` | The `Project` entry point and the fixed order of projector functions |
| Resource-named files (for example `peerauthentication.go`) | Decoding and graph semantics for one resource type, when substantial |
| `identity.go`, `assertions.go` | Shared identity, provenance, evidence, and assertion helpers |
| `remediation.go` | Remediation actions, if any |

Avoid empty layers, a package per resource, reflection dispatch, projector registries, and single-implementation interfaces. Split a file when it has its own decoding and semantics worth testing on their own.

A Kubernetes-backed semantic plugin's `Run` is a call to `plugins/internal/coherentcache.Run`, which owns subscription, replay, the coherent generation across resource and coverage collections, degraded republication on subscription failure, and readiness; the plugin supplies only a pure `Project` function over the snapshot (and, for Istio, an `OnObjects` hook for its telemetry resolver). Do not write that loop again.

Use the shared helpers in `plugins/internal/projectkit` (`MustCanonicalJSON`, `Digest`, `SecurityDigest`, `Qualifier`, `ObjectKey`, `KubernetesEventID`, `KubernetesEvidenceID`, `DisplayName`) instead of writing new ones. Their output ends up in published assertions, so changing one is a rule change for every projector that uses it.

## Projector structure

`Project` copies and sorts its input, builds its indexes once, then calls small per-resource functions in a fixed order. Index by immutable provider IDs; index by normalized name only when the provider itself refers to objects by name.

When a lookup can fail in ways that matter, return a typed result (resolved, not found, ambiguous, unsupported, coverage unknown) instead of a bare value or `nil`.

## Assertion helpers

Build assertions through small helpers that fill in the plugin ID and sort and deduplicate evidence IDs; see `plugins/istio/provenance.go` and `plugins/kubernetes/assertions.go`. The graph compiler rejects an assertion without a plugin, source, or rule ID, but does not check for evidence IDs, so your tests must.

## Rule IDs

A rule ID is the plugin ID, then the resource and what the rule produces: `kubernetes.ingress.exposure`, `istio.authorization-policy-target`. Keep the constants next to the helper that uses them.

## Evidence IDs

An evidence ID contains a provider prefix, an immutable key, and a revision; never JSON paths, slice positions, or receipt times. For Kubernetes objects, `projectkit.KubernetesEvidenceID` returns `kubernetes:<lowercase(apiVersion/kind/UID)>:<resourceVersion>:upsert`, so every plugin citing the same revision of an object uses the same ID. It is built by `projectkit.KubernetesEventID`, which the Kubernetes plugin also uses for its native event IDs, so the evidence and the change's `EventID` that semantic plugins cite resolve to the same durable receipt. The AWS plugin cites its native event IDs (`aws:<collection>:<key>:<revision>:<operation>`).

## Attribute keys and values

- Name provider-specific keys `<provider>/<lowercase-hyphenated-name>`, for example `kubernetes/pod-selector` or `istio/action`. `agentshield.io/security-semantics` is reserved for the [security semantics](../concepts/security-semantics.md) value.
- Encode structured values with `encoding/json` (`projectkit.MustCanonicalJSON`), not delimiter-joined strings.
- Sort and deduplicate sets and map-derived keys before encoding or hashing. Keep list order only when the provider gives it meaning.
- Build relationship qualifiers from semantic content or a stable digest (`projectkit.Qualifier`), never from input positions.
- When you cap a list, store the omitted count under a matching key, for example `aws/omitted-rules`.

## Security semantics in code

- Build the value with `graph.WithSecuritySemantics`.
- Cap and sort protocols and ports before encoding, and lower `coverage` when you cap or cannot express a native detail (named ports, ranges, inherited behavior, unsupported forms).
- Compute configuration digests with `projectkit.SecurityDigest` over the configuration, not over the currently selected targets.
- Put the value on the existing facet or relationship, not on a separate "semantic" resource.

## Comments and errors

Comment non-obvious provider behavior, safety boundaries, and why a simpler inference would be wrong; do not narrate code.

Errors name the operation or rule and a safe locator such as GVK/namespace/name, and wrap causes with `%w`. Never put payloads, secrets, or tokens in an error.

## Tests

- Name test files after the file they cover (`peerauthentication_test.go` for `peerauthentication.go`).
- Prefer table-driven tests with small object builders over large fixtures.
- Compile projected output with the real graph compiler, not a fake.
- Prove determinism by comparing graph digests for the original, reversed, and shuffled input.
- Test caps and fan-out with counts, not timings.

What must be covered is in the [contract](README.md#testing).
