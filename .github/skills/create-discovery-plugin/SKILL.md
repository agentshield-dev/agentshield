---
name: create-discovery-plugin
description: 'Create, extend, review, or debug an AgentShield discovery plugin or downstream provider integration. Use for Kubernetes, Istio, AWS, GCP, Azure, SaaS inventory, identity mapping, shared collections, checkpoints, contribution replacement, facets, relationships, telemetry boundaries, projector tests, and plugin authoring.'
argument-hint: 'Describe the downstream system and desired graph semantics'
user-invocable: true
---

<!-- markdownlint-disable MD013 -->

# Create an AgentShield discovery plugin

This skill is a work order. The rules are in the docs; follow the links rather than memory. Read the [plugin contract](../../../docs/plugins/README.md) first, then the [style guide](../../../docs/plugins/style-guide.md) and the [tutorial](../../../docs/plugins/tutorial.md) (a worked example with a code map). Add the [data model](../../../docs/concepts/data-model.md), [security semantics](../../../docs/concepts/security-semantics.md), and [telemetry](../../../docs/architecture/telemetry.md) pages when the plugin touches identity, security facts, or traffic.

Fill in the [design record](./references/checklist.md) as you go.

## 1. Pin down the provider

Answer these in the design record before writing code:

- What is the authority (the account, cluster, or tenant that issues IDs)?
- Which field never changes for the life of an object? That is the identity key; a name, label, or IP address is not.
- Does an existing identity scheme cover this authority, or do you need a new one?
- How do you get a full snapshot, learn about changes (watch, feed, or polling), and learn about deletions?
- Can the provider stream resume from a cursor?
- Does another plugin already read this provider? Then consume its collection.

## 2. Choose the parts

A plugin can have several parts:

- **Source**: owns the provider connection and publishes collections.
- **Semantic**: consumes another plugin's collections. For Kubernetes resources, declare `kubernetes.ResourceRequirement` values; see [Kubernetes-backed plugins](../../../docs/plugins/README.md#kubernetes-backed-plugins). Build `Run` on `plugins/internal/coherentcache` (as istio, cilium and agentgateway do) instead of writing your own subscribe, replay and sync loop, and cite Kubernetes evidence with `projectkit.KubernetesEventID` so it matches the stored native event IDs.
- **Telemetry**: maps traffic records into the telemetry pipeline; see [Writing a mapper](../../../docs/architecture/telemetry.md#writing-a-mapper).
- **Remediation**: offers provider changes; see [Remediation](../../../docs/architecture/remediation.md).

## 3. Write the descriptor

List the plugin ID, version, every collection consumed and published, every contribution name, and any new identity scheme. Use only predicates already in `pkg/graph`; discuss a new one with a maintainer first (it needs a migration).

## 4. Write the projector and its tests first

1. Write `Project` as a pure function from a snapshot to `graph.Input`, following [Projectors](../../../docs/plugins/README.md#projectors) and the [style guide](../../../docs/plugins/style-guide.md#projector-structure). Add assertion helpers that set provenance and sort evidence.
2. Attach security semantics to each security-relevant fact, or add it to the native-only column of the [coverage table](../../../docs/concepts/security-semantics.md#current-coverage-by-provider) with a reason.
3. Write the projector tests from [Testing](../../../docs/plugins/README.md#testing) that need no running plugin (identity, shuffled input, provenance, security semantics, malformed input, unresolved references, deletion by omission), and run `go test -race ./plugins/<name>` before wiring any I/O.

## 5. Wire the lifecycle

Implement `Run` following [Lifecycle](../../../docs/plugins/README.md#lifecycle), then check:

- [ ] The generation is recovered at startup and only goes up.
- [ ] Nothing is published before the cache is complete (source) or every consumed `sync` marker arrives (semantic).
- [ ] Collections are marked ready only after the first replacement succeeds.
- [ ] Readiness, publication, health, and coverage are tracked separately.
- [ ] A provider outage after the first publication republishes the last good input as degraded, never an empty one.
- [ ] Queue saturation, subscription closure, and publication failure return errors from `Run`.
- [ ] Raw telemetry goes to the telemetry pipeline, and any stream cursor is stored apart from the generation.

Then add the lifecycle tests from [Testing](../../../docs/plugins/README.md#testing).

## 6. Validate

Run the commands in [Testing](../../../docs/plugins/README.md#testing). Kubernetes or Istio projector changes also need `make eval-run` against the evaluation cluster, with every campaign's observation contract passing and `summary.json` written; `make eval-check` validates the cluster without model calls. The run is billed, so if you cannot run it, say so in the pull request and a maintainer will.

## 7. Document

1. Add `docs/plugins/<name>.md` covering the list in [Documenting a plugin](../../../docs/plugins/README.md#documenting-a-plugin).
2. Add the plugin to the table in [docs/plugins/README.md](../../../docs/plugins/README.md#existing-plugins) and to the providers line in [docs/README.md](../../../docs/README.md#plugins).
3. Add its security semantics row to the [coverage table](../../../docs/concepts/security-semantics.md#current-coverage-by-provider).
4. Add any new flags to [Configuration](../../../docs/operations/configuration.md).
