// Package graph defines AgentShield's provider-neutral graph model and the pure
// compiler that turns plugin assertions into a canonical snapshot.
//
// # Pipeline position
//
// Discovery plugins and the telemetry rollup emit an [Input]: resource, facet,
// relationship, and bounded telemetry assertions. Package state persists those
// assertions per contribution and calls [Compiler] twice: once to validate a
// candidate contribution ([Compiler.CompileContribution]) and once to
// materialize the union of all active contributions ([Compiler.Compile]). The
// resulting [Snapshot] feeds current-state projections, the graph API, and
// reasoning. This package performs no I/O and holds no contribution or
// generation state; ownership and replacement live in package state.
//
// # Identity
//
// Every graph node is named by an [IdentityClaim]: a scheme (group, version,
// kind), an authority ID, and an immutable key. A [Registry] maps each
// [IdentityScheme] to a normalizer, and the compiler derives a UUIDv5 resource
// ID from the normalized tuple. Claims must be authority-qualified (a cluster
// UID or cloud account, not a plugin ID) and provider-immutable (an object UID
// or immutable resource name, not a display name, label, or IP address), so
// independent plugins converge on the same node and a recreated object gets a
// new one. Mutable values belong in attributes. NetworkDestination and
// NetworkPeerClass are built-in provider-neutral schemes preloaded by
// [NewRegistry]; plugins register only the authority-specific schemes they
// introduce.
//
// # Assertions and provenance
//
// Every assertion carries PluginID, SourceID, RuleID, and EvidenceIDs. The
// compiler rejects assertions without a plugin, source, or rule, sorts and
// deduplicates evidence IDs, groups equal claims onto one record while keeping
// every contributing assertion, deduplicates identical assertions, and sorts
// all output. Two inputs containing the same assertion set therefore compile
// to byte-identical [Snapshot.CanonicalJSON] and the same [Snapshot.Hash],
// regardless of slice order or duplication.
//
// Relationships use only predicates registered in this package (see
// [IsRegisteredPredicate]); adding a predicate is a central change that must
// also update persistence constraints. A relationship or facet whose endpoint
// resource is not present is kept with [ResolutionUnresolved] so contributions
// can reference identities owned by other plugins without publication
// ordering. Conflicting kinds for one identity become an [AssertionConflict]
// rather than an error.
//
// # Security semantics
//
// [SecuritySemantics] is a closed, versioned, provider-neutral envelope stored
// in a facet attribute or relationship property under
// [SecuritySemanticsAttribute]. The compiler validates every envelope present
// and requires canonical encoding; it does not enforce that one is present.
//
// See https://agent-shield.dev/docs/concepts/data-model/ for the full model.
package graph
