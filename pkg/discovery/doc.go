// Package discovery hosts discovery plugins and connects them to observation
// collections and durable graph publication.
//
// # Pipeline position
//
// A source plugin watches a provider and publishes [Change] values to
// observation collections. Semantic plugins subscribe to those collections,
// run pure projectors over their current caches, and publish complete
// [ContributionOutput] values. [RuntimeService] records each change as a
// native event, fans it out through the in-memory [Hub], and hands
// contributions to package state for atomic publication. Everything after
// publication (outbox, reasoning, findings) is outside this package.
//
// # Shared collections and replay-then-live delivery
//
// A collection is keyed by (source ID, collection name) and is owned by
// exactly one publishing plugin per source; [NewManager] rejects duplicate
// publishers and consumers with no same-source publisher. Several consumers
// share one collection instead of opening duplicate provider watches. A new
// subscriber first receives the current items in key order, each marked
// Initial, then the last [OperationSync] marker if one was published, and then
// every later change in publish order on the same channel. Consumers can
// therefore treat the sync marker as "my cache now equals the source's
// coherent view".
//
// A slow subscriber never blocks the publisher and is not disconnected. Once
// its buffer is full, the hub coalesces its pending changes to the latest per
// key plus the newest sync marker, the same information a fresh replay would
// carry, and delivers them as it catches up.
//
// # Source scoping
//
// [Manager] gives each plugin instance a runtime scoped to its plugin ID and
// configured source ID. Publish, MarkReady, ReplaceContribution, and
// ContributionGeneration reject any other provenance, and Subscribe only sees
// collections of the same source, so two instances of one plugin cannot
// overwrite or consume each other's observations.
//
// # Supervision
//
// [Manager.Run] restarts a failed plugin instance with exponential backoff
// and leaves the others running. Before a restart it republishes the
// instance's last healthy contributions with degraded health, and after it
// the runtime removes collection items the new instance did not republish
// (see [RuntimeService.MarkReady]).
//
// # Readiness, publication, and health
//
// Collection readiness ([Runtime.MarkReady]) means a source's cache is
// coherent. Contribution publication ([Runtime.ReplaceContribution]) is a
// durable graph write with its own Ready flag and SourceHealth. They are
// separate states: a collection can be ready while its consumer has not yet
// published, and a contribution can stay published with degraded or stale
// health after its source fails.
//
// # Generations
//
// A contribution generation must increase across publications and process
// restarts. Plugins call [Runtime.ContributionGeneration] once at startup to
// recover the highest durable generation for their (plugin, source) and
// publish from the next value. Package state rejects older generations and
// treats a same-generation, same-input retry as idempotent.
//
// See docs/plugins/README.md for authoring guidance and
// docs/architecture/publication-and-storage.md for what publication does.
package discovery
