// Package telemetry ingests high-volume observed activity, stores it in a raw
// sink, and maintains bounded graph rollups from it.
//
// # Pipeline position
//
//	OTLP/HTTP or provider-native receiver
//	  -> MappingRegistry (plugin-owned mappers, trusted plugin/source)
//	  -> Pipeline.Ingest (bounded queue, all or none, rejects when full)
//	  -> Sink.WriteBatch (JSONL or ClickHouse, retried until it succeeds)
//	  -> CommitFunc (RollupPublisher.Commit: Rollup.ObserveResolved,
//	     Rollup.Advance, publish rollup contributions through the
//	     host's RollupTarget)
//
// Raw [Event] values never enter the graph. The graph receives only bounded
// [Rollup] output: per-minute telemetry series, NetworkPeerClass resources for
// unresolved peers, ProcessClass resources for process executions, and lease
// relationships whose predicate each kind declares in [EventKinds]
// (communicates-with for network kinds, executes for process executions).
//
// # Invariants
//
//   - Every event has a stable event ID that survives producer retries and
//     keeps its original observation timestamp, so the raw store can collapse
//     duplicates.
//   - Plugin and source provenance come from mapper registration, never from
//     payload fields.
//   - A batch reaches the commit callback only after the sink acknowledged it,
//     so the graph never reflects telemetry that is not durably stored.
//   - Nothing is dropped while the process runs: a request the queue cannot
//     take whole is rejected for the producer to retry, a failing sink stalls
//     the pipeline (and is logged with counts only), and a failing commit is
//     retried with the batch kept, stopping the pipeline only when it
//     persists.
//   - Receivers acknowledge a request once its events are queued, before the
//     sink write. Acknowledged events still in the queue are lost if the
//     process crashes, or at shutdown if the drain deadline in [Pipeline.Run]
//     expires first.
//   - Properties and evidence IDs are bounded per event, and rollup series are
//     bounded by retention and a series cap, so graph cardinality does not
//     grow with traffic volume.
//   - Properties and evidence may be sensitive. This package does not log
//     them; keep it that way.
//
// See https://agent-shield.dev/docs/architecture/telemetry/.
package telemetry
