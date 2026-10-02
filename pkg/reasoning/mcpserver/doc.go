// Package mcpserver exposes a reasoning [reasoning.ContextProvider] as
// read-only MCP tools for model-driven investigation.
//
// Each tool maps to one context template and accepts only resource IDs the
// provider knows. Every call is answered from the provider's immutable graph
// copy and pinned telemetry for one analysis token; tools cannot read live
// state, write anything, or reach a different graph digest. Results are bounded
// and report whether any collection was truncated.
//
// Tools:
//
//   - get_security_neighborhood: one-hop relationships around the anchors.
//   - get_telemetry_chain: pinned telemetry touching the anchors.
//   - get_governance_posture: governed-by relationships and facets, without
//     inferring policy effect.
//   - find_graph_paths: the subgraph within a fixed hop limit of the anchors,
//     over every registered predicate except runs-on or an explicit predicate
//     allowlist. It returns reachable resources and relationships, not
//     individual paths; the name predates that and is kept for compatibility.
//   - get_incident_timeline: ordered incident observations for the anchors.
//   - get_behavior_baseline: previously observed behavior for the anchors.
//
// The reasoning runtime uses [ConnectInMemory], so no MCP transport is exposed
// outside the process. The standalone command exposes [NewHTTPHandler] over
// streamable HTTP. [ServeStdio] remains available to embedders for local
// experiments.
package mcpserver
