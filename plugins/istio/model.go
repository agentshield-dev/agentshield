package istio

import (
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/coherentcache"
)

// ObservedObject keeps collection delivery metadata beside the native object so
// projected assertions can retain evidence provenance.
type ObservedObject = coherentcache.Object

// ProjectionContext carries authority and coverage boundaries into the pure
// semantic projection; it contains no runtime or provider clients.
type ProjectionContext struct {
	ClusterID            string
	NetworkID            string
	SourceID             string
	RootNamespace        string
	GatewayCoverageKnown bool
}

// ProjectionResult separates publishable assertions from bounded diagnostics
// about observations that could not produce graph semantics.
type ProjectionResult struct {
	Input       graph.Input
	Diagnostics []Diagnostic
}

// Diagnostic records an observation that produced no graph semantics, such as
// an invalid host or unsupported field. It is not a graph fact.
type Diagnostic struct {
	Code     string
	Resource string
}

type projection struct {
	context     ProjectionContext
	index       *Index
	input       graph.Input
	diagnostics []Diagnostic
}
