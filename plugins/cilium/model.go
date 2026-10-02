package cilium

import (
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/coherentcache"
)

// PluginID is the plugin and contribution owner ID.
const PluginID = "cilium"

// ObservedObject is one cached Kubernetes observation with the event ID used
// as assertion evidence.
type ObservedObject = coherentcache.Object

// ProjectionContext scopes projection to one cluster and source.
type ProjectionContext struct {
	ClusterID string
	SourceID  string
}

// ProjectionResult is the complete cni-semantics contribution input plus
// diagnostics for endpoints and nodes that could not be matched.
type ProjectionResult struct {
	Input       graph.Input
	Diagnostics []Diagnostic
}

// Diagnostic records an unresolved or unsupported provider object. It is not
// a graph fact and never implies policy absence.
type Diagnostic struct {
	Code     string
	Resource string
}
