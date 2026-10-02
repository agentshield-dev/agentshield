package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

// Operation is the kind of collection change.
type Operation string

// Collection operations. Upsert and delete carry an event ID and are recorded
// as native events; sync is an in-memory readiness marker only.
const (
	OperationUpsert Operation = "upsert"
	OperationDelete Operation = "delete"
	OperationSync   Operation = "sync"
)

// Change is one replayable item in a plugin-owned observation collection;
// OperationSync marks the boundary after its current-state replay is coherent.
type Change struct {
	EventID    string          `json:"eventId"`
	PluginID   string          `json:"pluginId"`
	SourceID   string          `json:"sourceId"`
	Collection string          `json:"collection"`
	Key        string          `json:"key"`
	Revision   string          `json:"revision,omitempty"`
	Generation uint64          `json:"generation"`
	Operation  Operation       `json:"operation"`
	ObservedAt time.Time       `json:"observedAt"`
	Initial    bool            `json:"initial,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

// Descriptor declares a plugin's collection contracts and any identity schemes
// whose authority it owns; it does not describe graph output ownership.
type Descriptor struct {
	ID string
	// Version is the plugin's release version, required and otherwise
	// informational. It is not persisted and is not part of contribution
	// identity, input digests, or assertions, so changing it republishes
	// nothing. In-tree plugins start at 0.1.0 while the project is pre-1.0;
	// bump it when the plugin's collections, identity schemes, or emitted
	// assertions change in a way its consumers should notice.
	Version     string
	Description string
	Consumes    []string
	Publishes   []string
	// IdentitySchemes lists authority-specific schemes this plugin introduces.
	// Leave it empty when the plugin only emits claims under existing schemes.
	// Follow-up: this could become an optional IdentitySchemeProvider
	// capability, like TelemetryMappingProvider, so the descriptor stays
	// limited to collection contracts.
	IdentitySchemes []graph.SchemeDefinition
}

// RegisterIdentitySchemes registers every descriptor's identity schemes. It
// must run before the graph compiler is constructed; a scheme declared by two
// plugins fails startup instead of silently sharing authority.
func RegisterIdentitySchemes(registry *graph.Registry, descriptors ...Descriptor) error {
	if registry == nil {
		return fmt.Errorf("identity registry is required")
	}
	for _, descriptor := range descriptors {
		for _, definition := range descriptor.IdentitySchemes {
			if err := registry.Register(definition); err != nil {
				return fmt.Errorf("register identity scheme for plugin %q: %w", descriptor.ID, err)
			}
		}
	}
	return nil
}

// ContributionOutput replaces one complete plugin-owned graph contribution.
// Its readiness and health are independent of collection readiness.
type ContributionOutput struct {
	Name             string
	Generation       uint64
	Input            graph.Input
	SourceObservedAt time.Time
	Ready            bool
	SourceHealth     string
}

// Runtime keeps observation collection delivery separate from durable graph
// contribution replacement, even when one plugin participates in both.
type Runtime interface {
	// Publish records a change as a native event and delivers it to the
	// source's collection subscribers.
	Publish(context.Context, Change) error
	// MarkReady publishes the sync marker for (plugin, source, collection) at
	// the given generation, signalling that the collection is coherent.
	MarkReady(context.Context, string, string, string, uint64) error
	// Subscribe replays the current collection and then streams live changes.
	// The channel closes when ctx ends. A subscriber that falls behind
	// receives coalesced changes instead of every intermediate one.
	Subscribe(context.Context, string) (<-chan Change, error)
	// ReplaceContribution durably replaces one named contribution for
	// (plugin, source). Assertions omitted from the output are retracted.
	ReplaceContribution(context.Context, string, string, ContributionOutput) error
	// ContributionGeneration returns the highest durable generation across
	// all contributions of (plugin, source), or zero if none exist.
	ContributionGeneration(context.Context, string, string) (uint64, error)
}

// Plugin is a discovery plugin. Run blocks until ctx ends or the plugin
// fails. [Manager] restarts a failed instance with backoff and leaves the
// plugins managed alongside it running; see [Manager.Run].
type Plugin interface {
	Descriptor() Descriptor
	Run(context.Context, Runtime) error
}

// IdentityReferenceResolver is an optional capability that maps a provider
// reference found in another plugin's data, such as a Kubernetes Node
// spec.providerID, to an identity claim in a scheme the plugin owns. This lets
// plugins join on authoritative IDs instead of names or tags.
type IdentityReferenceResolver interface {
	ResolveIdentityReference(string) (graph.IdentityClaim, bool, error)
}

// IdentityReferenceResolvers returns the plugins that implement
// IdentityReferenceResolver, in input order.
func IdentityReferenceResolvers(plugins ...Plugin) []IdentityReferenceResolver {
	var resolvers []IdentityReferenceResolver
	for _, plugin := range plugins {
		if resolver, ok := plugin.(IdentityReferenceResolver); ok {
			resolvers = append(resolvers, resolver)
		}
	}
	return resolvers
}

// ResolveIdentityReference asks every resolver. Matches that agree are
// accepted; two resolvers returning different claims is an error rather than
// a first-wins choice.
func ResolveIdentityReference(reference string, resolvers ...IdentityReferenceResolver) (graph.IdentityClaim, bool, error) {
	var resolved graph.IdentityClaim
	found := false
	for _, resolver := range resolvers {
		claim, matched, err := resolver.ResolveIdentityReference(reference)
		if err != nil {
			return graph.IdentityClaim{}, false, err
		}
		if !matched {
			continue
		}
		if found && claim != resolved {
			return graph.IdentityClaim{}, false, fmt.Errorf("identity reference %q resolves to multiple claims", reference)
		}
		resolved = claim
		found = true
	}
	return resolved, found, nil
}

// PluginInstance exposes the stable source identity configured by the host.
// Manager requires it and scopes all runtime access to this identity.
type PluginInstance interface {
	SourceID() string
}

// TelemetryMappingProvider is an optional plugin capability for translating
// source-specific OTLP log records into normalized telemetry events.
type TelemetryMappingProvider interface {
	TelemetryMappings() []telemetry.Mapping
}

// TelemetryReceiver is an HTTP route owned by a plugin. The host mounts the
// route, while the plugin owns its authentication, validation, and mapping.
type TelemetryReceiver struct {
	Method  string
	Path    string
	Handler http.Handler
}

// TelemetryReceiverProvider lets a plugin register native telemetry
// transports with the host's shared telemetry pipeline.
type TelemetryReceiverProvider interface {
	TelemetryReceivers(telemetry.EventIngestor) ([]TelemetryReceiver, error)
}

// RemediationProvider is an optional capability extracted independently from a
// plugin's discovery lifecycle and publication contracts.
type RemediationProvider interface {
	remediation.Provider
}
