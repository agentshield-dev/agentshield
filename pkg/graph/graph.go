package graph

import (
	"cmp"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// IdentityScheme names an identity authority contract in Kubernetes-style
// group/version/kind form. The group identifies the semantic authority, not
// the plugin that emits claims under it.
type IdentityScheme struct {
	Group   string `json:"group"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
}

func networkDestinationScheme() IdentityScheme {
	return IdentityScheme{Group: "agentshield.io", Version: "v1", Kind: "NetworkDestination"}
}

func networkPeerClassScheme() IdentityScheme {
	return IdentityScheme{Group: "agentshield.io", Version: "v1", Kind: "NetworkPeerClass"}
}

func processClassScheme() IdentityScheme {
	return IdentityScheme{Group: "agentshield.io", Version: "v1", Kind: "ProcessClass"}
}

// IdentityClaim names a resource within an authority-owned scheme. The compiler
// normalizes this tuple and derives the stable resource ID shared by assertions.
type IdentityClaim struct {
	Scheme       IdentityScheme `json:"scheme"`
	AuthorityID  string         `json:"authorityId"`
	ImmutableKey string         `json:"immutableKey"`
}

// ResourceAssertion claims that a resource with Kind exists under Claim. More
// than one plugin may assert the same identity; differing kinds produce an
// AssertionConflict instead of a Resource.
type ResourceAssertion struct {
	Claim       IdentityClaim     `json:"claim"`
	Kind        string            `json:"kind"`
	DisplayName string            `json:"displayName,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	PluginID    string            `json:"pluginId"`
	SourceID    string            `json:"sourceId"`
	RuleID      string            `json:"ruleId"`
	EvidenceIDs []string          `json:"evidenceIds"`
}

// Predicate is a directed relationship type. Only predicates in the central
// registry are accepted by the compiler; see IsRegisteredPredicate.
type Predicate string

// Registered predicates. Adding one is a central change that also needs a new
// state migration widening the relationship predicate CHECK constraints.
const (
	PredicateContains     Predicate = "contains"
	PredicateInstantiates Predicate = "instantiates"
	PredicateMemberOf     Predicate = "member-of"
	PredicateUsesIdentity Predicate = "uses-identity"
	PredicateExposes      Predicate = "exposes"
	PredicateGovernedBy   Predicate = "governed-by"
	PredicateCommunicates Predicate = "communicates-with"
	PredicateRunsOn       Predicate = "runs-on"
	PredicateBackedBy     Predicate = "backed-by"
	PredicateExecutes     Predicate = "executes"
)

var predicates = map[Predicate]struct{}{
	PredicateContains: {}, PredicateInstantiates: {}, PredicateMemberOf: {},
	PredicateUsesIdentity: {}, PredicateExposes: {}, PredicateGovernedBy: {},
	PredicateCommunicates: {}, PredicateRunsOn: {}, PredicateBackedBy: {},
	PredicateExecutes: {},
}

// PredicateDescription pairs a registered predicate with a human-readable
// meaning. It feeds generated detector-rule documentation.
type PredicateDescription struct {
	Predicate   Predicate
	Description string
}

var predicateDescriptions = map[Predicate]string{
	PredicateContains:     "The subject contains or scopes the object.",
	PredicateInstantiates: "The subject workload controller creates or owns an instance represented by the object.",
	PredicateMemberOf:     "The subject is a member of the object group or domain.",
	PredicateUsesIdentity: "The subject uses the object identity.",
	PredicateExposes:      "The subject exposes or binds the object network destination.",
	PredicateGovernedBy:   "The subject is governed by the object policy or control.",
	PredicateCommunicates: "Observed telemetry records communication from the subject to the object.",
	PredicateExecutes:     "Observed runtime telemetry records the subject workload starting a process of the object process class.",
}

// IsRegisteredPredicate reports whether predicate is in the central vocabulary.
func IsRegisteredPredicate(predicate Predicate) bool {
	_, registered := predicates[predicate]
	return registered
}

// RegisteredPredicateDescriptions returns every registered predicate sorted by
// name. Predicates without a description have an empty Description.
func RegisteredPredicateDescriptions() []PredicateDescription {
	result := make([]PredicateDescription, 0, len(predicates))
	for predicate := range predicates {
		result = append(result, PredicateDescription{Predicate: predicate, Description: predicateDescriptions[predicate]})
	}
	slices.SortFunc(result, func(left, right PredicateDescription) int {
		return strings.Compare(string(left.Predicate), string(right.Predicate))
	})
	return result
}

// FacetAssertion attaches one independently computed aspect, identified by
// Kind and Key, to the resource named by Resource. Facets let several plugins
// enrich the same node without sharing ownership of it.
type FacetAssertion struct {
	Resource    IdentityClaim     `json:"resource"`
	Kind        string            `json:"kind"`
	Key         string            `json:"key"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	PluginID    string            `json:"pluginId"`
	SourceID    string            `json:"sourceId"`
	RuleID      string            `json:"ruleId"`
	EvidenceIDs []string          `json:"evidenceIds"`
}

// TelemetryAssertion is a bounded rollup of observed activity from Subject to
// Object. EventID must be stable for the rollup series; reusing it within one
// plugin and source with different content is a compile error. Raw events stay
// in the telemetry sink.
type TelemetryAssertion struct {
	EventID     string            `json:"eventId"`
	Kind        string            `json:"kind"`
	Subject     IdentityClaim     `json:"subject"`
	Object      IdentityClaim     `json:"object"`
	Operation   string            `json:"operation,omitempty"`
	Outcome     string            `json:"outcome,omitempty"`
	Coverage    string            `json:"coverage,omitempty"`
	Count       uint64            `json:"count"`
	Properties  map[string]string `json:"properties,omitempty"`
	PluginID    string            `json:"pluginId"`
	SourceID    string            `json:"sourceId"`
	RuleID      string            `json:"ruleId"`
	EvidenceIDs []string          `json:"evidenceIds"`
}

// RelationshipAssertion claims a directed edge (Subject, Predicate, Object,
// Qualifier). Either endpoint may be owned by another contribution; the edge
// is kept as unresolved until both resources are present.
type RelationshipAssertion struct {
	Subject     IdentityClaim     `json:"subject"`
	Predicate   Predicate         `json:"predicate"`
	Object      IdentityClaim     `json:"object"`
	Qualifier   string            `json:"qualifier,omitempty"`
	Properties  map[string]string `json:"properties,omitempty"`
	PluginID    string            `json:"pluginId"`
	SourceID    string            `json:"sourceId"`
	RuleID      string            `json:"ruleId"`
	EvidenceIDs []string          `json:"evidenceIds"`
}

// Input is an assertion set submitted to the compiler. Contribution ownership
// and replacement are handled by the publication layer around this pure model.
type Input struct {
	Resources     []ResourceAssertion
	Facets        []FacetAssertion
	Relationships []RelationshipAssertion
	Telemetry     []TelemetryAssertion
}

// ResolutionStatus records whether a facet or relationship's endpoint
// resources are present in the compiled snapshot.
type ResolutionStatus string

// Resolution statuses. Resolved is the zero value so it is omitted from JSON.
const (
	ResolutionResolved   ResolutionStatus = ""
	ResolutionUnresolved ResolutionStatus = "unresolved"
)

// Resource is a compiled graph node with every assertion that claimed it, in
// canonical order.
type Resource struct {
	ID         string              `json:"id"`
	Kind       string              `json:"kind"`
	Identity   IdentityClaim       `json:"identity"`
	Assertions []ResourceAssertion `json:"assertions"`
}

// Relationship is a compiled edge. ID is derived from subject, predicate,
// object, and qualifier, so equal edges from different plugins share one
// record and keep separate assertions.
type Relationship struct {
	ID               string                  `json:"id"`
	SubjectID        string                  `json:"subjectId"`
	Predicate        Predicate               `json:"predicate"`
	ObjectID         string                  `json:"objectId"`
	Qualifier        string                  `json:"qualifier,omitempty"`
	ResolutionStatus ResolutionStatus        `json:"resolutionStatus,omitempty"`
	Assertions       []RelationshipAssertion `json:"assertions"`
}

// Facet is a compiled facet. ID is derived from resource ID, kind, and key.
type Facet struct {
	ID               string           `json:"id"`
	ResourceID       string           `json:"resourceId"`
	Kind             string           `json:"kind"`
	Key              string           `json:"key"`
	ResolutionStatus ResolutionStatus `json:"resolutionStatus,omitempty"`
	Assertions       []FacetAssertion `json:"assertions"`
}

// AssertionConflict records an identity asserted with more than one kind. The
// identity is withheld from Snapshot.Resources so traversal never picks a kind
// arbitrarily; edges to it remain unresolved.
type AssertionConflict struct {
	ResourceID string              `json:"resourceId"`
	Kinds      []string            `json:"kinds"`
	Assertions []ResourceAssertion `json:"assertions"`
}

// TelemetryEvent is a compiled telemetry rollup with endpoints resolved to
// resource IDs. ID is derived from plugin, source, and EventID.
type TelemetryEvent struct {
	ID          string            `json:"id"`
	EventID     string            `json:"eventId"`
	Kind        string            `json:"kind"`
	SubjectID   string            `json:"subjectId"`
	ObjectID    string            `json:"objectId"`
	Operation   string            `json:"operation,omitempty"`
	Outcome     string            `json:"outcome,omitempty"`
	Coverage    string            `json:"coverage,omitempty"`
	Count       uint64            `json:"count"`
	Properties  map[string]string `json:"properties,omitempty"`
	PluginID    string            `json:"pluginId"`
	SourceID    string            `json:"sourceId"`
	RuleID      string            `json:"ruleId"`
	EvidenceIDs []string          `json:"evidenceIds"`
}

// Snapshot is the canonical graph compiled by grouping assertions around their
// normalized identities while retaining each assertion's provenance.
type Snapshot struct {
	Resources     []Resource          `json:"resources"`
	Facets        []Facet             `json:"facets"`
	Relationships []Relationship      `json:"relationships"`
	Telemetry     []TelemetryEvent    `json:"telemetry"`
	Conflicts     []AssertionConflict `json:"conflicts,omitempty"`
}

// SchemeDefinition binds an authority contract to its identity normalizer.
// Plugins register only schemes whose identity authority they introduce.
type SchemeDefinition struct {
	Scheme    IdentityScheme
	Normalize func(IdentityClaim) (IdentityClaim, error)
}

// Registry maps identity schemes to their normalizers. It is populated at
// startup before the Compiler is built and is not safe for concurrent
// registration.
type Registry struct {
	definitions map[IdentityScheme]SchemeDefinition
}

// NewRegistry returns a registry preloaded with the built-in
// NetworkDestination and NetworkPeerClass schemes.
func NewRegistry() *Registry {
	destination := NetworkDestinationSchemeDefinition()
	peerClass := NetworkPeerClassSchemeDefinition()
	processClass := ProcessClassSchemeDefinition()
	return &Registry{definitions: map[IdentityScheme]SchemeDefinition{
		destination.Scheme:  destination,
		peerClass.Scheme:    peerClass,
		processClass.Scheme: processClass,
	}}
}

// Register adds a scheme definition. Registering the same scheme twice is an
// error, so two plugins cannot both claim authority over one scheme.
func (r *Registry) Register(definition SchemeDefinition) error {
	if err := validateIdentityScheme(definition.Scheme); err != nil {
		return err
	}
	if definition.Normalize == nil {
		return errors.New("identity scheme requires a normalizer")
	}
	if _, exists := r.definitions[definition.Scheme]; exists {
		return fmt.Errorf("identity scheme %s already registered", formatIdentityScheme(definition.Scheme))
	}
	r.definitions[definition.Scheme] = definition
	return nil
}

func validateIdentityScheme(scheme IdentityScheme) error {
	if strings.TrimSpace(scheme.Group) == "" || strings.TrimSpace(scheme.Version) == "" || strings.TrimSpace(scheme.Kind) == "" {
		return errors.New("identity scheme requires group, version, and kind")
	}
	return nil
}

func formatIdentityScheme(scheme IdentityScheme) string {
	return scheme.Group + "/" + scheme.Version + ", Kind=" + scheme.Kind
}

// TrimmedIdentityScheme returns a definition whose normalizer trims
// whitespace and requires a non-empty authority and key. It preserves key
// case; use a custom normalizer when the provider key is case-insensitive.
func TrimmedIdentityScheme(name IdentityScheme) SchemeDefinition {
	return SchemeDefinition{
		Scheme: name,
		Normalize: func(claim IdentityClaim) (IdentityClaim, error) {
			claim.AuthorityID = strings.TrimSpace(claim.AuthorityID)
			claim.ImmutableKey = strings.TrimSpace(claim.ImmutableKey)
			if claim.Scheme != name || claim.AuthorityID == "" || claim.ImmutableKey == "" {
				return IdentityClaim{}, fmt.Errorf("invalid %s identity claim", formatIdentityScheme(name))
			}
			return claim, nil
		},
	}
}

// NetworkDestinationSchemeDefinition defines the built-in agentshield.io/v1
// NetworkDestination scheme. Its authority is a network realm and its key is
// dns/<host> or ip/<address>, lowercased so configuration and telemetry
// converge on one node.
func NetworkDestinationSchemeDefinition() SchemeDefinition {
	scheme := networkDestinationScheme()
	return SchemeDefinition{
		Scheme: scheme,
		Normalize: func(claim IdentityClaim) (IdentityClaim, error) {
			claim.AuthorityID = strings.TrimSpace(claim.AuthorityID)
			claim.ImmutableKey = strings.ToLower(strings.TrimSpace(claim.ImmutableKey))
			if claim.Scheme != scheme || claim.AuthorityID == "" || claim.ImmutableKey == "" {
				return IdentityClaim{}, errors.New("invalid agentshield.io/v1 NetworkDestination identity claim")
			}
			return claim, nil
		},
	}
}

// NetworkDestinationClaim builds a claim through the scheme's normalizer, so
// it matches what the compiler stores; it fails for an empty authority or key.
func NetworkDestinationClaim(authorityID, immutableKey string) (IdentityClaim, error) {
	return NetworkDestinationSchemeDefinition().Normalize(IdentityClaim{
		Scheme: networkDestinationScheme(), AuthorityID: authorityID, ImmutableKey: immutableKey,
	})
}

// networkPeerClasses is the closed vocabulary for unresolved telemetry peers.
// Keeping it closed bounds the number of peer-class nodes per realm.
var networkPeerClasses = map[string]struct{}{
	"private-ip": {}, "loopback-ip": {}, "link-local-ip": {}, "special-use-ip": {},
	"external-source": {}, "external-destination": {}, "dns-source": {}, "dns-destination": {},
}

// NetworkPeerClassSchemeDefinition defines the built-in agentshield.io/v1
// NetworkPeerClass scheme. Its key must be one value of a closed vocabulary,
// so unresolved telemetry peers collapse into a bounded set of nodes instead
// of one node per raw address.
func NetworkPeerClassSchemeDefinition() SchemeDefinition {
	scheme := networkPeerClassScheme()
	return SchemeDefinition{
		Scheme: scheme,
		Normalize: func(claim IdentityClaim) (IdentityClaim, error) {
			claim.AuthorityID = strings.TrimSpace(claim.AuthorityID)
			claim.ImmutableKey = strings.ToLower(strings.TrimSpace(claim.ImmutableKey))
			_, validClass := networkPeerClasses[claim.ImmutableKey]
			if claim.Scheme != scheme || claim.AuthorityID == "" || !validClass {
				return IdentityClaim{}, errors.New("invalid agentshield.io/v1 NetworkPeerClass identity claim")
			}
			return claim, nil
		},
	}
}

// NetworkPeerClassClaim builds a claim through the scheme's normalizer; it
// fails for a key outside the closed peer-class vocabulary.
func NetworkPeerClassClaim(authorityID, immutableKey string) (IdentityClaim, error) {
	return NetworkPeerClassSchemeDefinition().Normalize(IdentityClaim{
		Scheme: networkPeerClassScheme(), AuthorityID: authorityID, ImmutableKey: immutableKey,
	})
}

// ProcessClassShell is an interactive shell process.
const ProcessClassShell = "shell"

var processClasses = map[string]struct{}{ProcessClassShell: {}}

// ProcessClassDescription pairs a core process class with its meaning. It feeds
// generated detector-rule documentation.
type ProcessClassDescription struct {
	Class       string
	Description string
}

// ProcessClasses lists the core process-class vocabulary.
func ProcessClasses() []ProcessClassDescription {
	return []ProcessClassDescription{{ProcessClassShell, "an interactive shell attached to a terminal"}}
}

// ProcessClassSchemeDefinition normalizes ProcessClass claims and accepts only
// the core process-class vocabulary.
func ProcessClassSchemeDefinition() SchemeDefinition {
	scheme := processClassScheme()
	return SchemeDefinition{
		Scheme: scheme,
		Normalize: func(claim IdentityClaim) (IdentityClaim, error) {
			claim.AuthorityID = strings.TrimSpace(claim.AuthorityID)
			claim.ImmutableKey = strings.ToLower(strings.TrimSpace(claim.ImmutableKey))
			_, validClass := processClasses[claim.ImmutableKey]
			if claim.Scheme != scheme || claim.AuthorityID == "" || !validClass {
				return IdentityClaim{}, errors.New("invalid agentshield.io/v1 ProcessClass identity claim")
			}
			return claim, nil
		},
	}
}

// ProcessClassClaim returns a normalized ProcessClass claim, or an error for a
// class outside the core vocabulary.
func ProcessClassClaim(authorityID, immutableKey string) (IdentityClaim, error) {
	return ProcessClassSchemeDefinition().Normalize(IdentityClaim{
		Scheme: processClassScheme(), AuthorityID: authorityID, ImmutableKey: immutableKey,
	})
}

// IsProcessClassClaim reports whether claim uses the ProcessClass scheme.
func IsProcessClassClaim(claim IdentityClaim) bool {
	return claim.Scheme == processClassScheme()
}

// IsNetworkDestinationClaim reports whether claim uses the NetworkDestination scheme.
func IsNetworkDestinationClaim(claim IdentityClaim) bool {
	return claim.Scheme == networkDestinationScheme()
}

// IsNetworkPeerClassClaim reports whether claim uses the NetworkPeerClass scheme.
func IsNetworkPeerClassClaim(claim IdentityClaim) bool {
	return claim.Scheme == networkPeerClassScheme()
}

// Compiler is the pure, deterministic graph materializer. It holds no state
// besides its registry and is safe for concurrent use once registration is
// complete.
type Compiler struct {
	registry *Registry
}

// NewCompiler returns a compiler that resolves identities through registry.
func NewCompiler(registry *Registry) *Compiler {
	return &Compiler{registry: registry}
}

// Compile materializes the complete active graph. Telemetry whose subject or
// object resource is absent is dropped, because telemetry rollups only attach
// to materialized inventory; unresolved facets and relationships are kept.
func (c *Compiler) Compile(input Input) (Snapshot, error) {
	return c.compile(input, true)
}

// CompileContribution validates and resolves assertions before persistence;
// endpoint presence is enforced later when all active contributions are composed.
func (c *Compiler) CompileContribution(input Input) (Snapshot, error) {
	return c.compile(input, false)
}

// compile groups assertions by derived ID. Every grouping step is keyed by a
// map and every output slice is sorted at the end, which is what makes output
// independent of input order and duplication. Phases run in a fixed order, so
// which invalid assertion is reported does not depend on the order of the
// other assertion kinds.
func (c *Compiler) compile(input Input, requireTelemetryResources bool) (Snapshot, error) {
	if c.registry == nil {
		return Snapshot{}, errors.New("identity registry is required")
	}
	groups, err := c.groupResources(input.Resources)
	if err != nil {
		return Snapshot{}, err
	}
	resources, conflicts := mergeResourceGroups(groups)
	facets, err := c.compileFacets(input.Facets, resources)
	if err != nil {
		return Snapshot{}, err
	}
	relationships, err := c.compileRelationships(input.Relationships, resources)
	if err != nil {
		return Snapshot{}, err
	}
	telemetry, err := c.compileTelemetry(input.Telemetry, resources, requireTelemetryResources)
	if err != nil {
		return Snapshot{}, err
	}
	return assembleSnapshot(resources, facets, relationships, telemetry, conflicts), nil
}

// resourceGroup collects the distinct assertions, and the kinds they claim,
// for one resolved resource ID.
type resourceGroup struct {
	identity   IdentityClaim
	assertions map[string]ResourceAssertion
	kinds      map[string]struct{}
}

// groupResources resolves and validates every resource assertion and groups
// the distinct ones by resource ID.
func (c *Compiler) groupResources(assertions []ResourceAssertion) (map[string]*resourceGroup, error) {
	groups := make(map[string]*resourceGroup)
	for _, assertion := range assertions {
		normalized, id, err := c.resolve(assertion.Claim)
		if err != nil {
			return nil, err
		}
		if err := validateResourceAssertion(assertion); err != nil {
			return nil, err
		}
		assertion.Claim = normalized
		assertion.EvidenceIDs = sortedUnique(assertion.EvidenceIDs)
		key, err := stableJSON(assertion)
		if err != nil {
			return nil, err
		}
		group := groups[id]
		if group == nil {
			group = &resourceGroup{identity: normalized, assertions: make(map[string]ResourceAssertion), kinds: make(map[string]struct{})}
			groups[id] = group
		}
		group.assertions[key] = assertion
		group.kinds[assertion.Kind] = struct{}{}
	}
	return groups, nil
}

// mergeResourceGroups turns each group into a resource, or into a conflict
// when its assertions claim more than one kind. A conflicting identity is
// withheld from resources, so facets and relationships that reference it
// compile as unresolved.
func mergeResourceGroups(groups map[string]*resourceGroup) (map[string]*Resource, []AssertionConflict) {
	resources := make(map[string]*Resource)
	conflicts := make([]AssertionConflict, 0)
	for id, group := range groups {
		assertions := make([]ResourceAssertion, 0, len(group.assertions))
		for _, assertion := range group.assertions {
			assertions = append(assertions, assertion)
		}
		slices.SortFunc(assertions, func(left, right ResourceAssertion) int {
			return cmp.Compare(assertionOrder(left), assertionOrder(right))
		})
		kinds := make([]string, 0, len(group.kinds))
		for kind := range group.kinds {
			kinds = append(kinds, kind)
		}
		slices.Sort(kinds)
		if len(kinds) > 1 {
			conflicts = append(conflicts, AssertionConflict{ResourceID: id, Kinds: kinds, Assertions: assertions})
			continue
		}
		resources[id] = &Resource{ID: id, Kind: kinds[0], Identity: group.identity, Assertions: assertions}
	}
	return resources, conflicts
}

// compileFacets validates, resolves, and deduplicates facet assertions by
// facet ID. A facet whose resource is not materialized is unresolved.
func (c *Compiler) compileFacets(assertions []FacetAssertion, resources map[string]*Resource) (map[string]*Facet, error) {
	facets := make(map[string]*Facet)
	dedup := make(map[string]map[string]struct{})
	for _, assertion := range assertions {
		if err := validateFacetAssertion(assertion); err != nil {
			return nil, err
		}
		resource, resourceID, err := c.resolve(assertion.Resource)
		if err != nil {
			return nil, err
		}
		assertion.Resource = resource
		assertion.EvidenceIDs = sortedUnique(assertion.EvidenceIDs)
		id := facetID(resourceID, assertion.Kind, assertion.Key)
		key, err := stableJSON(assertion)
		if err != nil {
			return nil, err
		}
		if existing, ok := facets[id]; ok {
			if _, duplicate := dedup[id][key]; !duplicate {
				existing.Assertions = append(existing.Assertions, assertion)
				dedup[id][key] = struct{}{}
			}
			continue
		}
		status := ResolutionResolved
		if resources[resourceID] == nil {
			status = ResolutionUnresolved
		}
		facets[id] = &Facet{ID: id, ResourceID: resourceID, Kind: assertion.Kind, Key: assertion.Key, ResolutionStatus: status, Assertions: []FacetAssertion{assertion}}
		dedup[id] = map[string]struct{}{key: {}}
	}
	return facets, nil
}

// compileRelationships validates, resolves, and deduplicates relationship
// assertions by relationship ID. A relationship with an endpoint that is not
// materialized is unresolved.
func (c *Compiler) compileRelationships(assertions []RelationshipAssertion, resources map[string]*Resource) (map[string]*Relationship, error) {
	relationships := make(map[string]*Relationship)
	dedup := make(map[string]map[string]struct{})
	for _, assertion := range assertions {
		if err := validateRelationshipAssertion(assertion); err != nil {
			return nil, err
		}
		subject, subjectID, err := c.resolve(assertion.Subject)
		if err != nil {
			return nil, err
		}
		object, objectID, err := c.resolve(assertion.Object)
		if err != nil {
			return nil, err
		}
		assertion.Subject = subject
		assertion.Object = object
		assertion.EvidenceIDs = sortedUnique(assertion.EvidenceIDs)
		id := relationshipID(subjectID, assertion.Predicate, objectID, assertion.Qualifier)
		key, err := stableJSON(assertion)
		if err != nil {
			return nil, err
		}
		if existing, ok := relationships[id]; ok {
			if _, duplicate := dedup[id][key]; !duplicate {
				existing.Assertions = append(existing.Assertions, assertion)
				dedup[id][key] = struct{}{}
			}
			continue
		}
		status := ResolutionResolved
		if resources[subjectID] == nil || resources[objectID] == nil {
			status = ResolutionUnresolved
		}
		relationships[id] = &Relationship{
			ID: id, SubjectID: subjectID, Predicate: assertion.Predicate,
			ObjectID: objectID, Qualifier: assertion.Qualifier, ResolutionStatus: status, Assertions: []RelationshipAssertion{assertion},
		}
		dedup[id] = map[string]struct{}{key: {}}
	}
	return relationships, nil
}

// compileTelemetry validates and resolves telemetry assertions into events
// keyed by producer event ID. With requireResources, an event whose subject or
// object is not materialized is dropped.
func (c *Compiler) compileTelemetry(assertions []TelemetryAssertion, resources map[string]*Resource, requireResources bool) (map[string]TelemetryEvent, error) {
	telemetry := make(map[string]TelemetryEvent)
	for _, assertion := range assertions {
		if err := validateTelemetryAssertion(assertion); err != nil {
			return nil, err
		}
		subject, subjectID, err := c.resolve(assertion.Subject)
		if err != nil {
			return nil, err
		}
		object, objectID, err := c.resolve(assertion.Object)
		if err != nil {
			return nil, err
		}
		if requireResources && (resources[subjectID] == nil || resources[objectID] == nil) {
			continue
		}
		assertion.Subject = subject
		assertion.Object = object
		assertion.EvidenceIDs = sortedUnique(assertion.EvidenceIDs)
		id := telemetryID(assertion.PluginID, assertion.SourceID, assertion.EventID)
		event := TelemetryEvent{
			ID: id, EventID: assertion.EventID, Kind: assertion.Kind, SubjectID: subjectID, ObjectID: objectID,
			Operation: assertion.Operation, Outcome: assertion.Outcome, Coverage: assertion.Coverage, Count: assertion.Count,
			Properties: assertion.Properties, PluginID: assertion.PluginID, SourceID: assertion.SourceID,
			RuleID: assertion.RuleID, EvidenceIDs: assertion.EvidenceIDs,
		}
		// Telemetry IDs come from the producer's event ID, so a collision with
		// different content is a producer defect rather than a duplicate.
		if existing, ok := telemetry[id]; ok {
			existingJSON, _ := stableJSON(existing)
			eventJSON, _ := stableJSON(event)
			if existingJSON != eventJSON {
				return nil, fmt.Errorf("telemetry event %q reused with different content", assertion.EventID)
			}
			continue
		}
		telemetry[id] = event
	}
	return telemetry, nil
}

// assembleSnapshot flattens the compiled maps and sorts every slice, and each
// element's assertions, into canonical order.
func assembleSnapshot(resources map[string]*Resource, facets map[string]*Facet, relationships map[string]*Relationship, telemetry map[string]TelemetryEvent, conflicts []AssertionConflict) Snapshot {
	snapshot := Snapshot{Resources: []Resource{}, Facets: []Facet{}, Relationships: []Relationship{}, Telemetry: []TelemetryEvent{}}
	for _, resource := range resources {
		slices.SortFunc(resource.Assertions, func(left, right ResourceAssertion) int {
			return cmp.Compare(assertionOrder(left), assertionOrder(right))
		})
		snapshot.Resources = append(snapshot.Resources, *resource)
	}
	for _, facet := range facets {
		slices.SortFunc(facet.Assertions, func(left, right FacetAssertion) int {
			return cmp.Compare(facetAssertionOrder(left), facetAssertionOrder(right))
		})
		snapshot.Facets = append(snapshot.Facets, *facet)
	}
	for _, relationship := range relationships {
		slices.SortFunc(relationship.Assertions, func(left, right RelationshipAssertion) int {
			return cmp.Compare(relationshipAssertionOrder(left), relationshipAssertionOrder(right))
		})
		snapshot.Relationships = append(snapshot.Relationships, *relationship)
	}
	for _, event := range telemetry {
		snapshot.Telemetry = append(snapshot.Telemetry, event)
	}
	snapshot.Conflicts = conflicts
	slices.SortFunc(snapshot.Resources, func(left, right Resource) int { return cmp.Compare(left.ID, right.ID) })
	slices.SortFunc(snapshot.Facets, func(left, right Facet) int { return cmp.Compare(left.ID, right.ID) })
	slices.SortFunc(snapshot.Relationships, func(left, right Relationship) int { return cmp.Compare(left.ID, right.ID) })
	slices.SortFunc(snapshot.Telemetry, func(left, right TelemetryEvent) int { return cmp.Compare(left.ID, right.ID) })
	slices.SortFunc(snapshot.Conflicts, func(left, right AssertionConflict) int { return cmp.Compare(left.ResourceID, right.ResourceID) })
	return snapshot
}

// Reverse returns a copy of input with every assertion slice reversed. Tests
// use it to prove that compiled output does not depend on input order.
func Reverse(input Input) Input {
	reversed := Input{
		Resources:     slices.Clone(input.Resources),
		Facets:        slices.Clone(input.Facets),
		Relationships: slices.Clone(input.Relationships),
		Telemetry:     slices.Clone(input.Telemetry),
	}
	reverse(reversed.Resources)
	reverse(reversed.Facets)
	reverse(reversed.Relationships)
	reverse(reversed.Telemetry)
	return reversed
}

func (c *Compiler) resolve(claim IdentityClaim) (IdentityClaim, string, error) {
	definition, ok := c.registry.definitions[claim.Scheme]
	if !ok {
		return IdentityClaim{}, "", fmt.Errorf("identity scheme %s is not registered", formatIdentityScheme(claim.Scheme))
	}
	normalized, err := definition.Normalize(claim)
	if err != nil {
		return IdentityClaim{}, "", err
	}
	return normalized, resourceID(normalized), nil
}

// CanonicalJSON encodes the snapshot. Because the compiler sorts every slice
// and encoding/json sorts map keys, equal snapshots encode to equal bytes.
func (s Snapshot) CanonicalJSON() ([]byte, error) {
	return json.Marshal(s)
}

// MarshalIndent encodes the snapshot for human inspection. Do not hash it.
func (s Snapshot) MarshalIndent() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// Hash returns the hex SHA-256 of CanonicalJSON.
func (s Snapshot) Hash() (string, error) {
	data, err := s.CanonicalJSON()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func validateResourceAssertion(assertion ResourceAssertion) error {
	if assertion.Kind == "" || assertion.PluginID == "" || assertion.SourceID == "" || assertion.RuleID == "" {
		return errors.New("resource assertion requires kind, source provenance, and a rule")
	}
	return nil
}

func validateRelationshipAssertion(assertion RelationshipAssertion) error {
	if !IsRegisteredPredicate(assertion.Predicate) || assertion.PluginID == "" || assertion.SourceID == "" || assertion.RuleID == "" {
		return errors.New("relationship assertion requires a registered predicate, source provenance, and a rule")
	}
	if _, err := DecodeSecuritySemantics(assertion.Properties); err != nil {
		return fmt.Errorf("relationship assertion security semantics: %w", err)
	}
	return nil
}

func validateFacetAssertion(assertion FacetAssertion) error {
	if assertion.Kind == "" || assertion.Key == "" || assertion.PluginID == "" || assertion.SourceID == "" || assertion.RuleID == "" {
		return errors.New("facet assertion requires kind, key, source provenance, and a rule")
	}
	if _, err := DecodeSecuritySemantics(assertion.Attributes); err != nil {
		return fmt.Errorf("facet assertion security semantics: %w", err)
	}
	return nil
}

func validateTelemetryAssertion(assertion TelemetryAssertion) error {
	if assertion.EventID == "" || assertion.Kind == "" || assertion.Count == 0 || assertion.PluginID == "" || assertion.SourceID == "" || assertion.RuleID == "" {
		return errors.New("telemetry assertion requires event identity, kind, positive count, source provenance, and a rule")
	}
	return nil
}

func stableJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	return string(data), err
}

func assertionOrder(assertion ResourceAssertion) string {
	value, _ := stableJSON(assertion)
	return value
}

func relationshipAssertionOrder(assertion RelationshipAssertion) string {
	value, _ := stableJSON(assertion)
	return value
}

func facetAssertionOrder(assertion FacetAssertion) string {
	value, _ := stableJSON(assertion)
	return value
}

func reverse[T any](values []T) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func resourceID(claim IdentityClaim) string {
	return uuidV5(resourceNamespace, encodeParts(claim.Scheme.Group, claim.Scheme.Version, claim.Scheme.Kind, claim.AuthorityID, claim.ImmutableKey))
}

func relationshipID(subjectID string, predicate Predicate, objectID, qualifier string) string {
	return uuidV5(relationshipNamespace, encodeParts(subjectID, string(predicate), objectID, qualifier))
}

func facetID(resourceID, kind, key string) string {
	return uuidV5(facetNamespace, encodeParts(resourceID, kind, key))
}

func telemetryID(pluginID, sourceID, eventID string) string {
	return uuidV5(telemetryNamespace, encodeParts(pluginID, sourceID, eventID))
}

// encodeParts length-prefixes each part so distinct tuples cannot collide by
// concatenation (for example "ab"+"c" and "a"+"bc").
func encodeParts(parts ...string) []byte {
	var result []byte
	for _, part := range parts {
		bytes := []byte(part)
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(bytes)))
		result = append(result, length...)
		result = append(result, bytes...)
	}
	return result
}

// UUIDv5 namespaces for derived IDs. Changing any of them changes every stored
// ID of that type.
var resourceNamespace = [16]byte{0x3b, 0xa7, 0x6f, 0x55, 0xa5, 0x94, 0x51, 0xaa, 0x87, 0x30, 0x8e, 0x16, 0xe5, 0x9f, 0x11, 0x3c}
var relationshipNamespace = [16]byte{0x18, 0x26, 0xf7, 0x76, 0x94, 0xeb, 0x58, 0x38, 0x92, 0x31, 0xe4, 0x66, 0xa8, 0xf1, 0x4e, 0xad}
var facetNamespace = [16]byte{0x5d, 0x8a, 0x2a, 0x25, 0x41, 0x85, 0x55, 0x7e, 0xa8, 0x17, 0x15, 0x32, 0x4d, 0x78, 0x2b, 0x61}
var telemetryNamespace = [16]byte{0x9f, 0x1c, 0xb0, 0x44, 0x71, 0x63, 0x52, 0xcf, 0x9b, 0xcd, 0xa3, 0x17, 0x2b, 0x1f, 0x7e, 0x09}

func uuidV5(namespace [16]byte, name []byte) string {
	hash := sha1.New()
	_, _ = hash.Write(namespace[:])
	_, _ = hash.Write(name)
	value := hash.Sum(nil)[:16]
	value[6] = (value[6] & 0x0f) | 0x50
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}
