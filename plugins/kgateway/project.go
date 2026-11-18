package kgateway

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	kubernetesapi "github.com/agentshield-dev/agentshield/plugins/kubernetes/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const (
	// PluginID is the plugin and contribution owner ID.
	PluginID = "kgateway"
	// DefaultControllerName is the GatewayClass controller OSS kgateway
	// registers.
	DefaultControllerName = "kgateway.dev/kgateway"

	kgatewayAPIVersion   = "gateway.kgateway.dev/v1alpha1"
	gatewayAPIGroup      = "gateway.networking.k8s.io"
	gatewayAPIVersion    = gatewayAPIGroup + "/v1"
	kgatewayGroup        = "gateway.kgateway.dev"
	kindTrafficPolicy    = "TrafficPolicy"
	kindListenerPolicy   = "ListenerPolicy"
	kindBackendConfig    = "BackendConfigPolicy"
	kindBackend          = "Backend"
	kindDirectResponse   = "DirectResponse"
	kindGatewayExtension = "GatewayExtension"
	kindGatewayParams    = "GatewayParameters"
)

type projection struct {
	context     ProjectionContext
	input       graph.Input
	diagnostics []Diagnostic
	objects     []ObservedObject
	byKind      map[string][]ObservedObject
	named       map[string]ObservedObject
}

// Project projects bare objects with every capability covered, deriving
// evidence IDs from object identity and resource version. It exists for tests
// and offline evaluation; the plugin uses [ProjectObserved].
func Project(clusterID, sourceID string, objects []*unstructured.Unstructured) (graph.Input, error) {
	observations := make([]ObservedObject, 0, len(objects))
	for _, object := range objects {
		if object == nil {
			continue
		}
		observations = append(observations, ObservedObject{Key: projectkit.ObjectKey(object), Object: object, EventID: projectkit.KubernetesEvidenceID(object), Revision: object.GetResourceVersion()})
	}
	coverage := make(map[string]CoverageState, len(resourceRequirements))
	for _, requirement := range resourceRequirements {
		coverage[requirement.Capability] = CoverageStateCovered
	}
	result, err := ProjectObserved(ProjectionContext{ClusterID: clusterID, SourceID: sourceID, Coverage: coverage}, observations)
	return result.Input, err
}

// ProjectObserved deterministically projects one coherent snapshot. The
// result is independent of observation order.
func ProjectObserved(scope ProjectionContext, observations []ObservedObject) (ProjectionResult, error) {
	scope.ClusterID = strings.TrimSpace(scope.ClusterID)
	scope.SourceID = strings.TrimSpace(scope.SourceID)
	scope.NetworkID = strings.TrimSpace(scope.NetworkID)
	if scope.ClusterID == "" || scope.SourceID == "" {
		return ProjectionResult{}, errors.New("cluster and source IDs are required")
	}
	if scope.NetworkID == "" {
		scope.NetworkID = scope.ClusterID
	}
	scope.ControllerNames = normalizedSet(scope.ControllerNames, DefaultControllerName)
	projector := &projection{context: scope}
	if err := projector.buildIndex(observations); err != nil {
		return ProjectionResult{}, err
	}
	steps := []func() error{
		projector.projectGatewayExtensions,
		projector.projectTrafficPolicies,
		projector.projectListenerPolicies,
		projector.projectBackends,
		projector.projectBackendConfigPolicies,
		projector.projectDirectResponses,
		projector.projectGatewayParameters,
		projector.projectGatewayCoverage,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return ProjectionResult{}, err
		}
	}
	projector.sortOutput()
	return ProjectionResult{Input: projector.input, Diagnostics: projector.diagnostics}, nil
}

func (p *projection) buildIndex(observations []ObservedObject) error {
	p.byKind = make(map[string][]ObservedObject)
	p.named = make(map[string]ObservedObject)
	for _, observation := range observations {
		if observation.Object == nil {
			continue
		}
		copy := observation
		if copy.Key == "" {
			copy.Key = projectkit.ObjectKey(copy.Object)
		}
		if copy.EventID == "" {
			copy.EventID = projectkit.KubernetesEvidenceID(copy.Object)
		}
		p.objects = append(p.objects, copy)
	}
	sort.Slice(p.objects, func(i, j int) bool { return p.objects[i].Key < p.objects[j].Key })
	for _, observation := range p.objects {
		item := observation.Object
		kind, tracked := trackedKind(item)
		if !tracked {
			continue
		}
		if item.GetUID() == "" {
			return fmt.Errorf("project %s %s/%s: metadata.uid is required", item.GetKind(), item.GetNamespace(), item.GetName())
		}
		p.byKind[kind] = append(p.byKind[kind], observation)
		p.named[objectName(kind, item.GetNamespace(), item.GetName())] = observation
	}
	return nil
}

// trackedKind returns the index key for objects this plugin reads.
func trackedKind(item *unstructured.Unstructured) (string, bool) {
	switch item.GetAPIVersion() {
	case kgatewayAPIVersion:
		switch item.GetKind() {
		case kindTrafficPolicy, kindListenerPolicy, kindBackendConfig, kindBackend, kindDirectResponse, kindGatewayExtension, kindGatewayParams:
			return item.GetKind(), true
		}
	case gatewayAPIVersion:
		switch item.GetKind() {
		case "GatewayClass", "Gateway", "HTTPRoute":
			return item.GetKind(), true
		}
	case "v1":
		if item.GetKind() == "Service" {
			return "Service", true
		}
	}
	return "", false
}

func objectName(kind, namespace, name string) string { return kind + "/" + namespace + "/" + name }

func (p *projection) lookup(kind, namespace, name string) (ObservedObject, bool) {
	observation, found := p.named[objectName(kind, namespace, name)]
	return observation, found
}

func (p *projection) diagnose(observation ObservedObject, code, message string) {
	p.diagnostics = append(p.diagnostics, Diagnostic{Resource: projectkit.DisplayName(observation.Object), Code: code, Message: message})
}

// projectGatewayCoverage records which kgateway capabilities were observable
// on every Gateway managed by a configured controller, so a missing policy
// edge can be told apart from an API that was never watched.
func (p *projection) projectGatewayCoverage() error {
	attributes := map[string]string{}
	for _, requirement := range resourceRequirements {
		if !strings.HasPrefix(requirement.Capability, "kgateway-") || requirement.Required {
			continue
		}
		state, found := p.context.Coverage[requirement.Capability]
		if !found {
			state = CoverageStateUnknown
		}
		attributes["kgateway/coverage/"+requirement.GVR.Resource] = string(state)
	}
	for _, observation := range p.byKind["Gateway"] {
		decoded, err := kubernetesapi.Decode[gateway](observation.Object)
		if err != nil {
			return fmt.Errorf("decode Gateway %q: %w", observation.Key, err)
		}
		class, found := p.lookup("GatewayClass", "", decoded.Value.Spec.GatewayClassName)
		if !found || !p.managedClass(class) {
			continue
		}
		p.addFacet(observation, "kgateway-coverage", "capabilities", attributes, "kgateway.gateway.coverage", class)
	}
	return nil
}

func (p *projection) managedClass(class ObservedObject) bool {
	decoded, err := kubernetesapi.Decode[gatewayClass](class.Object)
	return err == nil && contains(p.context.ControllerNames, decoded.Value.Spec.ControllerName)
}

// addResource enriches a resource the Kubernetes plugin already asserts; the
// kind must match its kubernetes/<kind> or the graph withholds both as a conflict.
func (p *projection) addResource(observation ObservedObject, ruleID string, attributes map[string]string) {
	p.input.Resources = append(p.input.Resources, graph.ResourceAssertion{
		Claim: kubernetesplugin.ClaimFor(p.context.ClusterID, observation.Object), Kind: "kubernetes/" + strings.ToLower(observation.Object.GetKind()), DisplayName: projectkit.DisplayName(observation.Object), Attributes: attributes,
		PluginID: PluginID, SourceID: p.context.SourceID, RuleID: ruleID, EvidenceIDs: evidenceIDs(observation),
	})
}

func (p *projection) addFacet(observation ObservedObject, kind, key string, attributes map[string]string, ruleID string, additional ...ObservedObject) {
	evidence := append([]ObservedObject{observation}, additional...)
	p.input.Facets = append(p.input.Facets, graph.FacetAssertion{
		Resource: kubernetesplugin.ClaimFor(p.context.ClusterID, observation.Object), Kind: kind, Key: key, Attributes: attributes,
		PluginID: PluginID, SourceID: p.context.SourceID, RuleID: ruleID, EvidenceIDs: evidenceIDs(evidence...),
	})
}

func (p *projection) addRelationship(subject ObservedObject, predicate graph.Predicate, object graph.IdentityClaim, qualifier string, properties map[string]string, ruleID string, evidence ...ObservedObject) {
	p.input.Relationships = append(p.input.Relationships, graph.RelationshipAssertion{
		Subject: kubernetesplugin.ClaimFor(p.context.ClusterID, subject.Object), Predicate: predicate, Object: object, Qualifier: qualifier, Properties: properties,
		PluginID: PluginID, SourceID: p.context.SourceID, RuleID: ruleID, EvidenceIDs: evidenceIDs(append([]ObservedObject{subject}, evidence...)...),
	})
}

func (p *projection) claim(observation ObservedObject) graph.IdentityClaim {
	return kubernetesplugin.ClaimFor(p.context.ClusterID, observation.Object)
}

func (p *projection) sortOutput() {
	sort.Slice(p.input.Resources, func(i, j int) bool {
		return assertionKey(p.input.Resources[i].Claim, p.input.Resources[i].RuleID) < assertionKey(p.input.Resources[j].Claim, p.input.Resources[j].RuleID)
	})
	sort.Slice(p.input.Facets, func(i, j int) bool {
		return assertionKey(p.input.Facets[i].Resource, p.input.Facets[i].Kind+p.input.Facets[i].Key) < assertionKey(p.input.Facets[j].Resource, p.input.Facets[j].Kind+p.input.Facets[j].Key)
	})
	sort.Slice(p.input.Relationships, func(i, j int) bool {
		left, right := p.input.Relationships[i], p.input.Relationships[j]
		return assertionKey(left.Subject, string(left.Predicate)+left.Qualifier+left.Object.ImmutableKey) < assertionKey(right.Subject, string(right.Predicate)+right.Qualifier+right.Object.ImmutableKey)
	})
	sort.Slice(p.diagnostics, func(i, j int) bool {
		return p.diagnostics[i].Resource+p.diagnostics[i].Code+p.diagnostics[i].Message < p.diagnostics[j].Resource+p.diagnostics[j].Code+p.diagnostics[j].Message
	})
}

func policyAccepted(status policyStatus, controllers []string) string {
	values := make(map[string]struct{})
	for _, ancestor := range status.Ancestors {
		if contains(controllers, ancestor.ControllerName) {
			values[conditionValue(ancestor.Conditions, "Accepted")] = struct{}{}
		}
	}
	if len(values) == 0 {
		return "unknown"
	}
	ordered := make([]string, 0, len(values))
	for value := range values {
		ordered = append(ordered, value)
	}
	sort.Strings(ordered)
	return strings.Join(ordered, ",")
}

func conditionValue(conditions []metav1.Condition, conditionType string) string {
	for _, condition := range conditions {
		if condition.Type == conditionType {
			return strings.ToLower(string(condition.Status))
		}
	}
	return "unknown"
}

func evidenceIDs(observations ...ObservedObject) []string {
	set := make(map[string]struct{}, len(observations))
	for _, observation := range observations {
		if observation.EventID != "" {
			set[observation.EventID] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func assertionKey(claim graph.IdentityClaim, suffix string) string {
	return strings.Join([]string{claim.Scheme.Group, claim.Scheme.Version, claim.Scheme.Kind, claim.AuthorityID, claim.ImmutableKey, suffix}, "/")
}

func normalizedSet(values []string, fallback string) []string {
	if len(values) == 0 {
		values = []string{fallback}
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func contains(values []string, target string) bool {
	index := sort.SearchStrings(values, strings.TrimSpace(target))
	return index < len(values) && values[index] == strings.TrimSpace(target)
}

func sortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
