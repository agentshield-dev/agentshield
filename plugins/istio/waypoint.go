package istio

import (
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesapi "github.com/agentshield-dev/agentshield/plugins/kubernetes/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

// projectAmbientAndWaypoints emits an istio-data-plane facet for each
// Namespace, Pod, Service, and ServiceEntry that declares ambient enrollment
// or a waypoint, and a governed-by edge to the waypoint Gateway when the
// binding resolves. Objects with neither label get no facet.
//
// Label precedence: istio.io/use-waypoint on the object overrides the
// namespace's label ("direct"); otherwise the namespace's value applies
// ("inherited"). The value "none" opts the object out of a namespace waypoint.
// The waypoint's namespace is the object's istio.io/use-waypoint-namespace,
// else the namespace's (only when the name was inherited), else the object's
// own namespace.
//
// waypoint-binding records how far the named waypoint was confirmed:
//   - none: no waypoint is named, or the name is "none".
//   - coverage-unknown: Gateway API Gateways are not watched, so a missing
//     Gateway proves nothing; or admission depends on a Selector listener and
//     the target's Namespace has not been observed.
//   - missing: Gateways are watched and none has that name, or the named
//     Gateway's class is not istio-waypoint.
//   - traffic-type-mismatch: the Gateway's istio.io/waypoint-for excludes
//     this target's traffic type.
//   - disallowed: no listener admits the target's namespace.
//   - not-ready: the Gateway is not Programmed.
//   - resolved: every check passed. Only this state produces an edge.
func (projector *projection) projectAmbientAndWaypoints() error {
	for _, target := range projector.index.items {
		if !waypointCandidate(target.Object) {
			continue
		}
		namespace, hasNamespace := projector.index.namespaces[target.Object.GetNamespace()]
		// A Namespace is its own source of inherited labels.
		if target.Object.GetKind() == "Namespace" {
			namespace, hasNamespace = target, true
		}
		namespaceLabels := map[string]string{}
		if hasNamespace {
			namespaceLabels = namespace.Object.GetLabels()
		}
		directName, direct := target.Object.GetLabels()["istio.io/use-waypoint"]
		waypointName := strings.TrimSpace(directName)
		intentSource := "direct"
		intentEvidence := target.EventID
		// A label that is present wins even when empty, so it never falls
		// through to the namespace.
		if !direct {
			waypointName = strings.TrimSpace(namespaceLabels["istio.io/use-waypoint"])
			intentSource = "inherited"
			if hasNamespace {
				intentEvidence = namespace.EventID
			}
		}
		waypointNamespace := target.Object.GetNamespace()
		if target.Object.GetKind() == "Namespace" {
			waypointNamespace = target.Object.GetName()
		}
		if value := strings.TrimSpace(target.Object.GetLabels()["istio.io/use-waypoint-namespace"]); value != "" {
			waypointNamespace = value
		} else if !direct {
			if value := strings.TrimSpace(namespaceLabels["istio.io/use-waypoint-namespace"]); value != "" {
				waypointNamespace = value
			}
		}
		dataPlane := projector.dataPlaneIntent(target)
		if waypointName == "" && dataPlane == "unspecified" {
			continue
		}
		attributes := map[string]string{
			"data-plane-intent":      dataPlane,
			"waypoint-intent-source": intentSource,
			"waypoint-binding":       "none",
			"evidence-source":        "labels",
		}
		evidence := []string{target.EventID}
		if waypointName != "" && !strings.EqualFold(waypointName, "none") {
			attributes["waypoint-name"] = waypointName
			attributes["waypoint-namespace"] = waypointNamespace
			attributes["waypoint-binding"] = "coverage-unknown"
			if projector.context.GatewayCoverageKnown {
				attributes["waypoint-binding"] = "missing"
			}
			gateway, found := projector.index.gateways[namespacedName(waypointNamespace, waypointName)]
			if found {
				evidence = append(evidence, intentEvidence, gateway.EventID)
				binding, err := projector.waypointBinding(target, namespace, gateway)
				if err != nil {
					return err
				}
				attributes["waypoint-binding"] = binding
				attributes["evidence-source"] = "labels-and-gateway"
				// The edge records that traffic to the target passes through
				// this waypoint, not which policies the waypoint enforces, so
				// the effect is unknown and coverage partial.
				if binding == "resolved" {
					properties, err := graph.WithSecuritySemantics(map[string]string{"semantic": "istio-waypoint-intent-association"}, graph.SecuritySemantics{
						Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainNetworkAccess,
						State: graph.SecurityStateObserved, Effect: "unknown", Scope: waypointScope(target.Object), Direction: "ingress", Coverage: "partial",
						ConfigurationDigest: projectkit.Digest(map[string]any{"waypointName": waypointName, "waypointNamespace": waypointNamespace, "intentSource": intentSource}),
					})
					if err != nil {
						return err
					}
					projector.input.Relationships = append(projector.input.Relationships, relationship(
						projector.context.SourceID, "istio.waypoint-association", target.Claim, graph.PredicateGovernedBy, gateway.Claim,
						"istio-waypoint", properties, evidence...,
					))
				}
			}
		}
		pluginID, sourceID, evidenceIDs := provenance(projector.context.SourceID, evidence...)
		projector.input.Facets = append(projector.input.Facets, graph.FacetAssertion{
			Resource: target.Claim, Kind: "istio-data-plane", Key: "ambient", Attributes: attributes,
			PluginID: pluginID, SourceID: sourceID, RuleID: "istio.ambient-intent", EvidenceIDs: evidenceIDs,
		})
	}
	return nil
}

// waypointScope maps the labeled kind to the security-semantics scope of the
// waypoint association.
func waypointScope(item *unstructured.Unstructured) string {
	switch item.GetKind() {
	case "Namespace":
		return "namespace"
	case "Pod":
		return "workload"
	default:
		return "service"
	}
}

// dataPlaneIntent reads istio.io/dataplane-mode, with the object's label
// overriding its namespace's. "none" opts a workload out of an ambient
// namespace; any other value, or no label, is "unspecified".
func (projector *projection) dataPlaneIntent(target indexedObject) string {
	namespaceLabels := map[string]string{}
	if namespace, ok := projector.index.namespaces[target.Object.GetNamespace()]; ok {
		namespaceLabels = namespace.Object.GetLabels()
	}
	if target.Object.GetKind() == "Namespace" {
		namespaceLabels = target.Object.GetLabels()
	}
	mode := effectiveLabel(target.Object.GetLabels(), namespaceLabels, "istio.io/dataplane-mode")
	switch mode {
	case "ambient":
		return "ambient"
	case "none":
		return "none"
	default:
		return "unspecified"
	}
}

// waypointBinding checks the named Gateway against what Istio requires of a
// waypoint: class, traffic type, namespace admission, and readiness. It
// returns the first failing state, or "resolved".
func (projector *projection) waypointBinding(target, namespace, gateway indexedObject) (string, error) {
	decoded, err := kubernetesapi.GatewayObject(gateway.Object)
	if err != nil {
		return "", err
	}
	gatewayAPI := decoded.Value
	if gatewayAPI.Spec.GatewayClassName != "istio-waypoint" {
		return "missing", nil
	}
	wants := waypointTargetType(target.Object)
	waypointFor := strings.ToLower(strings.TrimSpace(gateway.Object.GetLabels()["istio.io/waypoint-for"]))
	// Istio's default when the Gateway does not set istio.io/waypoint-for.
	if waypointFor == "" {
		waypointFor = "service"
	}
	if waypointFor != "all" && waypointFor != wants {
		return "traffic-type-mismatch", nil
	}
	namespaceName := target.Object.GetNamespace()
	if target.Object.GetKind() == "Namespace" {
		namespaceName = target.Object.GetName()
	}
	// namespace.Object is nil when the target's Namespace has not been observed.
	var namespaceLabels map[string]string
	if namespace.Object != nil {
		namespaceLabels = namespace.Object.GetLabels()
	}
	allowed, known := gatewayAllowsNamespace(&gatewayAPI, namespaceName, namespaceLabels, namespace.Object != nil)
	if !known {
		return "coverage-unknown", nil
	}
	if !allowed {
		return "disallowed", nil
	}
	if !gatewayReady(&gatewayAPI) {
		return "not-ready", nil
	}
	return "resolved", nil
}

// waypointCandidate reports whether item is a kind that accepts
// istio.io/use-waypoint. Gateway and waypoint proxy Pods are excluded: they
// would otherwise inherit their namespace's label and appear bound to
// themselves.
func waypointCandidate(item *unstructured.Unstructured) bool {
	if item == nil || string(item.GetUID()) == "" {
		return false
	}
	if item.GetKind() == "Pod" && (item.GetLabels()["gateway.networking.k8s.io/gateway-name"] != "" || item.GetLabels()["gateway.istio.io/managed"] != "") {
		return false
	}
	switch item.GetKind() {
	case "Namespace", "Pod", "Service", "ServiceEntry":
		return true
	default:
		return false
	}
}

// waypointTargetType returns the istio.io/waypoint-for value the target needs.
// Pods carry workload traffic; Services, ServiceEntries, and Namespaces are
// checked as service traffic, which is the waypoint-for default.
func waypointTargetType(item *unstructured.Unstructured) string {
	if item.GetKind() == "Pod" {
		return "workload"
	}
	return "service"
}

// gatewayReady reports whether the Gateway's controller set Programmed=True.
func gatewayReady(gateway *kubernetesapi.Gateway) bool {
	for _, condition := range gateway.Status.Conditions {
		if condition.Type == "Programmed" && condition.Status == "True" {
			return true
		}
	}
	return false
}

// gatewayAllowsNamespace applies Gateway API allowedRoutes, which Istio uses
// to decide which namespaces may use a waypoint. One admitting listener is
// enough. known is false when the answer depends on a Selector listener and
// the Namespace's labels were not observed.
func gatewayAllowsNamespace(gateway *kubernetesapi.Gateway, namespaceName string, namespaceLabels map[string]string, labelsObserved bool) (allowed, known bool) {
	// No listeners means no allowedRoutes to check, so nothing is refused.
	if len(gateway.Spec.Listeners) == 0 {
		return true, true
	}
	known = true
	for _, listener := range gateway.Spec.Listeners {
		// Unset allowedRoutes defaults to from: Same.
		if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil {
			if namespaceName == gateway.GetNamespace() {
				return true, true
			}
			continue
		}
		namespaces := listener.AllowedRoutes.Namespaces
		switch namespaces.From {
		case "All":
			return true, true
		case "Selector":
			if namespaces.Selector == nil {
				continue
			}
			// An invalid selector admits nothing.
			selector, err := metav1.LabelSelectorAsSelector(namespaces.Selector)
			if err != nil {
				continue
			}
			if !labelsObserved {
				known = false
				continue
			}
			if selector.Matches(labels.Set(namespaceLabels)) {
				return true, true
			}
		default: // "Same" or unset.
			if namespaceName == gateway.GetNamespace() {
				return true, true
			}
		}
	}
	return false, known
}
