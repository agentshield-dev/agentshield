package istio

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	istioapi "github.com/agentshield-dev/agentshield/plugins/istio/api"
)

// projectPeerAuthentications emits a resource per PeerAuthentication and, for
// valid declarations, a governed-by edge and istio-mtls facet on each target.
//
// Scope follows Istio: a selector makes the policy workload-scoped (Pods in
// the policy's namespace whose labels match); no selector in the mesh root
// namespace makes it mesh-wide; no selector elsewhere makes it
// namespace-wide. Mesh and namespace policies attach to Namespace nodes rather
// than fanning out to every Pod.
//
// Each declaration is recorded as-is. Istio picks the narrowest policy, the
// oldest when several share a level, and UNSET inherits from the parent; that
// effective mode is not computed here (effective-mode-evaluated=false).
func (projector *projection) projectPeerAuthentications() error {
	for _, observed := range projector.index.byKind["PeerAuthentication"] {
		policy := observed.Object
		if policy.GetAPIVersion() != "security.istio.io/v1" {
			continue
		}
		decoded, err := istioapi.PeerAuthenticationObject(policy)
		if err != nil {
			return err
		}
		peerAuthentication := decoded.Value
		mode := ""
		if peerAuthentication.Spec.Mtls != nil {
			mode = peerAuthentication.Spec.Mtls.Mode
		}
		if mode == "" {
			mode = "UNSET"
		}
		mode = strings.ToUpper(mode)
		selector := map[string]string(nil)
		if peerAuthentication.Spec.Selector != nil {
			selector = peerAuthentication.Spec.Selector.MatchLabels
		}
		portLevel := peerAuthentication.Spec.PortLevelMtls
		scope := "namespace"
		// An empty matchLabels selects the whole namespace, as in Istio.
		if len(selector) > 0 {
			scope = "workload"
		} else if policy.GetNamespace() == projector.context.RootNamespace {
			scope = "mesh"
		}
		validModes := map[string]bool{"UNSET": true, "DISABLE": true, "PERMISSIVE": true, "STRICT": true}
		validation := "valid"
		// Istio rejects portLevelMtls without a workload selector.
		if !validModes[mode] || (len(portLevel) > 0 && len(selector) == 0) {
			validation = "invalid-declaration"
			projector.diagnostics = append(projector.diagnostics, Diagnostic{Code: validation, Resource: projectkit.DisplayName(policy)})
		}
		attributes := map[string]string{
			"kubernetes/api-version":                policy.GetAPIVersion(),
			"kubernetes/name":                       policy.GetName(),
			"kubernetes/namespace":                  policy.GetNamespace(),
			"istio/declared-mode":                   mode,
			"istio/scope":                           scope,
			"istio/port-override-count":             strconv.Itoa(len(portLevel)),
			"istio/port-overrides-sha256":           projectkit.Digest(portLevel),
			"istio/port-overrides-require-selector": strconv.FormatBool(len(portLevel) > 0),
			"istio/validation":                      validation,
		}
		projector.input.Resources = append(projector.input.Resources, resourceAssertion(projector.context.SourceID, observed, "istio/peerauthentication", "istio.peer-authentication", attributes))
		// An invalid policy is still a resource, but Istio does not apply
		// it, so it governs nothing.
		if validation != "valid" {
			continue
		}
		var targets []indexedObject
		switch scope {
		case "mesh":
			names := make([]string, 0, len(projector.index.namespaces))
			for name := range projector.index.namespaces {
				names = append(names, name)
			}
			slices.Sort(names)
			for _, name := range names {
				targets = append(targets, projector.index.namespaces[name])
			}
		case "namespace":
			if namespace, ok := projector.index.namespaces[policy.GetNamespace()]; ok {
				targets = append(targets, namespace)
			}
		case "workload":
			targets = projector.index.podsSelectedBy(policy.GetNamespace(), projector.context.RootNamespace, selector)
		}
		for _, target := range targets {
			if err := projector.addPeerAuthenticationTarget(target, observed, mode, scope, portLevel); err != nil {
				return err
			}
		}
	}
	return nil
}

// addPeerAuthenticationTarget records one policy on one target. The facet key
// includes the policy name so several policies on a target stay separate.
// Direction is ingress because PeerAuthentication controls what the target
// accepts.
func (projector *projection) addPeerAuthenticationTarget(target, policy indexedObject, mode, scope string, portLevel map[string]istioapi.MutualTLS) error {
	ambient := projector.dataPlaneIntent(target) == "ambient"
	compatibility := "supported"
	if mode == "UNSET" {
		compatibility = "inherited"
	} else if mode == "DISABLE" && ambient {
		// Ambient always uses mTLS between enrolled workloads; Istio does not
		// support DISABLE there.
		compatibility = "unsupported-in-ambient"
	}
	attributes := map[string]string{
		"policy":                   projectkit.DisplayName(policy.Object),
		"declared-mode":            mode,
		"scope":                    scope,
		"port-override-count":      strconv.Itoa(len(portLevel)),
		"port-overrides-sha256":    projectkit.Digest(portLevel),
		"ambient-target":           strconv.FormatBool(ambient),
		"compatibility":            compatibility,
		"effective-mode-evaluated": "false",
	}
	pluginID, sourceID, evidence := provenance(projector.context.SourceID, target.EventID, policy.EventID)
	projector.input.Facets = append(projector.input.Facets, graph.FacetAssertion{
		Resource: target.Claim, Kind: "istio-mtls", Key: "peerauthentication/" + strings.ToLower(projectkit.DisplayName(policy.Object)), Attributes: attributes,
		PluginID: pluginID, SourceID: sourceID, RuleID: "istio.peer-authentication-facet", EvidenceIDs: evidence,
	})
	effect := map[string]string{"STRICT": "require", "PERMISSIVE": "permit", "DISABLE": "disable", "UNSET": "inherit"}[mode]
	// Port overrides can set a different mode on listed ports, so the
	// top-level effect does not describe every port.
	coverage := "complete"
	if len(portLevel) > 0 {
		coverage = "partial"
	}
	ports := make([]graph.SecurityPort, 0, len(portLevel))
	for value := range portLevel {
		// portLevelMtls keys are workload port numbers.
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			coverage = "partial"
			continue
		}
		ports = append(ports, graph.SecurityPort{Protocol: "TCP", Port: uint16(port)})
	}
	slices.SortFunc(ports, func(left, right graph.SecurityPort) int { return int(left.Port) - int(right.Port) })
	if len(ports) > 64 {
		ports = ports[:64]
		coverage = "partial"
	}
	semantics := graph.SecuritySemantics{
		Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainTransportAuthentication,
		State: graph.SecurityStateDeclared, Effect: effect, Scope: scope, Direction: "ingress", Coverage: coverage,
		Protocols: []string{"MTLS"}, Ports: ports, ConfigurationDigest: "sha256:" + projectkit.Digest(map[string]any{"mode": mode, "scope": scope, "ports": portLevel}),
	}
	properties, err := graph.WithSecuritySemantics(map[string]string{"declared-mode": mode, "effective-mode-evaluated": "false"}, semantics)
	if err != nil {
		return fmt.Errorf("peer authentication %s semantics: %w", projectkit.DisplayName(policy.Object), err)
	}
	projector.input.Relationships = append(projector.input.Relationships, relationship(
		projector.context.SourceID, "istio.peer-authentication-target", target.Claim, graph.PredicateGovernedBy, policy.Claim,
		"istio-peer-authentication-"+scope, properties, target.EventID, policy.EventID,
	))
	return nil
}
