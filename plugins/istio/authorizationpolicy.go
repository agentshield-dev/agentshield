package istio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	istioapi "github.com/agentshield-dev/agentshield/plugins/istio/api"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func (projector *projection) projectAuthorizationPolicies() error {
	for _, observed := range projector.index.byKind["AuthorizationPolicy"] {
		policy := observed.Object
		if policy.GetAPIVersion() != "security.istio.io/v1" {
			continue
		}
		decoded, err := istioapi.AuthorizationPolicyObject(policy)
		if err != nil {
			return err
		}
		policyAPI := decoded.Value
		action := policyAPI.Spec.Action
		if action == "" {
			action = "ALLOW"
		}
		var rules []json.RawMessage
		ruleForm := "omitted"
		if policyAPI.Spec.Rules != nil {
			rules = *policyAPI.Spec.Rules
			ruleForm = "present"
			if len(rules) == 1 && bytes.Equal(bytes.TrimSpace(rules[0]), []byte("{}")) {
				ruleForm = "single-empty-rule"
			}
		}
		ruleBreadth := authorizationRuleBreadth(rules)
		targetRefs := slices.Clone(policyAPI.Spec.TargetRefs)
		selectorPresent := policyAPI.Spec.Selector != nil
		selector := map[string]string(nil)
		if selectorPresent {
			selector = policyAPI.Spec.Selector.MatchLabels
		}
		validation := "valid"
		mechanism := "namespace"
		if selectorPresent && len(selector) > 0 {
			mechanism = "selector"
		}
		if len(targetRefs) > 0 {
			mechanism = "targetRefs"
		}
		if selectorPresent && len(targetRefs) > 0 {
			validation = "invalid-targeting"
			projector.diagnostics = append(projector.diagnostics, Diagnostic{Code: validation, Resource: projectkit.DisplayName(policy)})
		}
		provider := ""
		if policyAPI.Spec.Provider != nil {
			provider = policyAPI.Spec.Provider.Name
		}
		attributes := map[string]string{
			"kubernetes/api-version": policy.GetAPIVersion(),
			"kubernetes/name":        policy.GetName(),
			"kubernetes/namespace":   policy.GetNamespace(),
			"istio/action":           strings.ToUpper(action),
			"istio/dry-run":          strconv.FormatBool(strings.EqualFold(policy.GetAnnotations()["istio.io/dry-run"], "true")),
			"istio/rule-count":       strconv.Itoa(len(rules)),
			"istio/rule-form":        ruleForm,
			"istio/rule-breadth":     ruleBreadth,
			"istio/rules-sha256":     projectkit.Digest(rules),
			"istio/target-mechanism": mechanism,
			"istio/validation":       validation,
		}
		if strings.EqualFold(action, "CUSTOM") && provider != "" {
			attributes["istio/provider"] = provider
		}
		effect := strings.ToLower(action)
		if effect != "allow" && effect != "deny" && effect != "audit" && effect != "custom" {
			effect = "unknown"
		}
		semantics := graph.SecuritySemantics{
			Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainAuthorization,
			State: graph.SecurityStateDeclared, Effect: effect, Scope: authorizationScope(mechanism, policy.GetNamespace() == projector.context.RootNamespace),
			Direction: "ingress", Coverage: "partial", ConfigurationDigest: "sha256:" + projectkit.Digest(map[string]any{
				"action": action, "rules": rules, "selector": selector, "targetRefs": targetRefs, "provider": provider,
			}),
		}
		projector.input.Resources = append(projector.input.Resources, projectedResourceAssertion(projector.context.SourceID, observed, "istio/authorizationpolicy", "istio.authorization-policy", attributes))
		if validation != "valid" {
			continue
		}
		facetAttributes, err := graph.WithSecuritySemantics(map[string]string{
			"istio/action":                strings.ToUpper(action),
			"istio/rule-breadth":          ruleBreadth,
			"istio/target-mechanism":      mechanism,
			"istio/target-resolution":     "governed-by-relationships",
			"istio/declared-target-count": strconv.Itoa(len(targetRefs)),
		}, semantics)
		if err != nil {
			return fmt.Errorf("authorization policy %s posture semantics: %w", projectkit.DisplayName(policy), err)
		}
		projector.input.Facets = append(projector.input.Facets, graph.FacetAssertion{
			Resource: observed.Claim, Kind: "authorization-posture", Key: "istio-policy", Attributes: facetAttributes,
			PluginID: PluginID, SourceID: projector.context.SourceID, RuleID: "istio.authorization-policy-posture",
			EvidenceIDs: []string{observed.EventID},
		})
		switch {
		case len(targetRefs) > 0:
			if err := projector.projectAuthorizationTargetRefs(observed, targetRefs, semantics); err != nil {
				return err
			}
		case len(selector) > 0:
			for _, pod := range projector.index.podsSelectedBy(policy.GetNamespace(), projector.context.RootNamespace, selector) {
				if err := projector.addPolicyGovernance(pod, observed, "istio-authz-selector", semantics); err != nil {
					return err
				}
			}
		case policy.GetNamespace() == projector.context.RootNamespace:
			names := make([]string, 0, len(projector.index.namespaces))
			for name := range projector.index.namespaces {
				names = append(names, name)
			}
			slices.Sort(names)
			for _, name := range names {
				if err := projector.addPolicyGovernance(projector.index.namespaces[name], observed, "istio-authz-mesh", semantics); err != nil {
					return err
				}
			}
		default:
			if namespace, ok := projector.index.namespaces[policy.GetNamespace()]; ok {
				if err := projector.addPolicyGovernance(namespace, observed, "istio-authz-namespace", semantics); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (projector *projection) projectAuthorizationTargetRefs(policy indexedObject, references []istioapi.PolicyTargetReference, semantics graph.SecuritySemantics) error {
	for _, reference := range references {
		name := reference.Name
		kind := reference.Kind
		group := reference.Group
		namespace := reference.Namespace
		if namespace != "" && namespace != policy.Object.GetNamespace() {
			continue
		}
		for _, target := range projector.index.byKind[kind] {
			if target.Object.GetName() != name || target.Object.GetKind() != kind {
				continue
			}
			if !supportedAuthorizationTarget(policy.Object, target.Object, group, projector.context.RootNamespace) {
				continue
			}
			targetSemantics := semantics
			targetSemantics.Scope = authorizationTargetScope(target.Object.GetKind())
			if err := projector.addPolicyGovernance(target, policy, "istio-authz-targetref", targetSemantics); err != nil {
				return err
			}
		}
	}
	return nil
}

func authorizationTargetScope(kind string) string {
	switch kind {
	case "Gateway", "GatewayClass":
		return "gateway"
	default:
		return "service"
	}
}

func supportedAuthorizationTarget(policy, target *unstructured.Unstructured, group, rootNamespace string) bool {
	targetGroup := strings.SplitN(target.GetAPIVersion(), "/", 2)[0]
	if !strings.Contains(target.GetAPIVersion(), "/") {
		targetGroup = ""
	}
	switch target.GetKind() {
	case "Service":
		return target.GetNamespace() == policy.GetNamespace() && (group == "" || group == "core") && targetGroup == ""
	case "Gateway":
		return target.GetNamespace() == policy.GetNamespace() && group == "gateway.networking.k8s.io" && targetGroup == group
	case "ServiceEntry":
		return target.GetNamespace() == policy.GetNamespace() && group == "networking.istio.io" && targetGroup == group
	case "GatewayClass":
		return policy.GetNamespace() == rootNamespace && group == "gateway.networking.k8s.io" && targetGroup == group
	default:
		return false
	}
}

func (projector *projection) addPolicyGovernance(target, policy indexedObject, qualifier string, semantics graph.SecuritySemantics) error {
	properties, err := graph.WithSecuritySemantics(map[string]string{
		"semantic":                "istio-authorization-governance",
		"istio/target-resolution": "resolved-provider-reference",
	}, semantics)
	if err != nil {
		return fmt.Errorf("authorization policy %s semantics: %w", projectkit.DisplayName(policy.Object), err)
	}
	projector.input.Relationships = append(projector.input.Relationships, relationship(
		projector.context.SourceID, "istio.authorization-policy-target", target.Claim, graph.PredicateGovernedBy, policy.Claim,
		qualifier, properties, target.EventID, policy.EventID,
	))
	return nil
}

func authorizationRuleBreadth(rules []json.RawMessage) string {
	if len(rules) == 0 {
		return "no-requests"
	}
	for _, rule := range rules {
		if bytes.Equal(bytes.TrimSpace(rule), []byte("{}")) {
			return "all-requests"
		}
	}
	return "constrained"
}

func authorizationScope(mechanism string, mesh bool) string {
	if mesh {
		return "mesh"
	}
	switch mechanism {
	case "selector":
		return "workload"
	case "targetRefs":
		return "service"
	default:
		return "namespace"
	}
}
