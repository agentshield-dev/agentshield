package kgateway

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesapi "github.com/agentshield-dev/agentshield/plugins/kubernetes/api"
)

// targetKinds maps an attachable group/kind to its index key.
type targetKinds map[string]string

var (
	routeAndGatewayTargets = targetKinds{gatewayAPIGroup + "/Gateway": "Gateway", gatewayAPIGroup + "/HTTPRoute": "HTTPRoute"}
	gatewayTargets         = targetKinds{gatewayAPIGroup + "/Gateway": "Gateway"}
	backendTargets         = targetKinds{"/Service": "Service", "core/Service": "Service", kgatewayGroup + "/Backend": kindBackend}
)

type resolvedTarget struct {
	object      ObservedObject
	mechanism   string
	sectionName string
}

// resolveTargets applies kgateway attachment rules: targets must live in the
// policy namespace, so a reference elsewhere can never attach.
func (p *projection) resolveTargets(policy ObservedObject, references []targetReference, selectors []targetSelector, kinds targetKinds) []resolvedTarget {
	namespace := policy.Object.GetNamespace()
	seen := make(map[string]struct{})
	var result []resolvedTarget
	add := func(target ObservedObject, mechanism, section string) {
		key := target.Key + "\x00" + mechanism + "\x00" + section
		if _, duplicate := seen[key]; duplicate {
			return
		}
		seen[key] = struct{}{}
		result = append(result, resolvedTarget{object: target, mechanism: mechanism, sectionName: section})
	}
	for _, reference := range references {
		kind, supported := kinds[strings.TrimSpace(reference.Group)+"/"+reference.Kind]
		if !supported {
			p.diagnose(policy, "unsupported-target-kind", "target "+reference.Group+"/"+reference.Kind+" is not projected")
			continue
		}
		target, found := p.lookup(kind, namespace, reference.Name)
		if !found {
			p.diagnose(policy, "target-unresolved", kind+" "+namespace+"/"+reference.Name+" was not observed")
			continue
		}
		add(target, "targetRef", stringValue(reference.SectionName))
	}
	for _, selector := range selectors {
		kind, supported := kinds[strings.TrimSpace(selector.Group)+"/"+selector.Kind]
		if !supported {
			p.diagnose(policy, "unsupported-target-kind", "target selector "+selector.Group+"/"+selector.Kind+" is not projected")
			continue
		}
		for _, target := range p.byKind[kind] {
			if target.Object.GetNamespace() == namespace && labelsMatch(selector.MatchLabels, target.Object.GetLabels()) {
				add(target, "targetSelector", stringValue(selector.SectionName))
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].object.Key+result[i].mechanism+result[i].sectionName < result[j].object.Key+result[j].mechanism+result[j].sectionName
	})
	return result
}

func labelsMatch(selector, labels map[string]string) bool {
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func targetScope(target ObservedObject) string {
	if target.Object.GetKind() == "Gateway" {
		return "gateway"
	}
	return "service"
}

func (p *projection) addGovernance(target resolvedTarget, policy ObservedObject, ruleID string, properties map[string]string, semantics *graph.SecuritySemantics) error {
	properties["kgateway/target-mechanism"] = target.mechanism
	properties["kgateway/section-name"] = target.sectionName
	if semantics != nil {
		scoped := *semantics
		scoped.Scope = targetScope(target.object)
		withSemantics, err := graph.WithSecuritySemantics(properties, scoped)
		if err != nil {
			return fmt.Errorf("%s %s target semantics: %w", policy.Object.GetKind(), projectkit.DisplayName(policy.Object), err)
		}
		properties = withSemantics
	}
	qualifier := "kgateway-" + strings.ToLower(policy.Object.GetKind()) + "-" + projectkit.Qualifier(map[string]string{"mechanism": target.mechanism, "sectionName": target.sectionName})
	p.addRelationship(target.object, graph.PredicateGovernedBy, p.claim(policy), qualifier, properties, ruleID, policy)
	return nil
}

// projectTrafficPolicies emits each TrafficPolicy, an authorization-posture
// facet when it configures authentication or authorization, a
// network-access-posture facet for an IP ACL, and target governed-by policy
// edges. Precedence between gateway and route attachments is not resolved.
func (p *projection) projectTrafficPolicies() error {
	for _, observation := range p.byKind[kindTrafficPolicy] {
		decoded, err := kubernetesapi.Decode[trafficPolicy](observation.Object)
		if err != nil {
			return fmt.Errorf("decode TrafficPolicy %q: %w", observation.Key, err)
		}
		spec := decoded.Value.Spec
		enabled, disabled, extensions := authMechanisms(spec)
		attributes := map[string]string{
			"kgateway/auth-mechanisms":          projectkit.MustCanonicalJSON(enabled),
			"kgateway/auth-disabled":            projectkit.MustCanonicalJSON(disabled),
			"kgateway/accepted":                 policyAccepted(decoded.Value.Status, p.context.ControllerNames),
			"kgateway/declared-target-count":    strconv.Itoa(len(spec.TargetRefs) + len(spec.TargetSelectors)),
			"kgateway/auth-extensions":          projectkit.MustCanonicalJSON(extensions),
			"kgateway/auth-extensions-resolved": strconv.FormatBool(p.extensionsResolved(observation, extensions)),
		}
		if spec.RBAC != nil {
			attributes["kgateway/rbac-action"] = defaultString(spec.RBAC.Action, "Allow")
			attributes["kgateway/rbac-expression-count"] = strconv.Itoa(len(spec.RBAC.Policy.MatchExpressions))
		}
		if spec.ACL != nil {
			attributes["kgateway/acl-default-action"] = spec.ACL.DefaultAction
			attributes["kgateway/acl-rule-count"] = strconv.Itoa(len(spec.ACL.Rules))
		}
		p.addResource(observation, "kgateway.trafficpolicy.resource", attributes)

		authz := authorizationSemantics(spec, enabled)
		if authz != nil {
			facet, err := graph.WithSecuritySemantics(map[string]string{
				"kgateway/auth-mechanisms":   attributes["kgateway/auth-mechanisms"],
				"kgateway/target-resolution": "governed-by-relationships",
			}, *authz)
			if err != nil {
				return fmt.Errorf("TrafficPolicy %s authorization semantics: %w", projectkit.DisplayName(observation.Object), err)
			}
			p.addFacet(observation, "authorization-posture", "kgateway-trafficpolicy", facet, "kgateway.trafficpolicy.authorization")
		}
		acl := aclSemantics(spec)
		if acl != nil {
			facet, err := graph.WithSecuritySemantics(map[string]string{
				"kgateway/acl-default-action": spec.ACL.DefaultAction,
				"kgateway/acl-rule-count":     strconv.Itoa(len(spec.ACL.Rules)),
				"kgateway/client-ip-source":   "listener-policy-dependent",
			}, *acl)
			if err != nil {
				return fmt.Errorf("TrafficPolicy %s ACL semantics: %w", projectkit.DisplayName(observation.Object), err)
			}
			p.addFacet(observation, "network-access-posture", "kgateway-acl", facet, "kgateway.trafficpolicy.acl")
		}
		edgeSemantics := authz
		if edgeSemantics == nil {
			edgeSemantics = acl
		}
		for _, target := range p.resolveTargets(observation, spec.TargetRefs, spec.TargetSelectors, routeAndGatewayTargets) {
			properties := map[string]string{
				"semantic":                 "kgateway-traffic-policy",
				"kgateway/auth-mechanisms": attributes["kgateway/auth-mechanisms"],
				"kgateway/auth-disabled":   attributes["kgateway/auth-disabled"],
			}
			if err := p.addGovernance(target, observation, "kgateway.trafficpolicy.target", properties, edgeSemantics); err != nil {
				return err
			}
		}
	}
	return nil
}

// authMechanisms lists configured and explicitly disabled auth filters plus
// the GatewayExtensions they reference.
func authMechanisms(spec trafficPolicySpec) (enabled, disabled, extensions []string) {
	toggle := func(name string, present, off bool) {
		switch {
		case !present:
		case off:
			disabled = append(disabled, name)
		default:
			enabled = append(enabled, name)
		}
	}
	reference := func(ref *namespacedReference) {
		if ref != nil && ref.Name != "" {
			extensions = append(extensions, ref.Namespace+"/"+ref.Name)
		}
	}
	if spec.ExtAuth != nil {
		toggle("ext-auth", true, spec.ExtAuth.Disable != nil)
		if spec.ExtAuth.Disable == nil {
			reference(spec.ExtAuth.ExtensionRef)
		}
	}
	if spec.JWTAuth != nil {
		toggle("jwt", true, spec.JWTAuth.Disable != nil)
		if spec.JWTAuth.Disable == nil {
			reference(spec.JWTAuth.ExtensionRef)
		}
	}
	if spec.BasicAuth != nil {
		toggle("basic", true, spec.BasicAuth.Disable != nil)
	}
	if spec.APIKeyAuth != nil {
		toggle("api-key", true, spec.APIKeyAuth.Disable != nil)
	}
	if spec.OAuth2 != nil {
		toggle("oauth2", true, false)
		reference(&spec.OAuth2.ExtensionRef)
	}
	toggle("rbac", spec.RBAC != nil, false)
	return sortedUnique(enabled), sortedUnique(disabled), sortedUnique(extensions)
}

// extensionsResolved reports whether every referenced GatewayExtension was
// observed; references without a namespace use the policy namespace.
func (p *projection) extensionsResolved(policy ObservedObject, extensions []string) bool {
	for _, extension := range extensions {
		namespace, name, _ := strings.Cut(extension, "/")
		if _, found := p.lookup(kindGatewayExtension, defaultString(namespace, policy.Object.GetNamespace()), name); !found {
			return false
		}
	}
	return true
}

func authorizationSemantics(spec trafficPolicySpec, enabled []string) *graph.SecuritySemantics {
	if len(enabled) == 0 {
		return nil
	}
	effect := "allow"
	switch {
	case spec.RBAC != nil:
		effect = strings.ToLower(defaultString(spec.RBAC.Action, "Allow"))
		if effect != "allow" && effect != "deny" {
			effect = "unknown"
		}
	case spec.ExtAuth != nil && spec.ExtAuth.Disable == nil || spec.OAuth2 != nil:
		effect = "custom"
	}
	return &graph.SecuritySemantics{
		Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainAuthorization,
		State: graph.SecurityStateDeclared, Effect: effect, Scope: "service", Direction: "ingress", Coverage: "partial",
		ConfigurationDigest: projectkit.SecurityDigest(map[string]any{
			"targetRefs": spec.TargetRefs, "targetSelectors": spec.TargetSelectors, "extAuth": spec.ExtAuth, "jwtAuth": spec.JWTAuth,
			"basicAuth": spec.BasicAuth != nil, "apiKeyAuth": spec.APIKeyAuth, "oauth2": spec.OAuth2, "rbac": spec.RBAC,
		}),
	}
}

func aclSemantics(spec trafficPolicySpec) *graph.SecuritySemantics {
	if spec.ACL == nil {
		return nil
	}
	effect := "allow"
	if strings.EqualFold(spec.ACL.DefaultAction, "deny") {
		effect = "restrict"
	} else {
		for _, rule := range spec.ACL.Rules {
			if strings.EqualFold(rule.Action, "deny") {
				effect = "deny"
			}
		}
	}
	return &graph.SecuritySemantics{
		Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainNetworkAccess,
		State: graph.SecurityStateDeclared, Effect: effect, Scope: "service", Direction: "ingress", Coverage: "partial",
		ConfigurationDigest: projectkit.SecurityDigest(map[string]any{"targetRefs": spec.TargetRefs, "targetSelectors": spec.TargetSelectors, "acl": spec.ACL}),
	}
}

// projectListenerPolicies records access-log and client-address settings and
// Gateway governed-by ListenerPolicy edges. These settings decide what the
// gateway can observe, not who may connect, so they stay provider-native.
func (p *projection) projectListenerPolicies() error {
	for _, observation := range p.byKind[kindListenerPolicy] {
		decoded, err := kubernetesapi.Decode[listenerPolicy](observation.Object)
		if err != nil {
			return fmt.Errorf("decode ListenerPolicy %q: %w", observation.Key, err)
		}
		spec := decoded.Value.Spec
		configs := []*listenerConfig{spec.Default}
		for _, port := range spec.PerPort {
			configs = append(configs, port.Listener)
		}
		var sinks []string
		trustedHops, trustedCIDRs, remoteAddress := "", 0, ""
		for _, config := range configs {
			if config == nil || config.HTTPSettings == nil {
				continue
			}
			settings := config.HTTPSettings
			for _, log := range settings.AccessLog {
				switch {
				case log.OpenTelemetry != nil:
					sinks = append(sinks, "open-telemetry")
				case log.GrpcService != nil:
					sinks = append(sinks, "grpc")
				case log.FileSink != nil:
					sinks = append(sinks, "file")
				}
			}
			if settings.XffNumTrustedHops != nil && config == spec.Default {
				trustedHops = strconv.Itoa(int(*settings.XffNumTrustedHops))
			}
			if settings.UseRemoteAddress != nil && config == spec.Default {
				remoteAddress = strconv.FormatBool(*settings.UseRemoteAddress)
			}
			trustedCIDRs += len(settings.XffTrustedCIDRs)
		}
		attributes := map[string]string{
			"kgateway/access-log-sinks":     projectkit.MustCanonicalJSON(sortedUnique(sinks)),
			"kgateway/xff-num-trusted-hops": trustedHops,
			"kgateway/xff-trusted-cidrs":    strconv.Itoa(trustedCIDRs),
			"kgateway/use-remote-address":   remoteAddress,
			"kgateway/per-port-count":       strconv.Itoa(len(spec.PerPort)),
		}
		p.addResource(observation, "kgateway.listenerpolicy.resource", attributes)
		for _, target := range p.resolveTargets(observation, spec.TargetRefs, spec.TargetSelectors, gatewayTargets) {
			properties := map[string]string{"semantic": "kgateway-listener-policy", "kgateway/access-log-sinks": attributes["kgateway/access-log-sinks"]}
			if err := p.addGovernance(target, observation, "kgateway.listenerpolicy.target", properties, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// projectBackendConfigPolicies emits upstream TLS posture for Services and
// Backends. insecureSkipVerify keeps encryption but drops server
// authentication, so it is reported as permit rather than require.
func (p *projection) projectBackendConfigPolicies() error {
	for _, observation := range p.byKind[kindBackendConfig] {
		decoded, err := kubernetesapi.Decode[backendConfigPolicy](observation.Object)
		if err != nil {
			return fmt.Errorf("decode BackendConfigPolicy %q: %w", observation.Key, err)
		}
		spec := decoded.Value.Spec
		attributes := map[string]string{"kgateway/tls": "unset"}
		var semantics *graph.SecuritySemantics
		if spec.TLS != nil {
			verification, effect := tlsVerification(spec.TLS)
			attributes = map[string]string{
				"kgateway/tls":                   "configured",
				"kgateway/tls-verification":      verification,
				"kgateway/tls-sni":               stringValue(spec.TLS.Sni),
				"kgateway/tls-verify-san-count":  strconv.Itoa(len(spec.TLS.VerifySubjectAltNames)),
				"kgateway/tls-simple":            strconv.FormatBool(spec.TLS.SimpleTLS != nil && *spec.TLS.SimpleTLS),
				"kgateway/tls-client-cert-given": strconv.FormatBool(spec.TLS.SecretRef != nil || spec.TLS.Files != nil),
			}
			semantics = &graph.SecuritySemantics{
				Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassGovernance, Domain: graph.SecurityDomainTransportAuthentication,
				State: graph.SecurityStateDeclared, Effect: effect, Scope: "service", Direction: "egress", Coverage: "partial",
				ConfigurationDigest: projectkit.SecurityDigest(map[string]any{"targetRefs": spec.TargetRefs, "targetSelectors": spec.TargetSelectors, "tls": spec.TLS}),
			}
			facet, err := graph.WithSecuritySemantics(map[string]string{
				"kgateway/tls-verification":  verification,
				"kgateway/target-resolution": "governed-by-relationships",
			}, *semantics)
			if err != nil {
				return fmt.Errorf("BackendConfigPolicy %s TLS semantics: %w", projectkit.DisplayName(observation.Object), err)
			}
			p.addFacet(observation, "transport-posture", "kgateway-backend-tls", facet, "kgateway.backendconfigpolicy.tls")
		}
		p.addResource(observation, "kgateway.backendconfigpolicy.resource", attributes)
		for _, target := range p.resolveTargets(observation, spec.TargetRefs, spec.TargetSelectors, backendTargets) {
			properties := map[string]string{"semantic": "kgateway-backend-config", "kgateway/tls-verification": attributes["kgateway/tls-verification"]}
			if err := p.addGovernance(target, observation, "kgateway.backendconfigpolicy.target", properties, semantics); err != nil {
				return err
			}
		}
	}
	return nil
}

func tlsVerification(tls *backendTLS) (string, string) {
	switch {
	case tls.InsecureSkipVerify != nil && *tls.InsecureSkipVerify:
		return "insecure-skip-verify", "permit"
	case tls.WellKnownCACertificates != nil || tls.SecretRef != nil || tls.Files != nil:
		return "ca-verified", "require"
	default:
		return "unspecified-ca", "unknown"
	}
}
