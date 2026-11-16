package kubernetes

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const networkPolicyApplicabilityAttribute = "kubernetes/network-policy-applicability"

type hostNetworkContainer struct {
	Kind              string               `json:"kind"`
	Privileged        bool                 `json:"privileged,omitempty"`
	CapabilitiesAdded []string             `json:"capabilitiesAdded,omitempty"`
	Seccomp           string               `json:"seccomp,omitempty"`
	Ports             []graph.SecurityPort `json:"ports,omitempty"`
}

// isHostNetworkPod reports spec.hostNetwork; Pods that fail to decode already
// failed projection earlier.
func isHostNetworkPod(pod *unstructured.Unstructured) bool {
	hostNetwork, _, _ := unstructured.NestedBool(pod.Object, "spec", "hostNetwork")
	return hostNetwork
}

// hostNetworkPostureFacet states that a Pod is configured to share its Node's
// network namespace, with the declared co-factors that raise its impact.
//
// The facet describes configuration only. Effect stays unknown because a
// declared port does not prove a listener, and the privilege, capability, and
// seccomp counts stay provider-native because the neutral vocabulary has no
// kernel-privilege domain. Runtime behavior (sockets, packet capture, iptables
// changes, syscalls) needs runtime telemetry and is not inferred here.
func hostNetworkPostureFacet(clusterID, sourceID string, object *unstructured.Unstructured, pod *corev1.Pod) (graph.FacetAssertion, error) {
	containers := hostNetworkContainers(pod)
	result := map[string]string{
		"kubernetes/host-network":               "true",
		networkPolicyApplicabilityAttribute:     "implementation-defined",
		"kubernetes/host-pid":                   strconv.FormatBool(pod.Spec.HostPID),
		"kubernetes/host-ipc":                   strconv.FormatBool(pod.Spec.HostIPC),
		"kubernetes/privileged-container-count": strconv.Itoa(countContainers(containers, func(c hostNetworkContainer) bool { return c.Privileged })),
		"kubernetes/net-admin-container-count":  strconv.Itoa(countContainers(containers, hasCapability("NET_ADMIN"))),
		"kubernetes/net-raw-container-count":    strconv.Itoa(countContainers(containers, hasCapability("NET_RAW"))),
		"kubernetes/sys-admin-container-count":  strconv.Itoa(countContainers(containers, hasCapability("SYS_ADMIN"))),
		"kubernetes/unconfined-seccomp-container-count": strconv.Itoa(countContainers(containers, func(c hostNetworkContainer) bool {
			return c.Privileged || c.Seccomp == string(corev1.SeccompProfileTypeUnconfined)
		})),
	}
	setStringAttribute(result, "kubernetes/node-name", pod.Spec.NodeName)

	var protocols []string
	var ports []graph.SecurityPort
	for _, container := range containers {
		for _, port := range container.Ports {
			protocols = append(protocols, port.Protocol)
			ports = append(ports, port)
		}
	}
	declared := len(uniquePorts(ports))
	protocols, ports, _ = boundedSecurityDetails(protocols, ports)
	result["kubernetes/host-network-ports"] = projectkit.MustCanonicalJSON(ports)
	if omitted := declared - len(ports); omitted > 0 {
		result["kubernetes/omitted-host-network-values"] = strconv.Itoa(omitted)
	}

	semantics := graph.SecuritySemantics{
		Version: graph.SecuritySemanticsV1, Class: graph.SecurityClassExposure, Domain: graph.SecurityDomainNetworkAccess,
		State: graph.SecurityStateDeclared, Effect: "unknown", Scope: "workload", Direction: "bidirectional", Coverage: "partial",
		Protocols: protocols, Ports: ports, ConfigurationDigest: projectkit.SecurityDigest(map[string]any{
			"hostNetwork": true, "hostPID": pod.Spec.HostPID, "hostIPC": pod.Spec.HostIPC,
			"containers": canonicalUnorderedJSON(containers),
		}),
	}
	attributes, err := graph.WithSecuritySemantics(result, semantics)
	if err != nil {
		return graph.FacetAssertion{}, fmt.Errorf("pod %s host-network semantics: %w", projectkit.DisplayName(object), err)
	}
	return graph.FacetAssertion{
		Resource: claimFor(clusterID, object), Kind: "network-exposure", Key: "host-network", Attributes: attributes,
		PluginID: PluginID, SourceID: sourceID, RuleID: "kubernetes.pod.host-network-posture",
		EvidenceIDs: evidenceIDs(object),
	}, nil
}

// hostNetworkContainers normalizes regular, init, and ephemeral containers.
// Container seccomp overrides the Pod's; only explicit profiles are recorded.
func hostNetworkContainers(pod *corev1.Pod) []hostNetworkContainer {
	podSeccomp := ""
	if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.SeccompProfile != nil {
		podSeccomp = string(pod.Spec.SecurityContext.SeccompProfile.Type)
	}
	normalize := func(kind string, securityContext *corev1.SecurityContext, declared []corev1.ContainerPort) hostNetworkContainer {
		result := hostNetworkContainer{Kind: kind, Seccomp: podSeccomp}
		if securityContext != nil {
			result.Privileged = securityContext.Privileged != nil && *securityContext.Privileged
			if securityContext.Capabilities != nil {
				for _, capability := range securityContext.Capabilities.Add {
					result.CapabilitiesAdded = append(result.CapabilitiesAdded, strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(string(capability))), "CAP_"))
				}
				result.CapabilitiesAdded = uniqueSorted(result.CapabilitiesAdded)
			}
			if securityContext.SeccompProfile != nil {
				result.Seccomp = string(securityContext.SeccompProfile.Type)
			}
		}
		for _, port := range declared {
			if port.ContainerPort < 1 || port.ContainerPort > 65535 {
				continue
			}
			protocol := string(port.Protocol)
			if protocol == "" {
				protocol = string(corev1.ProtocolTCP)
			}
			result.Ports = append(result.Ports, graph.SecurityPort{Protocol: strings.ToUpper(protocol), Port: uint16(port.ContainerPort)})
		}
		return result
	}
	result := make([]hostNetworkContainer, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers)+len(pod.Spec.EphemeralContainers))
	for _, container := range pod.Spec.Containers {
		result = append(result, normalize("container", container.SecurityContext, container.Ports))
	}
	for _, container := range pod.Spec.InitContainers {
		result = append(result, normalize("init", container.SecurityContext, container.Ports))
	}
	for _, container := range pod.Spec.EphemeralContainers {
		result = append(result, normalize("ephemeral", container.SecurityContext, container.Ports))
	}
	return result
}

// hasCapability treats privileged containers and ALL as holding every capability.
func hasCapability(capability string) func(hostNetworkContainer) bool {
	return func(container hostNetworkContainer) bool {
		return container.Privileged || slices.Contains(container.CapabilitiesAdded, capability) || slices.Contains(container.CapabilitiesAdded, "ALL")
	}
}

func countContainers(containers []hostNetworkContainer, match func(hostNetworkContainer) bool) int {
	count := 0
	for _, container := range containers {
		if match(container) {
			count++
		}
	}
	return count
}

func uniquePorts(ports []graph.SecurityPort) map[graph.SecurityPort]struct{} {
	result := make(map[graph.SecurityPort]struct{}, len(ports))
	for _, port := range ports {
		result[port] = struct{}{}
	}
	return result
}

// hostNetworkPolicyProperties keeps a policy's direction, ports, and digest for
// a host-network Pod but drops the restrict claim: whether the CNI enforces
// NetworkPolicy on the host namespace is implementation-defined.
func hostNetworkPolicyProperties(properties map[string]string, semantics graph.SecuritySemantics) (map[string]string, error) {
	semantics.State, semantics.Effect, semantics.Coverage = graph.SecurityStateDeclared, "unknown", "unknown"
	result, err := graph.WithSecuritySemantics(properties, semantics)
	if err != nil {
		return nil, err
	}
	result[networkPolicyApplicabilityAttribute] = "implementation-defined"
	return result, nil
}
