package kubernetes

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	workloadContextAttribute         = "kubernetes/workload-context"
	maxWorkloadContainers            = 16
	maxWorkloadContainerItems        = 32
	maxWorkloadReferences            = 64
	maxWorkloadHostPaths             = 32
	maxWorkloadStringLength          = 512
	maxWorkloadTypeLength            = 64
	maxResourceAuthoringContextBytes = 32 << 10
)

type resourceAuthoringContext struct {
	SchemaVersion                string                      `json:"schemaVersion"`
	ServiceAccountName           string                      `json:"serviceAccountName,omitempty"`
	AutomountServiceAccountToken *bool                       `json:"automountServiceAccountToken,omitempty"`
	PodTemplateSHA256            string                      `json:"podTemplateSha256"`
	HostNetwork                  bool                        `json:"hostNetwork,omitempty"`
	HostPID                      bool                        `json:"hostPID,omitempty"`
	HostIPC                      bool                        `json:"hostIPC,omitempty"`
	PodSecurityContext           *workloadPodSecurityContext `json:"podSecurityContext,omitempty"`
	Containers                   []workloadContainer         `json:"containers,omitempty"`
	HostPathCount                int                         `json:"hostPathCount,omitempty"`
	HostPathTypes                []string                    `json:"hostPathTypes,omitempty"`
	References                   []workloadResourceReference `json:"references,omitempty"`
	Truncated                    bool                        `json:"truncated,omitempty"`
}

type workloadPodSecurityContext struct {
	RunAsUser      *int64 `json:"runAsUser,omitempty"`
	RunAsGroup     *int64 `json:"runAsGroup,omitempty"`
	RunAsNonRoot   *bool  `json:"runAsNonRoot,omitempty"`
	SeccompProfile string `json:"seccompProfile,omitempty"`
}

type workloadContainer struct {
	Type                     string                  `json:"type"`
	Name                     string                  `json:"name"`
	Image                    string                  `json:"image,omitempty"`
	Privileged               *bool                   `json:"privileged,omitempty"`
	AllowPrivilegeEscalation *bool                   `json:"allowPrivilegeEscalation,omitempty"`
	ReadOnlyRootFilesystem   *bool                   `json:"readOnlyRootFilesystem,omitempty"`
	RunAsUser                *int64                  `json:"runAsUser,omitempty"`
	RunAsGroup               *int64                  `json:"runAsGroup,omitempty"`
	RunAsNonRoot             *bool                   `json:"runAsNonRoot,omitempty"`
	SeccompProfile           string                  `json:"seccompProfile,omitempty"`
	CapabilitiesAdded        []string                `json:"capabilitiesAdded,omitempty"`
	CapabilitiesDropped      []string                `json:"capabilitiesDropped,omitempty"`
	Ports                    []workloadContainerPort `json:"ports,omitempty"`
}

type workloadContainerPort struct {
	Name          string `json:"name,omitempty"`
	ContainerPort int32  `json:"containerPort"`
	Protocol      string `json:"protocol,omitempty"`
	HostPort      int32  `json:"hostPort,omitempty"`
}

type workloadResourceReference struct {
	Kind  string `json:"kind"`
	Usage string `json:"usage"`
	Count int    `json:"count"`
}

func isAuthorableWorkload(item *unstructured.Unstructured) bool {
	if item == nil || item.GetAPIVersion() != "apps/v1" {
		return false
	}
	return item.GetKind() == "Deployment" || item.GetKind() == "StatefulSet" || item.GetKind() == "DaemonSet"
}

func addWorkloadAttributes(result map[string]string, item *unstructured.Unstructured) error {
	template, found, err := unstructured.NestedMap(item.Object, "spec", "template")
	if err != nil {
		return fmt.Errorf("read %s %s/%s pod template: %w", item.GetKind(), item.GetNamespace(), item.GetName(), err)
	}
	if !found {
		template = map[string]any{}
	}
	var podTemplate corev1.PodTemplateSpec
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(template, &podTemplate); err != nil {
		return fmt.Errorf("decode %s %s/%s pod template: %w", item.GetKind(), item.GetNamespace(), item.GetName(), err)
	}
	context := projectResourceAuthoringContext(&podTemplate.Spec)
	labels, _, _ := unstructured.NestedFieldNoCopy(item.Object, "spec", "template", "metadata", "labels")
	podSpec, _, _ := unstructured.NestedFieldNoCopy(item.Object, "spec", "template", "spec")
	context.PodTemplateSHA256 = projectkit.Digest(map[string]any{"labels": labels, "spec": podSpec})
	result[workloadContextAttribute] = canonicalResourceAuthoringContext(context)
	result["kubernetes/pod-template-sha256"] = context.PodTemplateSHA256
	if context.ServiceAccountName != "" {
		result["kubernetes/service-account-name"] = context.ServiceAccountName
	}
	return nil
}

func projectResourceAuthoringContext(spec *corev1.PodSpec) resourceAuthoringContext {
	context := resourceAuthoringContext{
		SchemaVersion:                "v1",
		AutomountServiceAccountToken: spec.AutomountServiceAccountToken,
		HostNetwork:                  spec.HostNetwork,
		HostPID:                      spec.HostPID,
		HostIPC:                      spec.HostIPC,
	}
	context.ServiceAccountName = boundedWorkloadString(spec.ServiceAccountName, &context.Truncated)
	context.PodSecurityContext = projectPodSecurityContext(spec.SecurityContext, &context.Truncated)
	containers := make([]workloadContainer, 0, len(spec.InitContainers)+len(spec.Containers))
	for _, container := range spec.InitContainers {
		containers = append(containers, projectWorkloadContainer("init", container, &context.Truncated))
	}
	for _, container := range spec.Containers {
		containers = append(containers, projectWorkloadContainer("container", container, &context.Truncated))
	}
	slices.SortFunc(containers, func(left, right workloadContainer) int {
		if result := cmp.Compare(left.Type, right.Type); result != 0 {
			return result
		}
		return cmp.Compare(left.Name, right.Name)
	})
	context.Containers = limitWorkloadItems(containers, maxWorkloadContainers, &context.Truncated)
	context.HostPathCount, context.HostPathTypes = projectWorkloadHostPaths(spec.Volumes, &context.Truncated)
	context.References = projectWorkloadReferences(spec, &context.Truncated)
	return context
}

func projectPodSecurityContext(securityContext *corev1.PodSecurityContext, truncated *bool) *workloadPodSecurityContext {
	if securityContext == nil {
		return nil
	}
	result := &workloadPodSecurityContext{
		RunAsUser:    securityContext.RunAsUser,
		RunAsGroup:   securityContext.RunAsGroup,
		RunAsNonRoot: securityContext.RunAsNonRoot,
	}
	if securityContext.SeccompProfile != nil {
		result.SeccompProfile = boundedWorkloadType(string(securityContext.SeccompProfile.Type), truncated)
	}
	return result
}

func projectWorkloadContainer(containerType string, container corev1.Container, truncated *bool) workloadContainer {
	result := workloadContainer{
		Type:  containerType,
		Name:  boundedWorkloadString(container.Name, truncated),
		Image: boundedWorkloadString(container.Image, truncated),
	}
	if securityContext := container.SecurityContext; securityContext != nil {
		result.Privileged = securityContext.Privileged
		result.AllowPrivilegeEscalation = securityContext.AllowPrivilegeEscalation
		result.ReadOnlyRootFilesystem = securityContext.ReadOnlyRootFilesystem
		result.RunAsUser = securityContext.RunAsUser
		result.RunAsGroup = securityContext.RunAsGroup
		result.RunAsNonRoot = securityContext.RunAsNonRoot
		if securityContext.SeccompProfile != nil {
			result.SeccompProfile = boundedWorkloadType(string(securityContext.SeccompProfile.Type), truncated)
		}
		if securityContext.Capabilities != nil {
			result.CapabilitiesAdded = boundedCapabilities(securityContext.Capabilities.Add, truncated)
			result.CapabilitiesDropped = boundedCapabilities(securityContext.Capabilities.Drop, truncated)
		}
	}
	ports := make([]workloadContainerPort, 0, len(container.Ports))
	for _, port := range container.Ports {
		ports = append(ports, workloadContainerPort{
			Name: boundedWorkloadString(port.Name, truncated), ContainerPort: port.ContainerPort,
			Protocol: boundedWorkloadType(string(port.Protocol), truncated), HostPort: port.HostPort,
		})
	}
	slices.SortFunc(ports, func(left, right workloadContainerPort) int {
		if result := cmp.Compare(left.ContainerPort, right.ContainerPort); result != 0 {
			return result
		}
		if result := cmp.Compare(left.Protocol, right.Protocol); result != 0 {
			return result
		}
		return cmp.Compare(left.Name, right.Name)
	})
	result.Ports = limitWorkloadItems(ports, maxWorkloadContainerItems, truncated)
	return result
}

func boundedCapabilities(values []corev1.Capability, truncated *bool) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, boundedWorkloadString(string(value), truncated))
	}
	result = uniqueSorted(result)
	return limitWorkloadItems(result, maxWorkloadContainerItems, truncated)
}

func projectWorkloadHostPaths(volumes []corev1.Volume, truncated *bool) (int, []string) {
	count := 0
	types := make([]string, 0)
	for _, volume := range volumes {
		if volume.HostPath == nil {
			continue
		}
		count++
		typeName := ""
		if volume.HostPath.Type != nil {
			typeName = boundedWorkloadType(string(*volume.HostPath.Type), truncated)
		}
		types = append(types, typeName)
	}
	types = uniqueSorted(types)
	return count, limitWorkloadItems(types, maxWorkloadHostPaths, truncated)
}

func projectWorkloadReferences(spec *corev1.PodSpec, truncated *bool) []workloadResourceReference {
	counts := make(map[workloadResourceReference]int)
	add := func(kind, name, usage string) {
		if name != "" {
			counts[workloadResourceReference{Kind: kind, Usage: usage}]++
		}
	}
	for _, secret := range spec.ImagePullSecrets {
		add("Secret", secret.Name, "imagePull")
	}
	containers := append(append([]corev1.Container(nil), spec.InitContainers...), spec.Containers...)
	for _, container := range containers {
		for _, source := range container.EnvFrom {
			if source.SecretRef != nil {
				add("Secret", source.SecretRef.Name, "envFrom")
			}
			if source.ConfigMapRef != nil {
				add("ConfigMap", source.ConfigMapRef.Name, "envFrom")
			}
		}
		for _, variable := range container.Env {
			if variable.ValueFrom == nil {
				continue
			}
			if variable.ValueFrom.SecretKeyRef != nil {
				add("Secret", variable.ValueFrom.SecretKeyRef.Name, "env")
			}
			if variable.ValueFrom.ConfigMapKeyRef != nil {
				add("ConfigMap", variable.ValueFrom.ConfigMapKeyRef.Name, "env")
			}
		}
	}
	for _, volume := range spec.Volumes {
		if volume.Secret != nil {
			add("Secret", volume.Secret.SecretName, "volume")
		}
		if volume.ConfigMap != nil {
			add("ConfigMap", volume.ConfigMap.Name, "volume")
		}
		if volume.Projected != nil {
			for _, source := range volume.Projected.Sources {
				if source.Secret != nil {
					add("Secret", source.Secret.Name, "projectedVolume")
				}
				if source.ConfigMap != nil {
					add("ConfigMap", source.ConfigMap.Name, "projectedVolume")
				}
			}
		}
	}
	result := make([]workloadResourceReference, 0, len(counts))
	for reference, count := range counts {
		reference.Count = count
		result = append(result, reference)
	}
	slices.SortFunc(result, func(left, right workloadResourceReference) int {
		if comparison := cmp.Compare(left.Kind, right.Kind); comparison != 0 {
			return comparison
		}
		return cmp.Compare(left.Usage, right.Usage)
	})
	return limitWorkloadItems(result, maxWorkloadReferences, truncated)
}

func canonicalResourceAuthoringContext(context resourceAuthoringContext) string {
	encoded := projectkit.MustCanonicalJSON(context)
	if len(encoded) <= maxResourceAuthoringContextBytes {
		return encoded
	}
	context.Truncated = true
	for len(encoded) > maxResourceAuthoringContextBytes {
		trimmed := false
		for index := len(context.Containers) - 1; index >= 0 && !trimmed; index-- {
			container := &context.Containers[index]
			switch {
			case len(container.Ports) > 0:
				container.Ports = container.Ports[:len(container.Ports)-1]
			case len(container.CapabilitiesDropped) > 0:
				container.CapabilitiesDropped = container.CapabilitiesDropped[:len(container.CapabilitiesDropped)-1]
			case len(container.CapabilitiesAdded) > 0:
				container.CapabilitiesAdded = container.CapabilitiesAdded[:len(container.CapabilitiesAdded)-1]
			default:
				continue
			}
			trimmed = true
		}
		switch {
		case trimmed:
		case len(context.References) > 0:
			context.References = context.References[:len(context.References)-1]
		case len(context.HostPathTypes) > 0:
			context.HostPathTypes = context.HostPathTypes[:len(context.HostPathTypes)-1]
		case len(context.Containers) > 0 && context.Containers[len(context.Containers)-1].Image != "":
			context.Containers[len(context.Containers)-1].Image = ""
		case len(context.Containers) > 0:
			context.Containers = context.Containers[:len(context.Containers)-1]
		}
		encoded = projectkit.MustCanonicalJSON(context)
	}
	return encoded
}

func boundedWorkloadString(value string, truncated *bool) string {
	if len(value) <= maxWorkloadStringLength {
		return value
	}
	*truncated = true
	return value[:maxWorkloadStringLength]
}

func boundedWorkloadType(value string, truncated *bool) string {
	if len(value) <= maxWorkloadTypeLength {
		return value
	}
	*truncated = true
	return value[:maxWorkloadTypeLength]
}

func limitWorkloadItems[T any](values []T, limit int, truncated *bool) []T {
	if len(values) <= limit {
		return values
	}
	*truncated = true
	return values[:limit]
}
