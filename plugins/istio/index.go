package istio

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
)

type resolutionStatus string

const (
	resolutionResolved    resolutionStatus = "resolved"
	resolutionNotFound    resolutionStatus = "not-found"
	resolutionAmbiguous   resolutionStatus = "ambiguous"
	resolutionUnsupported resolutionStatus = "unsupported"
)

type resolution struct {
	Status   resolutionStatus
	Claim    graph.IdentityClaim
	Evidence string
}

type indexedObject struct {
	ObservedObject
	Claim graph.IdentityClaim
}

type serviceEntryDestination struct {
	Claim     graph.IdentityClaim
	Namespace string
	ExportTo  []string
	Evidence  string
}

// Index is the immutable reconciliation index built once per projection.
// It indexes by UID for authoritative references and by normalized names only
// where Istio references are name-based.
type Index struct {
	context           ProjectionContext
	items             []indexedObject
	byKind            map[string][]indexedObject
	byObject          map[string][]indexedObject
	namespaces        map[string]indexedObject
	podsByNamespace   map[string][]indexedObject
	services          map[string]indexedObject
	serviceHosts      map[string][]indexedObject
	serviceEntryHosts map[string][]serviceEntryDestination
	gateways          map[string]indexedObject
}

// NewIndex sorts observations, skipping objects without a UID, so the index
// is independent of input order. Callers keep observations immutable.
func NewIndex(scope ProjectionContext, observations []ObservedObject) *Index {
	items := make([]ObservedObject, 0, len(observations))
	for _, observation := range observations {
		if observation.Object != nil && string(observation.Object.GetUID()) != "" {
			items = append(items, observation)
		}
	}
	slices.SortFunc(items, func(left, right ObservedObject) int {
		leftKey, rightKey := projectkit.ObjectKey(left.Object), projectkit.ObjectKey(right.Object)
		if leftKey == rightKey {
			return cmp.Compare(left.Key, right.Key)
		}
		return cmp.Compare(leftKey, rightKey)
	})
	index := &Index{
		context: scope, byKind: make(map[string][]indexedObject), byObject: make(map[string][]indexedObject),
		namespaces: make(map[string]indexedObject), podsByNamespace: make(map[string][]indexedObject),
		services: make(map[string]indexedObject), serviceHosts: make(map[string][]indexedObject),
		serviceEntryHosts: make(map[string][]serviceEntryDestination), gateways: make(map[string]indexedObject),
	}
	for _, observation := range items {
		item := observation.Object
		indexed := indexedObject{ObservedObject: observation, Claim: kubernetesplugin.ClaimFor(scope.ClusterID, item)}
		index.items = append(index.items, indexed)
		index.byKind[item.GetKind()] = append(index.byKind[item.GetKind()], indexed)
		lookup := objectLookupKey(item.GetAPIVersion(), item.GetKind(), item.GetNamespace(), item.GetName())
		index.byObject[lookup] = append(index.byObject[lookup], indexed)
		switch item.GetKind() {
		case "Namespace":
			index.namespaces[item.GetName()] = indexed
		case "Pod":
			index.podsByNamespace[item.GetNamespace()] = append(index.podsByNamespace[item.GetNamespace()], indexed)
		case "Service":
			index.services[namespacedName(item.GetNamespace(), item.GetName())] = indexed
			for _, host := range serviceCanonicalHosts(item.GetNamespace(), item.GetName()) {
				index.serviceHosts[host] = append(index.serviceHosts[host], indexed)
			}
		case "Gateway":
			if strings.HasPrefix(item.GetAPIVersion(), "gateway.networking.k8s.io/") {
				index.gateways[namespacedName(item.GetNamespace(), item.GetName())] = indexed
			}
		}
	}
	return index
}

// podsSelectedBy returns, in namespace and key order, the Pods whose labels
// match selector and that a workload-selector policy in namespace reaches.
// Istio looks up policies in the root namespace for workloads in every
// namespace (pilot's ListAuthorizationPolicies and getConfigsForWorkload), so
// a root-namespace selector matches Pods mesh-wide; any other policy reaches
// only its own namespace.
func (index *Index) podsSelectedBy(namespace, rootNamespace string, selector map[string]string) []indexedObject {
	namespaces := []string{namespace}
	if namespace == rootNamespace {
		namespaces = slices.Sorted(maps.Keys(index.podsByNamespace))
	}
	var result []indexedObject
	for _, name := range namespaces {
		for _, pod := range index.podsByNamespace[name] {
			if labelsMatch(selector, pod.Object.GetLabels()) {
				result = append(result, pod)
			}
		}
	}
	return result
}

func (index *Index) addServiceEntryHost(host string, destination serviceEntryDestination) {
	index.serviceEntryHosts[host] = append(index.serviceEntryHosts[host], destination)
}

func (index *Index) resolveDestination(namespace, host string) resolution {
	canonical, wildcard, err := canonicalHost(host)
	if err != nil || wildcard {
		return resolution{Status: resolutionUnsupported}
	}
	var candidates []resolution
	for _, service := range index.serviceHosts[canonicalServiceHost(namespace, canonical)] {
		candidates = append(candidates, resolution{Status: resolutionResolved, Claim: service.Claim, Evidence: service.EventID})
	}
	for _, destination := range index.serviceEntryHosts[canonical] {
		if visibleFrom(destination.Namespace, namespace, destination.ExportTo) {
			candidates = append(candidates, resolution{Status: resolutionResolved, Claim: destination.Claim, Evidence: destination.Evidence})
		}
	}
	if len(candidates) == 0 {
		return resolution{Status: resolutionNotFound}
	}
	if len(candidates) != 1 {
		return resolution{Status: resolutionAmbiguous}
	}
	return candidates[0]
}

func serviceCanonicalHosts(namespace, name string) []string {
	return []string{name + "." + namespace + ".svc.cluster.local"}
}

func canonicalServiceHost(namespace, host string) string {
	parts := strings.Split(host, ".")
	switch {
	case len(parts) == 1:
		return host + "." + namespace + ".svc.cluster.local"
	case len(parts) == 2:
		return host + ".svc.cluster.local"
	case len(parts) == 3 && parts[2] == "svc":
		return host + ".cluster.local"
	default:
		return host
	}
}

func visibleFrom(ownerNamespace, consumerNamespace string, exportTo []string) bool {
	if len(exportTo) == 0 {
		return true
	}
	for _, value := range exportTo {
		switch value {
		case "*":
			return true
		case ".":
			if ownerNamespace == consumerNamespace {
				return true
			}
		default:
			if value == consumerNamespace {
				return true
			}
		}
	}
	return false
}

func objectLookupKey(apiVersion, kind, namespace, name string) string {
	return strings.ToLower(apiVersion + "/" + kind + "/" + namespace + "/" + name)
}

func namespacedName(namespace, name string) string { return namespace + "/" + name }
