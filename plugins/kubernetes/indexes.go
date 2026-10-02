package kubernetes

import (
	"cmp"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type objectIndex struct {
	items                 []*unstructured.Unstructured
	byUID                 map[string]*unstructured.Unstructured
	namespacesByName      map[string]*unstructured.Unstructured
	serviceAccountsByName map[string]*unstructured.Unstructured
	nodesByName           map[string]*unstructured.Unstructured
	podsByNamespace       map[string][]*unstructured.Unstructured
	podsByLabel           map[string][]*unstructured.Unstructured
	servicesByName        map[string]*unstructured.Unstructured
	ingresses             []*unstructured.Unstructured
	networkPolicies       []*unstructured.Unstructured
	gatewaysByName        map[string]*unstructured.Unstructured
	httpRoutes            []*unstructured.Unstructured
	observedGateway       bool
	observedHTTPRoute     bool
}

func buildObjectIndex(objects []*unstructured.Unstructured) objectIndex {
	index := objectIndex{
		byUID:                 make(map[string]*unstructured.Unstructured),
		namespacesByName:      make(map[string]*unstructured.Unstructured),
		serviceAccountsByName: make(map[string]*unstructured.Unstructured),
		nodesByName:           make(map[string]*unstructured.Unstructured),
		podsByNamespace:       make(map[string][]*unstructured.Unstructured),
		podsByLabel:           make(map[string][]*unstructured.Unstructured),
		servicesByName:        make(map[string]*unstructured.Unstructured),
		gatewaysByName:        make(map[string]*unstructured.Unstructured),
	}
	for _, object := range objects {
		if object != nil {
			index.items = append(index.items, object)
		}
	}
	slices.SortFunc(index.items, func(left, right *unstructured.Unstructured) int {
		return cmp.Compare(projectkit.ObjectKey(left), projectkit.ObjectKey(right))
	})
	for _, item := range index.items {
		uid := string(item.GetUID())
		if uid == "" {
			continue
		}
		index.byUID[uid] = item
		switch {
		case item.GetAPIVersion() == "v1" && item.GetKind() == "Namespace":
			index.namespacesByName[item.GetName()] = item
		case item.GetAPIVersion() == "v1" && item.GetKind() == "ServiceAccount":
			index.serviceAccountsByName[namespacedName(item.GetNamespace(), item.GetName())] = item
		case item.GetAPIVersion() == "v1" && item.GetKind() == "Node":
			index.nodesByName[item.GetName()] = item
		case item.GetAPIVersion() == "v1" && item.GetKind() == "Pod":
			index.podsByNamespace[item.GetNamespace()] = append(index.podsByNamespace[item.GetNamespace()], item)
			for key, value := range item.GetLabels() {
				index.podsByLabel[podLabelKey(item.GetNamespace(), key, value)] = append(index.podsByLabel[podLabelKey(item.GetNamespace(), key, value)], item)
			}
		case item.GetAPIVersion() == "v1" && item.GetKind() == "Service":
			index.servicesByName[namespacedName(item.GetNamespace(), item.GetName())] = item
		case item.GetAPIVersion() == "networking.k8s.io/v1" && item.GetKind() == "Ingress":
			index.ingresses = append(index.ingresses, item)
		case item.GetAPIVersion() == "networking.k8s.io/v1" && item.GetKind() == "NetworkPolicy":
			index.networkPolicies = append(index.networkPolicies, item)
		case item.GetAPIVersion() == "gateway.networking.k8s.io/v1" && item.GetKind() == "Gateway":
			index.observedGateway = true
			index.gatewaysByName[namespacedName(item.GetNamespace(), item.GetName())] = item
		case item.GetAPIVersion() == "gateway.networking.k8s.io/v1" && item.GetKind() == "HTTPRoute":
			index.observedHTTPRoute = true
			index.httpRoutes = append(index.httpRoutes, item)
		}
	}
	return index
}

func (index objectIndex) podsForLabels(namespace string, selector map[string]string) []*unstructured.Unstructured {
	candidates := index.podsByNamespace[namespace]
	for key, value := range selector {
		indexed := index.podsByLabel[podLabelKey(namespace, key, value)]
		if len(indexed) < len(candidates) {
			candidates = indexed
		}
	}
	return candidates
}

func podLabelKey(namespace, key, value string) string {
	return namespace + "\x00" + key + "\x00" + value
}

func isIstioOwned(item *unstructured.Unstructured) bool {
	group := strings.SplitN(item.GetAPIVersion(), "/", 2)[0]
	return group == "security.istio.io" || group == "networking.istio.io"
}
