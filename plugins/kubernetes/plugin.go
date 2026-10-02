package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	agentshield "github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/projectkit"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Config configures one cluster source. NetworkID defaults to ClusterID,
// Actions to a transport over Dynamic, and Resync to 30 minutes. Resources
// are the merged semantic-plugin requirements from [ResourceRequirements].
type Config struct {
	ClusterID         string
	NetworkID         string
	SourceID          string
	Dynamic           dynamic.Interface
	Actions           WriteTransport
	Discovery         discovery.DiscoveryInterface
	Resync            time.Duration
	Resources         []ResourceRequirement
	IdentityResolvers []agentshield.IdentityReferenceResolver
}

// Plugin is the Kubernetes source, inventory projection, and remediation
// plugin.
type Plugin struct {
	config         Config
	publishedInput [32]byte
	hasPublication bool
}

// SourceID returns the configured source ID.
func (p *Plugin) SourceID() string { return p.config.SourceID }

func (p *Plugin) actionTransport() WriteTransport {
	if p.config.Actions != nil {
		return p.config.Actions
	}
	if p.config.Dynamic != nil {
		return &DynamicTransport{client: p.config.Dynamic}
	}
	return nil
}

// watchedResource is one shared informer and this plugin's handler on it.
// registration.HasSynced reports that the handler has processed the initial
// list, not only that the informer's store is filled; until then the
// collection is still missing objects.
type watchedResource struct {
	gvr          schema.GroupVersionResource
	informer     informers.GenericInformer
	registration cache.ResourceEventHandlerRegistration
}

// New validates config and applies defaults.
func New(config Config) (*Plugin, error) {
	if strings.TrimSpace(config.ClusterID) == "" || strings.TrimSpace(config.SourceID) == "" {
		return nil, errors.New("Kubernetes plugin requires cluster and source IDs")
	}
	if strings.TrimSpace(config.NetworkID) == "" {
		config.NetworkID = config.ClusterID
	}
	if config.Dynamic == nil || config.Discovery == nil {
		return nil, errors.New("Kubernetes plugin requires dynamic and discovery clients")
	}
	if config.Actions == nil {
		config.Actions = &DynamicTransport{client: config.Dynamic}
	}
	for _, requirement := range config.Resources {
		if err := validateResourceRequirement(requirement); err != nil {
			return nil, fmt.Errorf("invalid Kubernetes plugin resource: %w", err)
		}
	}
	if config.Resync <= 0 {
		config.Resync = 30 * time.Minute
	}
	return &Plugin{config: config}, nil
}

// NewForConfig builds clients from config and uses clusterID as network ID.
func NewForConfig(config *rest.Config, clusterID, sourceID string, resources ...ResourceRequirement) (*Plugin, error) {
	return NewForConfigWithNetworkID(config, clusterID, clusterID, sourceID, resources...)
}

// NewForConfigWithNetworkID builds clients from config.
func NewForConfigWithNetworkID(config *rest.Config, clusterID, networkID, sourceID string, resources ...ResourceRequirement) (*Plugin, error) {
	if config == nil {
		return nil, errors.New("Kubernetes REST config is required")
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %w", err)
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("create discovery client: %w", err)
	}
	return New(Config{ClusterID: clusterID, NetworkID: networkID, SourceID: sourceID, Dynamic: dynamicClient, Discovery: discoveryClient, Resources: resources})
}

// Descriptor adds a collection for each configured semantic-plugin GVR to
// [Descriptor].
func (p *Plugin) Descriptor() agentshield.Descriptor {
	descriptor := Descriptor()
	seen := make(map[string]struct{}, len(descriptor.Publishes))
	for _, collection := range descriptor.Publishes {
		seen[collection] = struct{}{}
	}
	for _, collection := range resourceCollections(p.config.Resources) {
		if _, found := seen[collection]; found {
			continue
		}
		descriptor.Publishes = append(descriptor.Publishes, collection)
		seen[collection] = struct{}{}
	}
	return descriptor
}

// Descriptor declares Kubernetes as the owner of the shared object and coverage
// collections and of the cluster-qualified Kubernetes identity scheme.
func Descriptor() agentshield.Descriptor {
	return agentshield.Descriptor{
		ID: PluginID, Version: "0.1.0", Description: "Kubernetes inventory and topology",
		Publishes:       append([]string{CollectionResourceCoverage}, resourceCollections(nil)...),
		IdentitySchemes: []graph.SchemeDefinition{IdentitySchemeDefinition()},
	}
}

// Run discovers APIs, starts one informer per selected GVR, and publishes
// observations, coverage, and the inventory contribution. Each informer
// change triggers a full reconciliation at the next generation; bursts
// coalesce into one.
func (p *Plugin) Run(ctx context.Context, runtime agentshield.Runtime) error {
	plan, err := resolveInventory(ctx, p.config.Discovery, p.config.Resources...)
	if err != nil {
		return err
	}
	factory := dynamicinformer.NewDynamicSharedInformerFactory(p.config.Dynamic, p.config.Resync)
	watchedResources := make([]watchedResource, 0, len(plan.resources))
	changes := make(chan struct{}, 1)
	errorsChannel := make(chan error, 1)
	var generation atomic.Uint64
	previousGeneration, err := runtime.ContributionGeneration(ctx, PluginID, p.config.SourceID)
	if err != nil {
		return err
	}
	generation.Store(previousGeneration + 1)

	publishError := func(err error) {
		select {
		case errorsChannel <- err:
		default:
		}
	}
	signal := func() {
		select {
		case changes <- struct{}{}:
		default:
		}
	}
	for _, gvr := range plan.resources {
		generic := factory.ForResource(gvr)
		if err := generic.Informer().SetTransform(stripManagedFields); err != nil {
			return fmt.Errorf("configure informer transform for %s: %w", gvr, err)
		}
		registration, err := generic.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(value any) {
				if item, ok := eventObject(value); ok {
					if err := p.publish(ctx, runtime, gvr, item, agentshield.OperationUpsert, generation.Load()); err != nil {
						publishError(err)
					}
					signal()
				}
			},
			UpdateFunc: func(oldValue, newValue any) {
				oldItem, oldOK := eventObject(oldValue)
				newItem, newOK := eventObject(newValue)
				if !newOK || (oldOK && oldItem.GetResourceVersion() == newItem.GetResourceVersion()) {
					return
				}
				if err := p.publish(ctx, runtime, gvr, newItem, agentshield.OperationUpsert, generation.Load()); err != nil {
					publishError(err)
				}
				signal()
			},
			DeleteFunc: func(value any) {
				if item, ok := eventObject(value); ok {
					if err := p.publish(ctx, runtime, gvr, item, agentshield.OperationDelete, generation.Load()); err != nil {
						publishError(err)
					}
					signal()
				}
			},
		})
		if err != nil {
			return fmt.Errorf("register informer for %s: %w", gvr, err)
		}
		watchedResources = append(watchedResources, watchedResource{gvr: gvr, informer: generic, registration: registration})
	}

	factory.Start(ctx.Done())
	// Wait for the handlers, not just the stores: the sync markers published
	// below tell consumers that every initial object is in the collection.
	synced := make([]cache.InformerSynced, 0, len(watchedResources))
	for _, resource := range watchedResources {
		synced = append(synced, resource.registration.HasSynced)
	}
	if !cache.WaitForCacheSync(ctx.Done(), synced...) {
		return errors.New("Kubernetes informer caches did not sync")
	}
	coverage := currentCoverage(plan, watchedResources)
	if err := p.publishCoverage(ctx, runtime, coverage, generation.Load()); err != nil {
		return err
	}
	if err := p.reconcile(ctx, runtime, watchedResources, coverage, generation.Load()); err != nil {
		return err
	}
	if err := p.markResourceCollectionsReady(ctx, runtime, generation.Load()); err != nil {
		return err
	}
	if err := runtime.MarkReady(ctx, PluginID, p.config.SourceID, CollectionResourceCoverage, generation.Load()); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errorsChannel:
			return err
		case <-changes:
			next := generation.Add(1)
			coverage := currentCoverage(plan, watchedResources)
			if err := p.publishCoverage(ctx, runtime, coverage, next); err != nil {
				return err
			}
			if err := p.reconcile(ctx, runtime, watchedResources, coverage, next); err != nil {
				return err
			}
			if err := p.markResourceCollectionsReady(ctx, runtime, next); err != nil {
				return err
			}
			if err := runtime.MarkReady(ctx, PluginID, p.config.SourceID, CollectionResourceCoverage, next); err != nil {
				return err
			}
		}
	}
}

func stripManagedFields(value any) (any, error) {
	if item, ok := value.(*unstructured.Unstructured); ok {
		item.SetManagedFields(nil)
	}
	return value, nil
}

func (p *Plugin) reconcile(ctx context.Context, runtime agentshield.Runtime, watchedResources []watchedResource, coverage []ResourceCoverage, generation uint64) error {
	var objects []*unstructured.Unstructured
	for _, resource := range watchedResources {
		for _, value := range resource.informer.Informer().GetStore().List() {
			if item, ok := eventObject(value); ok {
				objects = append(objects, item)
			}
		}
	}
	index := buildObjectIndex(objects)
	input, err := projectSnapshot(p.config.ClusterID, p.config.NetworkID, p.config.SourceID, index, capabilityCovered(coverage, "gateway-api-v1"), p.config.IdentityResolvers)
	if err != nil {
		return fmt.Errorf("project Kubernetes snapshot: %w", err)
	}
	health := "healthy"
	for _, item := range coverage {
		if item.Status == CoverageDegraded || item.Status == CoverageFailed {
			health = "degraded"
			break
		}
	}
	encoded, err := json.Marshal(struct {
		Input  graph.Input
		Health string
	}{input, health})
	if err != nil {
		return fmt.Errorf("encode Kubernetes projection: %w", err)
	}
	digest := sha256.Sum256(encoded)
	if p.hasPublication && digest == p.publishedInput {
		return nil
	}
	if err := runtime.ReplaceContribution(ctx, PluginID, p.config.SourceID, agentshield.ContributionOutput{
		Name: "inventory", Generation: generation, Input: input, SourceObservedAt: time.Now().UTC(), Ready: true, SourceHealth: health,
	}); err != nil {
		return err
	}
	p.publishedInput = digest
	p.hasPublication = true
	return nil
}

func currentCoverage(plan inventoryPlan, watchedResources []watchedResource) []ResourceCoverage {
	result := slices.Clone(plan.coverage)
	byGVR := make(map[string]bool, len(watchedResources))
	for _, resource := range watchedResources {
		byGVR[resource.gvr.String()] = resource.registration.HasSynced()
	}
	for index := range result {
		if result[index].Status != CoverageCovered {
			continue
		}
		if synced, selected := byGVR[result[index].GVR]; selected && !synced {
			if result[index].Required {
				result[index].Status = CoverageFailed
				result[index].Message = "required informer is not synced"
			} else {
				result[index].Status = CoverageDegraded
				result[index].Message = "advertised optional informer is not synced"
			}
		}
	}
	return result
}

func (p *Plugin) publishCoverage(ctx context.Context, runtime agentshield.Runtime, coverage []ResourceCoverage, generation uint64) error {
	for _, item := range coverage {
		payload, err := item.payload()
		if err != nil {
			return fmt.Errorf("encode coverage %s: %w", item.key(), err)
		}
		change := agentshield.Change{
			EventID:  PluginID + ":coverage:" + item.key() + ":" + strconv.FormatUint(generation, 10) + ":upsert",
			PluginID: PluginID, SourceID: p.config.SourceID, Collection: CollectionResourceCoverage, Key: item.key(),
			Revision: strconv.FormatUint(generation, 10), Generation: generation, Operation: agentshield.OperationUpsert,
			ObservedAt: time.Now().UTC(), Payload: payload,
		}
		if err := runtime.Publish(ctx, change); err != nil {
			return fmt.Errorf("publish coverage %s: %w", item.key(), err)
		}
	}
	return nil
}

func (p *Plugin) publish(ctx context.Context, runtime agentshield.Runtime, gvr schema.GroupVersionResource, item *unstructured.Unstructured, operation agentshield.Operation, generation uint64) error {
	key := projectkit.ObjectKey(item)
	collection := ResourceRequirement{GVR: gvr}.Collection()
	change := agentshield.Change{
		EventID:  projectkit.KubernetesEventID(key, item.GetResourceVersion(), string(operation)),
		PluginID: PluginID, SourceID: p.config.SourceID, Collection: collection, Key: key,
		Revision: item.GetResourceVersion(), Generation: generation, Operation: operation, ObservedAt: time.Now().UTC(),
	}
	if operation == agentshield.OperationUpsert {
		payload, err := json.Marshal(observationPayload(gvr, item))
		if err != nil {
			return err
		}
		change.Payload = payload
	}
	return runtime.Publish(ctx, change)
}

func observationPayload(gvr schema.GroupVersionResource, item *unstructured.Unstructured) map[string]any {
	if gvr.Group != "" || gvr.Version != "v1" || gvr.Resource != "secrets" {
		return item.Object
	}
	metadata := &unstructured.Unstructured{}
	metadata.SetAPIVersion(item.GetAPIVersion())
	metadata.SetKind(item.GetKind())
	metadata.SetNamespace(item.GetNamespace())
	metadata.SetName(item.GetName())
	metadata.SetUID(item.GetUID())
	metadata.SetResourceVersion(item.GetResourceVersion())
	metadata.SetGeneration(item.GetGeneration())
	metadata.SetCreationTimestamp(item.GetCreationTimestamp())
	metadata.SetDeletionTimestamp(item.GetDeletionTimestamp())
	metadata.SetDeletionGracePeriodSeconds(item.GetDeletionGracePeriodSeconds())
	metadata.SetLabels(item.GetLabels())
	metadata.SetOwnerReferences(item.GetOwnerReferences())
	metadata.SetFinalizers(item.GetFinalizers())
	keys := make(map[string]struct{})
	for _, field := range []string{"data", "stringData"} {
		values, _, _ := unstructured.NestedMap(item.Object, field)
		for key := range values {
			keys[key] = struct{}{}
		}
	}
	secretKeys := make([]string, 0, len(keys))
	for key := range keys {
		secretKeys = append(secretKeys, key)
	}
	slices.Sort(secretKeys)
	if len(secretKeys) > 0 {
		metadata.Object["keys"] = secretKeys
	}
	return metadata.Object
}

func (p *Plugin) markResourceCollectionsReady(ctx context.Context, runtime agentshield.Runtime, generation uint64) error {
	for _, collection := range resourceCollections(p.config.Resources) {
		if err := runtime.MarkReady(ctx, PluginID, p.config.SourceID, collection, generation); err != nil {
			return err
		}
	}
	return nil
}

func resourceCollections(requirements []ResourceRequirement) []string {
	seen := make(map[string]struct{})
	for _, spec := range requiredResourceSpecs {
		seen[ResourceRequirement{GVR: spec.gvr}.Collection()] = struct{}{}
	}
	for _, capability := range optionalResourceCapabilities {
		for _, spec := range capability {
			seen[ResourceRequirement{GVR: spec.gvr}.Collection()] = struct{}{}
		}
	}
	for _, requirement := range requirements {
		seen[requirement.Collection()] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for collection := range seen {
		result = append(result, collection)
	}
	slices.Sort(result)
	return result
}

func eventObject(value any) (*unstructured.Unstructured, bool) {
	switch item := value.(type) {
	case *unstructured.Unstructured:
		return item, true
	case cache.DeletedFinalStateUnknown:
		object, ok := item.Obj.(*unstructured.Unstructured)
		return object, ok
	default:
		return nil, false
	}
}
