// Package coherentcache is the consumer loop shared by the Kubernetes-backed
// semantic plugins. It subscribes to a plugin's resource collections and the
// Kubernetes coverage collection, keeps a cache from replay and live changes,
// and calls the plugin's projector only on a coherent snapshot: every resource
// collection and the coverage collection synced at the same Kubernetes
// generation. It then replaces the plugin's contribution at the plugin's next
// generation.
package coherentcache

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/plugins/internal/fanin"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Object keeps collection delivery metadata beside the native object so
// projected assertions can cite the native event as evidence.
type Object struct {
	Key        string
	Object     *unstructured.Unstructured
	EventID    string
	Revision   string
	ObservedAt time.Time
}

// Snapshot is one coherent immutable view of every consumed collection.
type Snapshot struct {
	Objects []Object
	// Coverage is keyed by lowercase capability/GVR.
	Coverage map[string]kubernetesplugin.ResourceCoverage
}

// Config describes one semantic plugin instance.
type Config struct {
	PluginID string
	SourceID string
	// Contribution is the name of the contribution Project fills.
	Contribution string
	Resources    []*kubernetesplugin.ResourceClient[*unstructured.Unstructured]
	// ReadyCollection, if set, is marked ready at each published generation
	// for plugins that consume this plugin's projection.
	ReadyCollection string
	// OnObjects, if set, receives each new coherent object set before it is
	// published, for example to refresh a telemetry resolver. It must not
	// modify the map or its objects.
	OnObjects func(map[string]Object)
	// Project returns the contribution input and the source health derived
	// from coverage. It must be a pure function of the snapshot.
	Project func(Snapshot) (graph.Input, string, error)
}

// collection is the cache of one resource collection: the live state, the
// state at its last sync marker, and that marker's generation and time.
type collection struct {
	live       map[string]Object
	synced     map[string]Object
	generation uint64
	observedAt time.Time
}

type cache struct {
	config  Config
	runtime discovery.Runtime
	// generation is the plugin's contribution generation.
	generation  uint64
	collections map[string]*collection
	// objects is the merged coherent object set at objectGeneration.
	objects          map[string]Object
	objectGeneration uint64
	objectObservedAt time.Time
	// coverage is live; coherentCoverage is its state at the last coverage
	// sync. coverageKeys maps a coverage change key to the records it holds.
	coverage           map[string]kubernetesplugin.ResourceCoverage
	coverageKeys       map[string][]string
	coherentCoverage   map[string]kubernetesplugin.ResourceCoverage
	coverageGeneration uint64
	coverageObservedAt time.Time
	published          bool
	publishedDigest    [32]byte
}

// Run consumes the collections and replaces the contribution whenever both
// the objects and the coverage reach a new coherent generation. It returns on
// ctx cancellation, a subscription error or unexpected closure, a malformed
// change, or a failed projection or publication. Before returning for a
// subscription failure after a successful publication, it republishes the
// last coherent snapshot with degraded health.
func Run(ctx context.Context, runtime discovery.Runtime, config Config) error {
	objectChanges := make(chan kubernetesplugin.ResourceChange[*unstructured.Unstructured])
	objectErrors := make(chan error, len(config.Resources))
	for _, client := range config.Resources {
		changes, errorsChannel, err := client.Subscribe(ctx, runtime)
		if err != nil {
			return fmt.Errorf("subscribe to Kubernetes resource %s: %w", client.Requirement().GVR, err)
		}
		go fanin.Forward(ctx, changes, errorsChannel, objectChanges, objectErrors)
	}
	coverageChanges, err := runtime.Subscribe(ctx, kubernetesplugin.CollectionResourceCoverage)
	if err != nil {
		return fmt.Errorf("subscribe to Kubernetes resource coverage: %w", err)
	}
	generation, err := runtime.ContributionGeneration(ctx, config.PluginID, config.SourceID)
	if err != nil {
		return fmt.Errorf("restore %s contribution generation: %w", config.PluginID, err)
	}
	state := &cache{
		config: config, runtime: runtime, generation: generation,
		collections: make(map[string]*collection, len(config.Resources)),
		objects:     make(map[string]Object),
		coverage:    make(map[string]kubernetesplugin.ResourceCoverage), coverageKeys: make(map[string][]string),
		coherentCoverage: make(map[string]kubernetesplugin.ResourceCoverage),
	}
	for _, client := range config.Resources {
		state.collections[client.Collection()] = &collection{live: make(map[string]Object)}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-objectErrors:
			state.degrade(ctx)
			return err
		case change := <-objectChanges:
			if err := state.applyObject(ctx, change); err != nil {
				return err
			}
		case change, ok := <-coverageChanges:
			if !ok {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				state.degrade(ctx)
				return errors.New("Kubernetes resource-coverage subscription closed unexpectedly")
			}
			if err := state.applyCoverage(ctx, change); err != nil {
				return err
			}
		}
	}
}

func (c *cache) applyObject(ctx context.Context, change kubernetesplugin.ResourceChange[*unstructured.Unstructured]) error {
	state := c.collections[change.Collection]
	if state == nil {
		return fmt.Errorf("change for unsubscribed Kubernetes collection %q", change.Collection)
	}
	switch change.Operation {
	case discovery.OperationUpsert:
		state.live[change.Key] = Object{Key: change.Key, Object: change.Object, EventID: change.EventID, Revision: change.Revision, ObservedAt: change.ObservedAt}
	case discovery.OperationDelete:
		delete(state.live, change.Key)
	case discovery.OperationSync:
		state.synced = cloneObjects(state.live)
		state.generation = change.Generation
		state.observedAt = change.ObservedAt
		generation, observedAt, ready := c.coherentGeneration()
		if !ready || generation <= c.objectGeneration {
			return nil
		}
		c.objectGeneration = generation
		c.objectObservedAt = observedAt
		c.objects = c.mergeSynced()
		if c.config.OnObjects != nil {
			c.config.OnObjects(c.objects)
		}
		return c.publish(ctx, "")
	default:
		return fmt.Errorf("unsupported Kubernetes object operation %q", change.Operation)
	}
	return nil
}

// applyCoverage tracks coverage records. The coherent coverage and its
// observation time come only from the sync marker: an upsert after the
// marker belongs to the next generation.
func (c *cache) applyCoverage(ctx context.Context, change discovery.Change) error {
	switch change.Operation {
	case discovery.OperationUpsert:
		records, err := decodeCoverage(change.Payload)
		if err != nil {
			return fmt.Errorf("decode Kubernetes resource coverage %q: %w", change.Key, err)
		}
		c.removeCoverage(change.Key)
		keys := make([]string, 0, len(records))
		for _, record := range records {
			key := coverageKey(record)
			c.coverage[key] = record
			keys = append(keys, key)
		}
		c.coverageKeys[change.Key] = keys
	case discovery.OperationDelete:
		c.removeCoverage(change.Key)
	case discovery.OperationSync:
		c.coherentCoverage = maps.Clone(c.coverage)
		c.coverageGeneration = change.Generation
		c.coverageObservedAt = change.ObservedAt
		return c.publish(ctx, "")
	default:
		return fmt.Errorf("unsupported Kubernetes resource-coverage operation %q", change.Operation)
	}
	return nil
}

func (c *cache) removeCoverage(changeKey string) {
	for _, key := range c.coverageKeys[changeKey] {
		delete(c.coverage, key)
	}
	delete(c.coverageKeys, changeKey)
}

// coherentGeneration reports the generation at which every resource
// collection last synced, if they all agree, and the latest sync time.
func (c *cache) coherentGeneration() (uint64, time.Time, bool) {
	var generation uint64
	var observedAt time.Time
	for _, client := range c.config.Resources {
		state := c.collections[client.Collection()]
		if state.generation == 0 || generation != 0 && state.generation != generation {
			return 0, time.Time{}, false
		}
		generation = state.generation
		observedAt = laterTime(observedAt, state.observedAt)
	}
	return generation, observedAt, generation != 0
}

// mergeSynced merges the synced collections in resource order.
func (c *cache) mergeSynced() map[string]Object {
	result := make(map[string]Object)
	for _, client := range c.config.Resources {
		maps.Copy(result, c.collections[client.Collection()].synced)
	}
	return result
}

// publish projects and replaces the contribution when the objects and the
// coverage are coherent at the same generation. healthOverride replaces the
// projector's health when set.
func (c *cache) publish(ctx context.Context, healthOverride string) error {
	if c.objectGeneration == 0 || c.objectGeneration != c.coverageGeneration {
		return nil
	}
	objects := make([]Object, 0, len(c.objects))
	for _, object := range c.objects {
		objects = append(objects, object)
	}
	input, health, err := c.config.Project(Snapshot{Objects: objects, Coverage: maps.Clone(c.coherentCoverage)})
	if err != nil {
		return err
	}
	if healthOverride != "" {
		health = healthOverride
	}
	encoded, err := json.Marshal(struct {
		Input  graph.Input
		Health string
	}{input, health})
	if err != nil {
		return fmt.Errorf("encode %s projection: %w", c.config.PluginID, err)
	}
	digest := sha256.Sum256(encoded)
	if healthOverride == "" && c.published && digest == c.publishedDigest {
		return nil
	}
	c.generation++
	if err := c.runtime.ReplaceContribution(ctx, c.config.PluginID, c.config.SourceID, discovery.ContributionOutput{
		Name: c.config.Contribution, Generation: c.generation, Input: input,
		SourceObservedAt: laterTime(c.objectObservedAt, c.coverageObservedAt), Ready: true, SourceHealth: health,
	}); err != nil {
		return err
	}
	if c.config.ReadyCollection != "" {
		if err := c.runtime.MarkReady(ctx, c.config.PluginID, c.config.SourceID, c.config.ReadyCollection, c.generation); err != nil {
			return fmt.Errorf("mark %s projection ready: %w", c.config.PluginID, err)
		}
	}
	c.published = true
	c.publishedDigest = digest
	return nil
}

// degrade republishes the last coherent snapshot with degraded health after a
// subscription failure. Its error is dropped: the caller is already returning
// the subscription failure, and the manager also marks the contribution
// degraded when Run fails.
func (c *cache) degrade(ctx context.Context) {
	if c.published {
		_ = c.publish(ctx, "degraded")
	}
}

func cloneObjects(objects map[string]Object) map[string]Object {
	return maps.Clone(objects)
}

// coverageEnvelope is a coverage payload carrying several records. The
// Kubernetes plugin publishes one record per change; the envelope form is
// accepted too.
type coverageEnvelope struct {
	Resources []kubernetesplugin.ResourceCoverage `json:"resources"`
	Coverage  []kubernetesplugin.ResourceCoverage `json:"coverage"`
}

func decodeCoverage(payload []byte) ([]kubernetesplugin.ResourceCoverage, error) {
	var envelope coverageEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, err
	}
	if result := append(envelope.Resources, envelope.Coverage...); len(result) > 0 {
		return result, nil
	}
	var record kubernetesplugin.ResourceCoverage
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, err
	}
	return []kubernetesplugin.ResourceCoverage{record}, nil
}

// coverageKey returns the lowercase capability/GVR key of [Snapshot.Coverage].
func coverageKey(record kubernetesplugin.ResourceCoverage) string {
	return strings.ToLower(record.Capability + "/" + record.GVR)
}

func laterTime(left, right time.Time) time.Time {
	if left.After(right) {
		return left
	}
	return right
}
