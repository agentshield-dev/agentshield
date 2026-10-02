package discovery

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/progress"
	"github.com/agentshield-dev/agentshield/pkg/remediation"
	"github.com/agentshield-dev/agentshield/pkg/state"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

// RuntimeService is the unscoped host runtime shared by all plugins. Plugins
// never see it directly; Manager wraps it in a per-instance scoped runtime.
type RuntimeService struct {
	hub   *Hub
	store runtimeStore
}

// runtimeStore is the part of [state.Store] the runtime uses.
type runtimeStore interface {
	RecordNative(context.Context, state.NativeEvent) error
	ReplaceContribution(context.Context, state.Contribution) (state.GraphView, error)
	ContributionGeneration(context.Context, string, string) (uint64, error)
}

// NewRuntime returns a runtime backed by store with a fresh in-memory hub.
func NewRuntime(store *state.Store) (*RuntimeService, error) {
	if store == nil {
		return nil, errors.New("state store is required")
	}
	return &RuntimeService{hub: NewHub(), store: store}, nil
}

// Publish records a durable receipt before delivering change. A change that
// fails to persist is never delivered, so every observation a projector cites
// as evidence has durable provenance metadata and a content digest. Provider
// payloads remain in the in-memory collection path.
func (r *RuntimeService) Publish(ctx context.Context, change Change) error {
	if change.ObservedAt.IsZero() {
		change.ObservedAt = time.Now().UTC()
	}
	if err := r.recordNative(ctx, change); err != nil {
		return err
	}
	return r.hub.Publish(ctx, change)
}

func (r *RuntimeService) recordNative(ctx context.Context, change Change) error {
	return r.store.RecordNative(ctx, state.NativeEvent{
		EventID: change.EventID, PluginID: change.PluginID, SourceID: change.SourceID,
		Collection: change.Collection, Key: change.Key, Revision: change.Revision,
		Operation: string(change.Operation), ObservedAt: change.ObservedAt, Payload: change.Payload,
	})
}

// MarkReady publishes an in-memory sync marker. It is not persisted: after a
// restart the source must rebuild its cache and mark the collection ready again.
//
// After the manager restarts a plugin instance, the first MarkReady of each of
// its collections first deletes the items the new instance did not republish,
// so objects removed while it was down do not linger in consumers' caches.
// The delete's event ID is the item's last event ID with its ":upsert" suffix
// replaced by ":delete", which is the ID the Kubernetes and AWS plugins give
// their own delete of that revision; an ID without that suffix falls back to
// <plugin>:<collection>:<key>:<revision>:delete.
func (r *RuntimeService) MarkReady(ctx context.Context, pluginID, sourceID, collection string, generation uint64) error {
	now := time.Now().UTC()
	stale := r.hub.staleItems(sourceID, collection)
	for _, item := range stale {
		eventID, upsert := strings.CutSuffix(item.EventID, ":"+string(OperationUpsert))
		if !upsert {
			eventID = pluginID + ":" + collection + ":" + item.Key + ":" + item.Revision
		}
		change := Change{
			EventID:  eventID + ":" + string(OperationDelete),
			PluginID: pluginID, SourceID: sourceID, Collection: collection, Key: item.Key, Revision: item.Revision,
			Generation: generation, Operation: OperationDelete, ObservedAt: now,
		}
		if err := r.recordNative(ctx, change); err != nil {
			return fmt.Errorf("delete stale %s item %s: %w", collection, item.Key, err)
		}
		r.hub.deleteStale(change)
	}
	if len(stale) > 0 {
		r.hub.endResync(sourceID, collection)
		slog.InfoContext(ctx, "removed collection items not republished after plugin restart",
			"plugin", pluginID, "source", sourceID, "collection", collection, "items", len(stale))
	}
	change := Change{PluginID: pluginID, SourceID: sourceID, Collection: collection, Key: "sync", Generation: generation, Operation: OperationSync, ObservedAt: now}
	return r.hub.Publish(ctx, change)
}

// Subscribe always fails because a subscription must be scoped to a source;
// plugins subscribe through the scoped runtime that Manager provides.
func (r *RuntimeService) Subscribe(ctx context.Context, collection string) (<-chan Change, error) {
	return nil, errors.New("unscoped runtime subscriptions are not available to plugins")
}

// ReplaceContribution publishes output as the complete current contribution
// for (plugin, source, output.Name). A failure is logged here because some
// plugins only degrade their health after one instead of stopping.
func (r *RuntimeService) ReplaceContribution(ctx context.Context, pluginID, sourceID string, output ContributionOutput) error {
	_, err := r.store.ReplaceContribution(ctx, state.Contribution{
		PluginID: pluginID, SourceID: sourceID, Name: output.Name, Generation: output.Generation, Input: output.Input,
		SourceObservedAt: output.SourceObservedAt, Ready: output.Ready, SourceHealth: output.SourceHealth,
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("contribution publication failed",
			"plugin", pluginID, "source", sourceID, "contribution", output.Name, "generation", output.Generation, "error", err)
	}
	return err
}

// ContributionGeneration returns the highest durable generation for
// (plugin, source) so a restarted plugin resumes above it.
func (r *RuntimeService) ContributionGeneration(ctx context.Context, pluginID, sourceID string) (uint64, error) {
	return r.store.ContributionGeneration(ctx, pluginID, sourceID)
}

// RollupTarget returns the [telemetry.RollupTarget] that publishes each
// telemetry rollup as a ready, healthy contribution and then marks the rollup
// collection ready at the same generation.
func (r *RuntimeService) RollupTarget() telemetry.RollupTarget {
	return rollupTarget{runtime: r}
}

type rollupTarget struct {
	runtime *RuntimeService
}

func (t rollupTarget) ContributionGeneration(ctx context.Context, pluginID, sourceID string) (uint64, error) {
	return t.runtime.ContributionGeneration(ctx, pluginID, sourceID)
}

func (t rollupTarget) PublishRollup(ctx context.Context, pluginID, sourceID string, generation uint64, input graph.Input, observedAt time.Time) error {
	if err := t.runtime.ReplaceContribution(ctx, pluginID, sourceID, ContributionOutput{
		Name: telemetry.RollupContributionName, Generation: generation, Input: input, SourceObservedAt: observedAt, Ready: true, SourceHealth: "healthy",
	}); err != nil {
		return err
	}
	return t.runtime.MarkReady(ctx, pluginID, sourceID, telemetry.RollupCollection, generation)
}

// Manager validates and runs a fixed set of plugin instances. It owns the
// collection topology check and the remediation provider registry.
type Manager struct {
	runtime      *RuntimeService
	plugins      []managedPlugin
	remediations *remediation.Registry
	// restartBackoff and maxRestartBackoff bound the delay before a failed
	// plugin instance is restarted; tests shorten them.
	restartBackoff    time.Duration
	maxRestartBackoff time.Duration
}

// Restart delays for a failed plugin instance. The delay doubles per
// consecutive failure up to the cap, and resets once an instance has run for
// at least the cap.
const (
	defaultRestartBackoff    = time.Second
	defaultMaxRestartBackoff = 2 * time.Minute
)

type managedPlugin struct {
	plugin   Plugin
	sourceID string
}

// scopedRuntime is the Runtime handed to one plugin instance. It pins plugin
// and source provenance so an instance cannot publish, mark ready, or
// contribute as another plugin or source, and limits Subscribe to collections
// of its own source.
type scopedRuntime struct {
	runtime  *RuntimeService
	pluginID string
	sourceID string
	// progress counts the instance's observations and publications for its status line.
	progress *progress.Reporter
	// published remembers the instance's last stored output per contribution
	// so the manager can mark it degraded when the instance fails.
	published *publishedOutputs
}

// publishedOutputs is the last successfully stored output of each named
// contribution of one plugin instance. It outlives the instance's restarts.
type publishedOutputs struct {
	mu     sync.Mutex
	byName map[string]ContributionOutput
}

func (p *publishedOutputs) record(output ContributionOutput) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byName[output.Name] = output
}

func (p *publishedOutputs) snapshot() []ContributionOutput {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]ContributionOutput, 0, len(p.byName))
	for _, name := range slices.Sorted(maps.Keys(p.byName)) {
		result = append(result, p.byName[name])
	}
	return result
}

func (r scopedRuntime) Publish(ctx context.Context, change Change) error {
	if change.PluginID != r.pluginID || change.SourceID != r.sourceID {
		return errors.New("discovery change provenance does not match the scoped plugin instance")
	}
	if err := r.runtime.Publish(ctx, change); err != nil {
		return err
	}
	r.count("observations")
	return nil
}

func (r scopedRuntime) count(name string) {
	if r.progress != nil {
		r.progress.Add(name, 1)
	}
}

func (r scopedRuntime) MarkReady(ctx context.Context, pluginID, sourceID, collection string, generation uint64) error {
	if pluginID != r.pluginID || sourceID != r.sourceID {
		return errors.New("discovery readiness provenance does not match the scoped plugin instance")
	}
	return r.runtime.MarkReady(ctx, pluginID, sourceID, collection, generation)
}

func (r scopedRuntime) Subscribe(ctx context.Context, collection string) (<-chan Change, error) {
	return r.runtime.hub.subscribe(ctx, r.sourceID, collection, r.pluginID)
}

func (r scopedRuntime) ReplaceContribution(ctx context.Context, pluginID, sourceID string, output ContributionOutput) error {
	if pluginID != r.pluginID || sourceID != r.sourceID {
		return errors.New("contribution provenance does not match the scoped plugin instance")
	}
	if err := r.runtime.ReplaceContribution(ctx, pluginID, sourceID, output); err != nil {
		return err
	}
	r.published.record(output)
	r.count("contributions")
	return nil
}

func (r scopedRuntime) ContributionGeneration(ctx context.Context, pluginID, sourceID string) (uint64, error) {
	if pluginID != r.pluginID || sourceID != r.sourceID {
		return 0, errors.New("contribution generation provenance does not match the scoped plugin instance")
	}
	return r.runtime.ContributionGeneration(ctx, pluginID, sourceID)
}

type pluginInstanceKey struct {
	pluginID string
	sourceID string
}

// NewManager validates the plugin set: every plugin needs an ID, version, and
// stable source ID; each (plugin, source) appears once; each (source,
// collection) has one publisher; and every consumed collection has a publisher
// on the same source. Plugins are sorted so startup order is deterministic.
// Remediation capabilities are registered separately from discovery.
func NewManager(runtime *RuntimeService, plugins ...Plugin) (*Manager, error) {
	if runtime == nil {
		return nil, errors.New("runtime is required")
	}
	seen := make(map[pluginInstanceKey]struct{}, len(plugins))
	published := make(map[collectionKey]string)
	var remediationProviders []remediation.Registration
	managed := make([]managedPlugin, 0, len(plugins))
	for _, plugin := range plugins {
		if plugin == nil {
			return nil, errors.New("nil plugin")
		}
		descriptor := plugin.Descriptor()
		if descriptor.ID == "" || descriptor.Version == "" {
			return nil, errors.New("plugin descriptor requires ID and version")
		}
		instance, ok := plugin.(PluginInstance)
		if !ok || instance.SourceID() == "" {
			return nil, fmt.Errorf("plugin %q requires a stable nonempty source ID", descriptor.ID)
		}
		sourceID := instance.SourceID()
		key := pluginInstanceKey{pluginID: descriptor.ID, sourceID: sourceID}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("plugin instance %q/%q registered more than once", descriptor.ID, sourceID)
		}
		seen[key] = struct{}{}
		managed = append(managed, managedPlugin{plugin: plugin, sourceID: sourceID})
		if provider, ok := plugin.(RemediationProvider); ok {
			remediationProviders = append(remediationProviders, remediation.Registration{ProviderID: descriptor.ID, SourceID: sourceID, Provider: provider})
		}
		for _, collection := range descriptor.Publishes {
			collectionKey := collectionKey{sourceID: sourceID, collection: collection}
			if owner, exists := published[collectionKey]; exists {
				return nil, fmt.Errorf("collection %q for source %q is published by both %q and %q", collection, sourceID, owner, descriptor.ID)
			}
			published[collectionKey] = descriptor.ID
		}
	}
	for _, instance := range managed {
		descriptor := instance.plugin.Descriptor()
		for _, collection := range descriptor.Consumes {
			if _, exists := published[collectionKey{sourceID: instance.sourceID, collection: collection}]; !exists {
				return nil, fmt.Errorf("plugin %q source %q consumes collection %q with no same-source publisher", descriptor.ID, instance.sourceID, collection)
			}
		}
	}
	slices.SortFunc(managed, func(left, right managedPlugin) int {
		if result := cmp.Compare(left.plugin.Descriptor().ID, right.plugin.Descriptor().ID); result != 0 {
			return result
		}
		return cmp.Compare(left.sourceID, right.sourceID)
	})
	remediations, err := remediation.NewRegistry(remediationProviders...)
	if err != nil {
		return nil, fmt.Errorf("register remediation providers: %w", err)
	}
	return &Manager{
		runtime: runtime, plugins: managed, remediations: remediations,
		restartBackoff: defaultRestartBackoff, maxRestartBackoff: defaultMaxRestartBackoff,
	}, nil
}

// Remediations returns the providers extracted from plugins that implement
// RemediationProvider.
func (m *Manager) Remediations() *remediation.Registry {
	return m.remediations
}

// Run starts every plugin instance concurrently and blocks until ctx ends.
//
// Each instance is supervised on its own: when its Run returns an error or
// panics while ctx is live, the manager logs the failure, republishes the
// instance's last stored healthy contributions with degraded source health
// (their assertions stay active rather than being retracted), and restarts it
// after an exponential backoff. Other instances keep running. A restarted
// instance rebuilds its caches; see [RuntimeService.MarkReady] for how items
// it no longer publishes are removed. An instance whose Run returns nil while
// ctx is live has finished and is not restarted; if every instance finishes,
// Run reports an error, because discovery is expected to run for the life of
// the process. Cancellation of ctx returns nil unless it carries a
// non-cancellation cause.
func (m *Manager) Run(ctx context.Context) error {
	var wait sync.WaitGroup
	reporters := make([]*progress.Reporter, 0, len(m.plugins))
	for _, instance := range m.plugins {
		descriptor := instance.plugin.Descriptor()
		reporter := progress.New("discovery plugin", "plugin", descriptor.ID, "source", instance.sourceID)
		reporters = append(reporters, reporter)
		wait.Add(1)
		go func() {
			defer wait.Done()
			m.supervise(ctx, instance, descriptor, reporter)
		}()
	}
	done := make(chan struct{})
	go func() { wait.Wait(); close(done) }()
	// One goroutine logs every plugin instance's bounded status line.
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				for _, reporter := range reporters {
					reporter.Tick(ctx, nil)
				}
			}
		}
	}()
	<-done
	if ctx.Err() == nil {
		return errors.New("all discovery plugins stopped unexpectedly")
	}
	if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// supervise runs one plugin instance until ctx ends or the instance returns
// nil, restarting it after each failure.
func (m *Manager) supervise(ctx context.Context, instance managedPlugin, descriptor Descriptor, reporter *progress.Reporter) {
	published := &publishedOutputs{byName: make(map[string]ContributionOutput)}
	runtime := scopedRuntime{runtime: m.runtime, pluginID: descriptor.ID, sourceID: instance.sourceID, progress: reporter, published: published}
	delay := m.restartBackoff
	for attempt := 1; ; attempt++ {
		if attempt > 1 {
			m.runtime.hub.beginResync(instance.sourceID, descriptor.Publishes)
		}
		slog.InfoContext(ctx, "discovery plugin started", "plugin", descriptor.ID, "source", instance.sourceID, "attempt", attempt)
		started := time.Now()
		err := runInstance(ctx, instance.plugin, runtime)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			slog.InfoContext(ctx, "discovery plugin finished", "plugin", descriptor.ID, "source", instance.sourceID)
			return
		}
		if time.Since(started) >= m.maxRestartBackoff {
			delay = m.restartBackoff
		}
		slog.ErrorContext(ctx, "discovery plugin failed; restarting", "plugin", descriptor.ID, "source", instance.sourceID,
			"attempt", attempt, "restart_in", delay, "error", err)
		m.degrade(ctx, descriptor.ID, instance.sourceID, published)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(delay*2, m.maxRestartBackoff)
	}
}

// runInstance runs one attempt of plugin under its own context, so the
// attempt's subscriptions and informers stop when it returns, and turns a
// panic in the plugin's Run goroutine into an error that carries the stack.
func runInstance(ctx context.Context, plugin Plugin, runtime Runtime) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("plugin panicked: %v\n%s", recovered, debug.Stack())
		}
	}()
	return plugin.Run(ctx, runtime)
}

// degrade republishes each last stored healthy contribution of a failed
// instance at the next generation with degraded health. The assertions stay
// active; only the source state changes. Failures are logged by
// ReplaceContribution and not returned: the restarted instance publishes again
// from the durable generation.
func (m *Manager) degrade(ctx context.Context, pluginID, sourceID string, published *publishedOutputs) {
	outputs := published.snapshot()
	healthy := func(output ContributionOutput) bool {
		return output.SourceHealth == "" || output.SourceHealth == state.SourceHealthHealthy
	}
	if !slices.ContainsFunc(outputs, healthy) {
		return
	}
	generation, err := m.runtime.ContributionGeneration(ctx, pluginID, sourceID)
	if err != nil {
		slog.ErrorContext(ctx, "mark failed plugin contributions degraded", "plugin", pluginID, "source", sourceID, "error", err)
		return
	}
	for _, output := range outputs {
		if !healthy(output) {
			continue
		}
		output.Generation = generation + 1
		output.SourceHealth = state.SourceHealthDegraded
		if err := m.runtime.ReplaceContribution(ctx, pluginID, sourceID, output); err == nil {
			published.record(output)
		}
	}
}
