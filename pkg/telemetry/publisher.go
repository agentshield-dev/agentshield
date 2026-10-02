package telemetry

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// Every (plugin, source) pair that produced rollups owns one contribution
// named RollupContributionName and marks RollupCollection ready after each
// publication.
const (
	RollupContributionName = "rollups"
	RollupCollection       = "telemetry/rollups"
)

// RollupTarget persists rollup contributions. The host implements it over the
// discovery runtime, which this package cannot import.
type RollupTarget interface {
	// ContributionGeneration returns the highest durable contribution
	// generation for (plugin, source).
	ContributionGeneration(ctx context.Context, pluginID, sourceID string) (uint64, error)
	// PublishRollup replaces the (plugin, source) rollup contribution with
	// input at generation and marks RollupCollection ready at generation.
	PublishRollup(ctx context.Context, pluginID, sourceID string, generation uint64, input graph.Input, observedAt time.Time) error
}

// RollupPublisherConfig configures a RollupPublisher.
type RollupPublisherConfig struct {
	Rollup *Rollup
	// Snapshot returns the current graph. It resolves event endpoints and
	// decides which rollup assertions are published.
	Snapshot func(context.Context) (graph.Snapshot, error)
	Target   RollupTarget
	// PublishInterval bounds graph publication frequency independently of raw
	// sink flushing. Zero publishes on every commit.
	PublishInterval time.Duration
	// Now is the clock for observation, expiry, and the unresolved-address
	// grace. Defaults to time.Now.
	Now func() time.Time
	// Logger receives counts of future-dated events left out of the rollup.
	// Default slog.Default().
	Logger *slog.Logger
}

// skewLogInterval limits how often skipped future-dated events are logged.
const skewLogInterval = time.Minute

// RollupPublisher projects sink-committed telemetry into per-provider rollup
// contributions. Its Commit method is the pipeline's CommitFunc.
//
// Each (plugin, source) that has ever produced rollups in this process is
// republished on every commit that changed something, with generations
// advancing from the durable generation read on first use. A pair whose
// series have all expired is published with empty input so its stale
// assertions retract. Publication is in (plugin, source) order.
//
// A RollupPublisher is not safe for concurrent use; [Pipeline] never calls its
// CommitFunc concurrently.
type RollupPublisher struct {
	config RollupPublisherConfig
	// generations caches the last published generation per owner. Zero means
	// unknown: a publication failed ambiguously, so the next one re-reads the
	// durable generation.
	generations map[rollupOwner]uint64
	digests     map[rollupOwner][32]byte
	// pending holds sink-committed events until the next graph publication.
	// shortcut: cadence buffers sink-committed events in memory, pre-aggregate
	// before publication if measured traffic makes one interval too large.
	pending []Event
	// dirty records rollup changes not yet published to every owner.
	dirty bool
	// skipped counts future-dated events since the last skew log.
	skipped      int
	skewLoggedAt time.Time
	nextPublish  time.Time
}

type rollupOwner struct {
	pluginID string
	sourceID string
}

// NewRollupPublisher validates config.
func NewRollupPublisher(config RollupPublisherConfig) (*RollupPublisher, error) {
	if config.Rollup == nil || config.Snapshot == nil || config.Target == nil {
		return nil, errors.New("rollup publisher requires a rollup, snapshot source, and target")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &RollupPublisher{config: config, generations: make(map[rollupOwner]uint64), digests: make(map[rollupOwner][32]byte)}, nil
}

// Commit observes events, advances rollup lifecycle, and republishes every
// owner's rollup contribution. It publishes nothing when events is empty and
// nothing expired, resolved, or is still unpublished.
//
// Commit follows the [CommitFunc] retry contract: after an error, the batch
// is kept (observed, or queued if the graph could not be loaded) and the next
// call, even with nil events, publishes it. Republishing replaces each
// owner's whole contribution, so a retry is idempotent. After a failed
// publication the owner's durable generation is re-read, because the failed
// write may have committed.
func (publisher *RollupPublisher) Commit(ctx context.Context, events []Event) error {
	rollup := publisher.config.Rollup
	publisher.pending = append(publisher.pending, events...)
	now := publisher.config.Now().UTC()
	if publisher.config.PublishInterval > 0 && !publisher.nextPublish.IsZero() && now.Before(publisher.nextPublish) {
		return nil
	}
	snapshot, err := publisher.config.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("load graph for telemetry rollup: %w", err)
	}
	resolvedChanged, skipped := rollup.ObserveResolved(publisher.pending, snapshot, now)
	if len(publisher.pending) > 0 || resolvedChanged {
		publisher.dirty = true
	}
	publisher.pending = nil
	publisher.logSkipped(skipped, now)
	if rollup.Advance(now) {
		publisher.dirty = true
	}
	if !publisher.dirty {
		return nil
	}
	owned := rollup.Inputs()
	active := make(map[rollupOwner]struct{}, len(owned))
	for _, input := range owned {
		active[rollupOwner{pluginID: input.PluginID, sourceID: input.SourceID}] = struct{}{}
	}
	for owner := range publisher.generations {
		if _, found := active[owner]; !found {
			owned = append(owned, OwnedInput{PluginID: owner.pluginID, SourceID: owner.sourceID})
		}
	}
	slices.SortFunc(owned, func(left, right OwnedInput) int {
		if order := cmp.Compare(left.PluginID, right.PluginID); order != 0 {
			return order
		}
		return cmp.Compare(left.SourceID, right.SourceID)
	})
	for _, input := range owned {
		owner := rollupOwner{pluginID: input.PluginID, sourceID: input.SourceID}
		resolved := retainResolved(input.Input, snapshot)
		encoded, err := json.Marshal(resolved)
		if err != nil {
			return fmt.Errorf("encode telemetry rollup for %s/%s: %w", input.PluginID, input.SourceID, err)
		}
		digest := sha256.Sum256(encoded)
		if previous, published := publisher.digests[owner]; published && previous == digest {
			continue
		}
		generation := publisher.generations[owner]
		if generation == 0 {
			generation, err = publisher.config.Target.ContributionGeneration(ctx, input.PluginID, input.SourceID)
			if err != nil {
				// Track the owner so it is still retracted if its series expire.
				publisher.generations[owner] = 0
				return err
			}
		}
		generation++
		if err := publisher.config.Target.PublishRollup(ctx, input.PluginID, input.SourceID, generation, resolved, now); err != nil {
			publisher.generations[owner] = 0
			return err
		}
		publisher.generations[owner] = generation
		publisher.digests[owner] = digest
	}
	publisher.dirty = false
	if publisher.config.PublishInterval > 0 {
		publisher.nextPublish = now.Add(publisher.config.PublishInterval)
	}
	return nil
}

// logSkipped reports future-dated events left out of the rollup, at most once
// per skewLogInterval, with a count only.
func (publisher *RollupPublisher) logSkipped(skipped int, now time.Time) {
	publisher.skipped += skipped
	if publisher.skipped == 0 || now.Sub(publisher.skewLoggedAt) < skewLogInterval {
		return
	}
	publisher.config.Logger.Warn("telemetry events dated past the clock skew bound were kept in the raw sink but not rolled up",
		"events", publisher.skipped)
	publisher.skipped = 0
	publisher.skewLoggedAt = now
}

// retainResolved drops relationship and telemetry assertions whose endpoints
// are neither in snapshot nor among input's own resources, so the rollup never
// publishes an edge to an identity the graph cannot resolve.
func retainResolved(input graph.Input, snapshot graph.Snapshot) graph.Input {
	resources := make(map[graph.IdentityClaim]struct{}, len(snapshot.Resources)+len(input.Resources))
	for _, resource := range snapshot.Resources {
		resources[resource.Identity] = struct{}{}
	}
	for _, resource := range input.Resources {
		resources[resource.Claim] = struct{}{}
	}
	resolvedRelationships := input.Relationships[:0]
	for _, relationship := range input.Relationships {
		_, subjectFound := resources[relationship.Subject]
		_, objectFound := resources[relationship.Object]
		if subjectFound && objectFound {
			resolvedRelationships = append(resolvedRelationships, relationship)
		}
	}
	input.Relationships = resolvedRelationships
	resolved := input.Telemetry[:0]
	for _, event := range input.Telemetry {
		_, subjectFound := resources[event.Subject]
		_, objectFound := resources[event.Object]
		if subjectFound && objectFound {
			resolved = append(resolved, event)
		}
	}
	input.Telemetry = resolved
	return input
}
