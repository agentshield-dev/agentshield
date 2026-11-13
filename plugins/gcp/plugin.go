package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
)

const (
	defaultPollInterval   = 5 * time.Minute
	instancesCollection   = "gcp/compute/instances"
	firewallsCollection   = "gcp/compute/firewalls"
	subnetworksCollection = "gcp/compute/subnetworks"
)

// Config configures one project source. ProjectID and ProjectNumber must name
// the same project, and SourceID should come from [SourceID]. Region is an
// optional filter for zonal and regional resources.
type Config struct {
	ProjectID     string
	ProjectNumber string
	Region        string
	SourceID      string
	Compute       ComputeAPI
	PollInterval  time.Duration
}

// Plugin is the GCP Compute Engine source plugin for one project.
type Plugin struct {
	config Config
}

// New validates config and applies the default five-minute poll interval.
func New(config Config) (*Plugin, error) {
	config.ProjectID = strings.TrimSpace(config.ProjectID)
	config.ProjectNumber = strings.TrimSpace(config.ProjectNumber)
	config.Region = strings.TrimSpace(config.Region)
	config.SourceID = strings.TrimSpace(config.SourceID)
	if config.ProjectID == "" || !validNumericID(config.ProjectNumber) || config.SourceID == "" {
		return nil, errors.New("GCP plugin requires project ID, numeric project number, and source ID")
	}
	if err := validateClient(config.Compute); err != nil {
		return nil, err
	}
	if config.PollInterval <= 0 {
		config.PollInterval = defaultPollInterval
	}
	return &Plugin{config: config}, nil
}

// SourceID returns gcp/<project-number>, or gcp/<project-number>/<region>
// with a region filter. The project number, not the mutable display name or
// the project ID string, identifies the observer.
func SourceID(projectNumber, region string) (string, error) {
	projectNumber = strings.TrimSpace(projectNumber)
	region = strings.TrimSpace(region)
	if !validNumericID(projectNumber) {
		return "", errors.New("GCP source identity requires a numeric project number")
	}
	if region == "" {
		return "gcp/" + projectNumber, nil
	}
	if !validGCPName(region) {
		return "", fmt.Errorf("invalid GCP region %q", region)
	}
	return "gcp/" + projectNumber + "/" + region, nil
}

// SourceID returns the configured source ID.
func (p *Plugin) SourceID() string { return p.config.SourceID }

// ResolveIdentityReference resolves a Kubernetes Node spec.providerID of the
// form gce://<project-id>/<zone>/<instance-name> to an instance claim in this
// source's project. It reports false for other references so other resolvers
// may claim them.
func (p *Plugin) ResolveIdentityReference(reference string) (graph.IdentityClaim, bool, error) {
	return instanceClaimFromProviderID(p.config.ProjectID, p.config.ProjectNumber, p.config.Region, reference)
}

// Descriptor registers the cloud.google.com/v1 Resource identity scheme and
// the published collections.
func Descriptor() discovery.Descriptor {
	return discovery.Descriptor{
		ID: PluginID, Version: "0.1.0", Description: "GCP Compute Engine network security inventory",
		IdentitySchemes: []graph.SchemeDefinition{IdentitySchemeDefinition()},
	}
}

// Descriptor adds the published collections to [Descriptor].
func (p *Plugin) Descriptor() discovery.Descriptor {
	descriptor := Descriptor()
	descriptor.Publishes = []string{instancesCollection, firewallsCollection, subnetworksCollection}
	return descriptor
}

// Run polls and reconciles until ctx ends. See the package documentation for
// readiness and degraded-health behavior.
func (p *Plugin) Run(ctx context.Context, runtime discovery.Runtime) error {
	generation, err := runtime.ContributionGeneration(ctx, PluginID, p.config.SourceID)
	if err != nil {
		return fmt.Errorf("restore GCP contribution generation: %w", err)
	}
	var current Snapshot
	var input graph.Input
	var observedAt time.Time
	ready := false
	healthy := false
	retainDegraded := func(candidateErr error) error {
		if !ready {
			return candidateErr
		}
		if healthy {
			generation++
			if err := p.replace(ctx, runtime, input, generation, observedAt, "degraded"); err != nil {
				return err
			}
			healthy = false
		}
		return nil
	}
	reconcile := func() error {
		next, captureErr := capture(ctx, p.config.Compute, p.config.SourceID, p.config.ProjectID, p.config.Region)
		if captureErr != nil {
			return retainDegraded(captureErr)
		}
		now := time.Now().UTC()
		projected, err := Project(ProjectionContext{ProjectNumber: p.config.ProjectNumber, SourceID: p.config.SourceID}, next)
		if err != nil {
			return retainDegraded(fmt.Errorf("project GCP snapshot: %w", err))
		}
		generation++
		if err := p.publishChanges(ctx, runtime, current, next, generation, now); err != nil {
			return err
		}
		if err := p.replace(ctx, runtime, projected.Input, generation, now, "healthy"); err != nil {
			return err
		}
		for _, collection := range p.Descriptor().Publishes {
			if err := runtime.MarkReady(ctx, PluginID, p.config.SourceID, collection, generation); err != nil {
				return err
			}
		}
		current = next
		input = projected.Input
		observedAt = now
		ready = true
		healthy = true
		return nil
	}
	if err := reconcile(); err != nil {
		return err
	}
	ticker := time.NewTicker(p.config.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := reconcile(); err != nil {
				return err
			}
		}
	}
}

func (p *Plugin) replace(ctx context.Context, runtime discovery.Runtime, input graph.Input, generation uint64, observedAt time.Time, health string) error {
	return runtime.ReplaceContribution(ctx, PluginID, p.config.SourceID, discovery.ContributionOutput{
		Name: "inventory", Generation: generation, Input: input, SourceObservedAt: observedAt, Ready: true, SourceHealth: health,
	})
}

func (p *Plugin) publishChanges(ctx context.Context, runtime discovery.Runtime, previous, next Snapshot, generation uint64, observedAt time.Time) error {
	if err := publishCollection(ctx, runtime, p.config.SourceID, instancesCollection, previous.Instances, next.Instances, generation, observedAt, func(item Instance) (string, string, string, any) {
		return item.ID, item.Revision, item.EventID, item
	}); err != nil {
		return err
	}
	if err := publishCollection(ctx, runtime, p.config.SourceID, firewallsCollection, previous.Firewalls, next.Firewalls, generation, observedAt, func(item Firewall) (string, string, string, any) {
		return item.ID, item.Revision, item.EventID, item
	}); err != nil {
		return err
	}
	return publishCollection(ctx, runtime, p.config.SourceID, subnetworksCollection, previous.Subnetworks, next.Subnetworks, generation, observedAt, func(item Subnetwork) (string, string, string, any) {
		return item.ID, item.Revision, item.EventID, item
	})
}

func publishCollection[T any](ctx context.Context, runtime discovery.Runtime, sourceID, collection string, previous, next []T, generation uint64, observedAt time.Time, fields func(T) (string, string, string, any)) error {
	old := make(map[string]string, len(previous))
	for _, item := range previous {
		key, revision, _, _ := fields(item)
		old[key] = revision
	}
	current := make(map[string]struct{}, len(next))
	for _, item := range next {
		key, revision, id, payloadValue := fields(item)
		current[key] = struct{}{}
		if old[key] == revision {
			continue
		}
		payload, err := json.Marshal(payloadValue)
		if err != nil {
			return fmt.Errorf("encode GCP collection %s object %s: %w", collection, key, err)
		}
		if err := runtime.Publish(ctx, discovery.Change{
			EventID: id, PluginID: PluginID, SourceID: sourceID, Collection: collection, Key: key, Revision: revision,
			Generation: generation, Operation: discovery.OperationUpsert, ObservedAt: observedAt, Payload: payload,
		}); err != nil {
			return err
		}
	}
	var deleted []string
	for key := range old {
		if _, found := current[key]; !found {
			deleted = append(deleted, key)
		}
	}
	slices.Sort(deleted)
	for _, key := range deleted {
		if err := runtime.Publish(ctx, discovery.Change{
			EventID: eventID(sourceID, collection, key, old[key], "delete"), PluginID: PluginID, SourceID: sourceID,
			Collection: collection, Key: key, Revision: old[key], Generation: generation,
			Operation: discovery.OperationDelete, ObservedAt: observedAt,
		}); err != nil {
			return err
		}
	}
	return nil
}

// eventID includes the source so two sources never share an ID; the state
// store rejects a reused ID whose source differs.
func eventID(sourceID, collection, key, revision, operation string) string {
	return PluginID + ":" + sourceID + ":" + collection + ":" + key + ":" + revision + ":" + operation
}
