package aws

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

const defaultPollInterval = 5 * time.Minute

// Config configures one regional source. SourceID should come from
// [SourceID] so it is bound to the authenticated caller account. Subscriber is
// optional; without it the plugin relies on PollInterval alone.
type Config struct {
	Partition         string
	Region            string
	SourceID          string
	EC2               EC2API
	Subscriber        EventSubscriber
	PollInterval      time.Duration
	FirehoseStreamARN string
	FirehoseAccessKey string
}

// Plugin is the AWS EC2 source plugin for one partition, account, and region.
type Plugin struct {
	config Config
}

// New validates config and applies the default five-minute poll interval.
func New(config Config) (*Plugin, error) {
	config.Partition = strings.TrimSpace(config.Partition)
	config.Region = strings.TrimSpace(config.Region)
	config.SourceID = strings.TrimSpace(config.SourceID)
	if config.Partition == "" || config.Region == "" || config.SourceID == "" {
		return nil, errors.New("AWS plugin requires partition, region, and source ID")
	}
	if err := validateClient(config.EC2); err != nil {
		return nil, err
	}
	if config.PollInterval <= 0 {
		config.PollInterval = defaultPollInterval
	}
	return &Plugin{config: config}, nil
}

// SourceID returns aws/<partition>/<account>/<region>, the stable source ID
// for the authenticated caller. Changing accounts therefore changes the source
// and its contribution ownership.
func SourceID(partition, accountID, region string) (string, error) {
	partition = strings.TrimSpace(partition)
	accountID = strings.TrimSpace(accountID)
	region = strings.TrimSpace(region)
	if partition == "" || region == "" || !validAccountID(accountID) {
		return "", errors.New("AWS source identity requires partition, 12-digit account ID, and region")
	}
	return "aws/" + partition + "/" + accountID + "/" + region, nil
}

// SourceID returns the configured source ID.
func (p *Plugin) SourceID() string { return p.config.SourceID }

// ResolveIdentityReference resolves a Kubernetes Node spec.providerID of the
// form aws:///<zone>/<instance-id> to an instance claim in this source's
// account and region. It reports false for non-AWS references so other
// resolvers may claim them.
func (p *Plugin) ResolveIdentityReference(reference string) (graph.IdentityClaim, bool, error) {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(reference)), "aws://") {
		return graph.IdentityClaim{}, false, nil
	}
	parts := strings.Split(p.config.SourceID, "/")
	if len(parts) != 4 || parts[0] != "aws" || parts[1] != p.config.Partition || parts[3] != p.config.Region || !validAccountID(parts[2]) {
		return graph.IdentityClaim{}, false, fmt.Errorf("AWS source ID %q cannot resolve provider references", p.config.SourceID)
	}
	return instanceClaimFromProviderID(p.config.Partition, parts[2], p.config.Region, reference)
}

// Descriptor registers the aws.amazon.com/v1 Resource identity scheme. The
// per-region collections are added by [Plugin.Descriptor].
func Descriptor() discovery.Descriptor {
	return discovery.Descriptor{
		ID: PluginID, Version: "0.1.0", Description: "AWS EC2 network security inventory",
		IdentitySchemes: []graph.SchemeDefinition{IdentitySchemeDefinition()},
	}
}

// Descriptor adds this region's published collections to [Descriptor].
func (p *Plugin) Descriptor() discovery.Descriptor {
	descriptor := Descriptor()
	descriptor.Publishes = []string{networkInterfacesCollection(p.config.Region), instancesCollection(p.config.Region), securityGroupsCollection(p.config.Region)}
	return descriptor
}

// Run polls and reconciles until ctx ends. See the package documentation for
// readiness and degraded-health behavior.
func (p *Plugin) Run(ctx context.Context, runtime discovery.Runtime) error {
	generation, err := runtime.ContributionGeneration(ctx, PluginID, p.config.SourceID)
	if err != nil {
		return fmt.Errorf("restore AWS contribution generation: %w", err)
	}
	var current Snapshot
	var input graph.Input
	var observedAt time.Time
	ready := false
	healthy := false
	retainDegraded := func(candidateErr error) (bool, error) {
		if !ready {
			return false, candidateErr
		}
		if healthy {
			generation++
			if err := p.replace(ctx, runtime, input, generation, observedAt, "degraded"); err != nil {
				return false, err
			}
			healthy = false
		}
		return false, nil
	}
	reconcile := func() (bool, error) {
		next, captureErr := capture(ctx, p.config.EC2, p.config.Region)
		if captureErr != nil {
			return retainDegraded(captureErr)
		}
		now := time.Now().UTC()
		projected, err := Project(ProjectionContext{Partition: p.config.Partition, Region: p.config.Region, SourceID: p.config.SourceID}, next)
		if err != nil {
			return retainDegraded(fmt.Errorf("project AWS snapshot: %w", err))
		}
		generation++
		if err := p.publishChanges(ctx, runtime, current, next, generation, now); err != nil {
			return false, err
		}
		if err := p.replace(ctx, runtime, projected.Input, generation, now, "healthy"); err != nil {
			return false, err
		}
		for _, collection := range p.Descriptor().Publishes {
			if err := runtime.MarkReady(ctx, PluginID, p.config.SourceID, collection, generation); err != nil {
				return false, err
			}
		}
		current = next
		input = projected.Input
		observedAt = now
		ready = true
		healthy = true
		return true, nil
	}
	if _, err := reconcile(); err != nil {
		return err
	}
	ticker := time.NewTicker(p.config.PollInterval)
	defer ticker.Stop()
	var batches <-chan ChangeBatch
	var subscriberErrors <-chan error
	if p.config.Subscriber != nil {
		batchChannel := make(chan ChangeBatch)
		errorChannel := make(chan error, 1)
		batches = batchChannel
		subscriberErrors = errorChannel
		go receiveChanges(ctx, p.config.Subscriber, batchChannel, errorChannel)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := reconcile(); err != nil {
				return err
			}
		case err := <-subscriberErrors:
			return err
		case batch := <-batches:
			if len(batch.Subscriptions) == 0 {
				if err := p.config.Subscriber.Acknowledge(ctx, batch); err != nil {
					return err
				}
				continue
			}
			committed, err := reconcile()
			if err != nil {
				return err
			}
			if committed {
				if err := p.config.Subscriber.Acknowledge(ctx, batch); err != nil {
					return err
				}
			}
		}
	}
}

func receiveChanges(ctx context.Context, subscriber EventSubscriber, batches chan<- ChangeBatch, subscriberErrors chan<- error) {
	for {
		batch, err := subscriber.Receive(ctx)
		if err != nil {
			select {
			case subscriberErrors <- err:
			case <-ctx.Done():
			}
			return
		}
		select {
		case batches <- batch:
		case <-ctx.Done():
			return
		}
	}
}

func (p *Plugin) replace(ctx context.Context, runtime discovery.Runtime, input graph.Input, generation uint64, observedAt time.Time, health string) error {
	return runtime.ReplaceContribution(ctx, PluginID, p.config.SourceID, discovery.ContributionOutput{
		Name: "inventory", Generation: generation, Input: input, SourceObservedAt: observedAt, Ready: true, SourceHealth: health,
	})
}

func (p *Plugin) publishChanges(ctx context.Context, runtime discovery.Runtime, previous, next Snapshot, generation uint64, observedAt time.Time) error {
	if err := publishCollection(ctx, runtime, p.config.SourceID, networkInterfacesCollection(p.config.Region), previous.NetworkInterfaces, next.NetworkInterfaces, generation, observedAt, func(item NetworkInterface) (string, string, string, any) {
		return item.ID, item.Revision, item.EventID, item
	}); err != nil {
		return err
	}
	if err := publishCollection(ctx, runtime, p.config.SourceID, instancesCollection(p.config.Region), previous.Instances, next.Instances, generation, observedAt, func(item Instance) (string, string, string, any) {
		return item.ID, item.Revision, item.EventID, item
	}); err != nil {
		return err
	}
	return publishCollection(ctx, runtime, p.config.SourceID, securityGroupsCollection(p.config.Region), previous.SecurityGroups, next.SecurityGroups, generation, observedAt, func(item SecurityGroup) (string, string, string, any) {
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
			return fmt.Errorf("encode AWS collection %s object %s: %w", collection, key, err)
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
			EventID: eventID(collection, key, old[key], "delete"), PluginID: PluginID, SourceID: sourceID,
			Collection: collection, Key: key, Revision: old[key], Generation: generation,
			Operation: discovery.OperationDelete, ObservedAt: observedAt,
		}); err != nil {
			return err
		}
	}
	return nil
}

func networkInterfacesCollection(region string) string {
	return "aws/ec2/" + region + "/network-interfaces"
}

func securityGroupsCollection(region string) string {
	return "aws/ec2/" + region + "/security-groups"
}

func instancesCollection(region string) string {
	return "aws/ec2/" + region + "/instances"
}

func eventID(collection, key, revision, operation string) string {
	return PluginID + ":" + collection + ":" + key + ":" + revision + ":" + operation
}
