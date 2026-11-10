package gcp

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	compute "google.golang.org/api/compute/v1"
)

// pageSize is the Compute API maximum for list calls.
const pageSize = 500

// PageRequest selects one page of a project-scoped Compute list call.
type PageRequest struct {
	Project    string
	PageToken  string
	MaxResults int64
}

// ComputeAPI is the subset of the Compute Engine API used for inventory. Each
// call returns one page; capture follows page tokens to the end on each poll.
type ComputeAPI interface {
	AggregatedListInstances(context.Context, PageRequest) (*compute.InstanceAggregatedList, error)
	ListFirewalls(context.Context, PageRequest) (*compute.FirewallList, error)
	AggregatedListSubnetworks(context.Context, PageRequest) (*compute.SubnetworkAggregatedList, error)
}

// NewComputeAPI adapts a Compute Engine service to [ComputeAPI].
func NewComputeAPI(service *compute.Service) ComputeAPI {
	return computeService{service: service}
}

type computeService struct {
	service *compute.Service
}

func (c computeService) AggregatedListInstances(ctx context.Context, request PageRequest) (*compute.InstanceAggregatedList, error) {
	return c.service.Instances.AggregatedList(request.Project).MaxResults(request.MaxResults).PageToken(request.PageToken).Context(ctx).Do()
}

func (c computeService) ListFirewalls(ctx context.Context, request PageRequest) (*compute.FirewallList, error) {
	return c.service.Firewalls.List(request.Project).MaxResults(request.MaxResults).PageToken(request.PageToken).Context(ctx).Do()
}

func (c computeService) AggregatedListSubnetworks(ctx context.Context, request PageRequest) (*compute.SubnetworkAggregatedList, error) {
	return c.service.Subnetworks.AggregatedList(request.Project).MaxResults(request.MaxResults).PageToken(request.PageToken).Context(ctx).Do()
}

// listTimeout bounds one page request, so a stalled call fails the poll
// instead of blocking the plugin. It is per page, not per poll, so large
// projects are not cut off.
var listTimeout = time.Minute

// paginate calls fetch under listTimeout until the page token is empty.
func paginate[T any](ctx context.Context, project, what string, fetch func(context.Context, PageRequest) (T, error), next func(T) (string, error)) error {
	token := ""
	seen := map[string]struct{}{}
	for {
		pageContext, cancel := context.WithTimeout(ctx, listTimeout)
		page, err := fetch(pageContext, PageRequest{Project: project, PageToken: token, MaxResults: pageSize})
		cancel()
		if err != nil {
			return fmt.Errorf("list GCP %s in %s: %w", what, project, err)
		}
		token, err = next(page)
		if err != nil {
			return fmt.Errorf("list GCP %s in %s: %w", what, project, err)
		}
		if token == "" {
			return nil
		}
		if _, repeated := seen[token]; repeated {
			return fmt.Errorf("list GCP %s in %s: repeated page token", what, project)
		}
		seen[token] = struct{}{}
	}
}

func capture(ctx context.Context, client ComputeAPI, sourceID, project, region string) (Snapshot, error) {
	instances, err := captureInstances(ctx, client, sourceID, project, region)
	if err != nil {
		return Snapshot{}, err
	}
	firewalls, err := captureFirewalls(ctx, client, sourceID, project)
	if err != nil {
		return Snapshot{}, err
	}
	subnetworks, err := captureSubnetworks(ctx, client, sourceID, project, region)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Instances: instances, Firewalls: firewalls, Subnetworks: subnetworks}, nil
}

func captureInstances(ctx context.Context, client ComputeAPI, sourceID, project, region string) ([]Instance, error) {
	var result []Instance
	err := paginate(ctx, project, "instances", client.AggregatedListInstances, func(page *compute.InstanceAggregatedList) (string, error) {
		if page == nil {
			return "", errors.New("empty response")
		}
		if len(page.Unreachables) > 0 {
			return "", fmt.Errorf("unreachable scopes %v", page.Unreachables)
		}
		for _, scoped := range page.Items {
			for _, value := range scoped.Instances {
				if value == nil {
					continue
				}
				item := normalizeInstance(value)
				if region != "" && zoneRegion(item.Zone) != region {
					continue
				}
				if err := finalizeInstance(sourceID, &item); err != nil {
					return "", err
				}
				result = append(result, item)
			}
		}
		return page.NextPageToken, nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(result, func(left, right Instance) int { return compareNumericIDs(left.ID, right.ID) })
	return result, nil
}

func normalizeInstance(value *compute.Instance) Instance {
	item := Instance{
		ID: strconv.FormatUint(value.Id, 10), Name: value.Name, Zone: lastSegment(value.Zone),
		MachineType: lastSegment(value.MachineType), Status: value.Status,
	}
	if value.Tags != nil {
		item.Tags = uniqueSorted(slices.Clone(value.Tags.Items))
	}
	for _, account := range value.ServiceAccounts {
		if account != nil {
			item.ServiceAccounts = append(item.ServiceAccounts, account.Email)
		}
	}
	item.ServiceAccounts = uniqueSorted(item.ServiceAccounts)
	for _, value := range value.NetworkInterfaces {
		if value == nil {
			continue
		}
		nic := NetworkInterface{Name: value.Name, Network: relativePath(value.Network), Subnetwork: relativePath(value.Subnetwork)}
		nic.Addresses = append(nic.Addresses, value.NetworkIP, value.Ipv6Address)
		for _, access := range slices.Concat(value.AccessConfigs, value.Ipv6AccessConfigs) {
			if access != nil {
				nic.Addresses = append(nic.Addresses, access.NatIP, access.ExternalIpv6)
			}
		}
		nic.Addresses = uniqueSorted(nic.Addresses)
		for _, alias := range slices.Concat(value.AliasIpRanges, value.AliasIpv6Ranges) {
			if alias != nil {
				nic.AliasIPRanges = append(nic.AliasIPRanges, alias.IpCidrRange)
			}
		}
		nic.AliasIPRanges = uniqueSorted(nic.AliasIPRanges)
		item.NetworkInterfaces = append(item.NetworkInterfaces, nic)
	}
	slices.SortFunc(item.NetworkInterfaces, func(left, right NetworkInterface) int { return strings.Compare(left.Name, right.Name) })
	return item
}

func captureFirewalls(ctx context.Context, client ComputeAPI, sourceID, project string) ([]Firewall, error) {
	var result []Firewall
	err := paginate(ctx, project, "firewalls", client.ListFirewalls, func(page *compute.FirewallList) (string, error) {
		if page == nil {
			return "", errors.New("empty response")
		}
		for _, value := range page.Items {
			if value == nil {
				continue
			}
			item := Firewall{
				ID: strconv.FormatUint(value.Id, 10), Name: value.Name, Network: relativePath(value.Network),
				Direction: value.Direction, Priority: value.Priority, Disabled: value.Disabled,
				SourceRanges: uniqueSorted(slices.Clone(value.SourceRanges)), DestinationRanges: uniqueSorted(slices.Clone(value.DestinationRanges)),
				SourceTags: uniqueSorted(slices.Clone(value.SourceTags)), SourceServiceAccounts: uniqueSorted(slices.Clone(value.SourceServiceAccounts)),
				TargetTags: uniqueSorted(slices.Clone(value.TargetTags)), TargetServiceAccounts: uniqueSorted(slices.Clone(value.TargetServiceAccounts)),
			}
			for _, allowed := range value.Allowed {
				if allowed != nil {
					item.Allowed = append(item.Allowed, Permission{Protocol: allowed.IPProtocol, Ports: allowed.Ports})
				}
			}
			for _, denied := range value.Denied {
				if denied != nil {
					item.Denied = append(item.Denied, Permission{Protocol: denied.IPProtocol, Ports: denied.Ports})
				}
			}
			item.Allowed = canonicalPermissions(item.Allowed)
			item.Denied = canonicalPermissions(item.Denied)
			if err := finalizeFirewall(sourceID, &item); err != nil {
				return "", err
			}
			result = append(result, item)
		}
		return page.NextPageToken, nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(result, func(left, right Firewall) int { return compareNumericIDs(left.ID, right.ID) })
	return result, nil
}

func captureSubnetworks(ctx context.Context, client ComputeAPI, sourceID, project, region string) ([]Subnetwork, error) {
	var result []Subnetwork
	err := paginate(ctx, project, "subnetworks", client.AggregatedListSubnetworks, func(page *compute.SubnetworkAggregatedList) (string, error) {
		if page == nil {
			return "", errors.New("empty response")
		}
		if len(page.Unreachables) > 0 {
			return "", fmt.Errorf("unreachable scopes %v", page.Unreachables)
		}
		for _, scoped := range page.Items {
			for _, value := range scoped.Subnetworks {
				if value == nil {
					continue
				}
				item := Subnetwork{
					ID: strconv.FormatUint(value.Id, 10), Name: value.Name, Region: lastSegment(value.Region), Network: relativePath(value.Network),
					IPCIDRRange: value.IpCidrRange, IPv6CIDRRange: value.Ipv6CidrRange, Purpose: value.Purpose, StackType: value.StackType,
				}
				if region != "" && item.Region != region {
					continue
				}
				for _, secondary := range value.SecondaryIpRanges {
					if secondary != nil {
						item.SecondaryRanges = append(item.SecondaryRanges, SecondaryRange{Name: secondary.RangeName, IPCIDRRange: secondary.IpCidrRange})
					}
				}
				slices.SortFunc(item.SecondaryRanges, func(left, right SecondaryRange) int {
					return cmp.Or(strings.Compare(left.Name, right.Name), strings.Compare(left.IPCIDRRange, right.IPCIDRRange))
				})
				if err := finalizeSubnetwork(sourceID, &item); err != nil {
					return "", err
				}
				result = append(result, item)
			}
		}
		return page.NextPageToken, nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(result, func(left, right Subnetwork) int { return compareNumericIDs(left.ID, right.ID) })
	return result, nil
}

func finalizeInstance(sourceID string, item *Instance) error {
	if !validNumericID(item.ID) || strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Zone) == "" {
		return fmt.Errorf("GCP instance %q requires numeric ID, name, and zone", item.Name)
	}
	return finalize(item, sourceID, instancesCollection, item.ID, &item.Revision, &item.EventID)
}

func finalizeFirewall(sourceID string, item *Firewall) error {
	if !validNumericID(item.ID) || strings.TrimSpace(item.Name) == "" {
		return fmt.Errorf("GCP firewall %q requires numeric ID and name", item.Name)
	}
	return finalize(item, sourceID, firewallsCollection, item.ID, &item.Revision, &item.EventID)
}

func finalizeSubnetwork(sourceID string, item *Subnetwork) error {
	if !validNumericID(item.ID) || strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Region) == "" {
		return fmt.Errorf("GCP subnetwork %q requires numeric ID, name, and region", item.Name)
	}
	return finalize(item, sourceID, subnetworksCollection, item.ID, &item.Revision, &item.EventID)
}

func finalize(item any, sourceID, collection, key string, revision, event *string) error {
	value, err := contentRevision(item)
	if err != nil {
		return err
	}
	*revision = value
	*event = eventID(sourceID, collection, key, value, "upsert")
	return nil
}

func contentRevision(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode GCP observation: %w", err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

// relativePath turns a Compute self link into projects/<project>/... form.
func relativePath(url string) string {
	if index := strings.Index(url, "projects/"); index >= 0 {
		return url[index:]
	}
	return url
}

func lastSegment(url string) string {
	return url[strings.LastIndexByte(url, '/')+1:]
}

func compareNumericIDs(left, right string) int {
	return cmp.Or(cmp.Compare(len(left), len(right)), strings.Compare(left, right))
}

func validateClient(client ComputeAPI) error {
	if client == nil {
		return errors.New("GCP Compute client is required")
	}
	return nil
}
