package cilium

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
)

// The Hubble flow types and functions are unexported until a Hubble Relay
// transport calls ingestHubbleFlow; nothing in the binary produces flows yet.
// See https://agent-shield.dev/docs/plugins/cilium/.

// hubbleConfig supplies the authorities used for flow endpoint claims.
// NetworkID defaults to ClusterID.
type hubbleConfig struct {
	ClusterID string
	NetworkID string
	SourceID  string
}

// hubbleFlow is the bounded L3/L4 subset of a Hubble flow that AgentShield
// retains. FlowID, when present, is the retry-stable event ID.
type hubbleFlow struct {
	FlowID      string
	ObservedAt  time.Time
	Source      hubbleEndpoint
	Destination hubbleEndpoint
	Verdict     string
	Direction   string
	Protocol    string
	SourcePort  uint16
	DestPort    uint16
}

// hubbleEndpoint identifies a flow endpoint by Pod UID when Hubble resolved
// one, otherwise by IP address as a network destination.
type hubbleEndpoint struct {
	KubernetesUID string
	IP            string
}

// missingIdentityError reports a flow endpoint with neither a Kubernetes UID
// nor an IP address. Callers can count these separately from malformed
// flows.
type missingIdentityError struct {
	Endpoint string
}

// Error implements error.
func (err *missingIdentityError) Error() string {
	return "Hubble flow is missing " + err.Endpoint + " endpoint identity"
}

// normalizeHubbleFlow maps one flow to a telemetry event. It requires the
// original observation timestamp and accepts only TCP, UDP, SCTP, ICMP, and
// ICMPv6; labels, payloads, and L7 fields are never retained. Without a
// provider flow ID, the event ID is derived from the source ID and flow
// content.
func normalizeHubbleFlow(config hubbleConfig, flow hubbleFlow) (telemetry.Event, error) {
	config.ClusterID = strings.TrimSpace(config.ClusterID)
	config.NetworkID = strings.TrimSpace(config.NetworkID)
	config.SourceID = strings.TrimSpace(config.SourceID)
	if config.ClusterID == "" || config.SourceID == "" {
		return telemetry.Event{}, errors.New("Hubble normalization requires cluster and source IDs")
	}
	if config.NetworkID == "" {
		config.NetworkID = config.ClusterID
	}
	if flow.ObservedAt.IsZero() {
		return telemetry.Event{}, errors.New("Hubble flow requires its original observation timestamp")
	}
	subject, err := hubbleEndpointClaim(config, "source", flow.Source)
	if err != nil {
		return telemetry.Event{}, err
	}
	object, err := hubbleEndpointClaim(config, "destination", flow.Destination)
	if err != nil {
		return telemetry.Event{}, err
	}
	direction := strings.ToLower(strings.TrimSpace(flow.Direction))
	if direction != "ingress" && direction != "egress" && direction != "unknown" {
		return telemetry.Event{}, fmt.Errorf("unsupported Hubble traffic direction %q", flow.Direction)
	}
	verdict := strings.ToLower(strings.TrimSpace(flow.Verdict))
	if verdict == "" {
		return telemetry.Event{}, errors.New("Hubble flow requires a verdict")
	}
	protocol := strings.ToUpper(strings.TrimSpace(flow.Protocol))
	switch protocol {
	case "TCP", "UDP", "SCTP", "ICMP", "ICMPV6":
	default:
		return telemetry.Event{}, fmt.Errorf("unsupported Hubble transport protocol %q", flow.Protocol)
	}
	properties := map[string]string{"protocol": strings.ToLower(protocol)}
	destinationIPClass := telemetry.DestinationIPClassUnknown
	if destinationIP := strings.TrimSpace(flow.Destination.IP); destinationIP != "" {
		destinationIPClass, err = telemetry.ClassifyDestinationIP(destinationIP)
		if err != nil {
			return telemetry.Event{}, fmt.Errorf("invalid Hubble destination IP: %w", err)
		}
	}
	properties["destination-ip-class"] = destinationIPClass
	if flow.SourcePort != 0 {
		properties["source-port"] = strconv.FormatUint(uint64(flow.SourcePort), 10)
	}
	if flow.DestPort != 0 {
		properties["destination-port"] = strconv.FormatUint(uint64(flow.DestPort), 10)
	}
	event := telemetry.Event{
		PluginID: PluginID, ObservedAt: flow.ObservedAt.UTC(), Kind: telemetry.EventKindNetworkFlow, Subject: subject, Object: object,
		Operation: direction, Outcome: verdict, Coverage: "hubble-flow",
		Properties: properties, RollupProperties: selectedProperties(properties, "protocol", "destination-port", "destination-ip-class"), SourceID: config.SourceID, Count: 1,
	}
	event.EventID = hubbleEventID(config.SourceID, flow, event)
	event.EvidenceIDs = []string{event.EventID}
	return event, nil
}

func selectedProperties(properties map[string]string, keys ...string) map[string]string {
	result := make(map[string]string, len(keys))
	for _, key := range keys {
		if value, found := properties[key]; found {
			result[key] = value
		}
	}
	return result
}

// ingestHubbleFlow normalizes flow and submits it to pipeline, blocking while
// the pipeline queue is full.
func ingestHubbleFlow(ctx context.Context, pipeline *telemetry.Pipeline, config hubbleConfig, flow hubbleFlow) error {
	if pipeline == nil {
		return errors.New("Hubble telemetry pipeline is required")
	}
	event, err := normalizeHubbleFlow(config, flow)
	if err != nil {
		return err
	}
	return telemetry.IngestWaiting(ctx, pipeline, event)
}

func hubbleEndpointClaim(config hubbleConfig, endpointName string, endpoint hubbleEndpoint) (graph.IdentityClaim, error) {
	if rawIP := strings.TrimSpace(endpoint.IP); rawIP != "" {
		if _, err := netip.ParseAddr(rawIP); err != nil {
			return graph.IdentityClaim{}, fmt.Errorf("invalid Hubble %s endpoint IP: %w", endpointName, err)
		}
	}
	if uid := strings.TrimSpace(endpoint.KubernetesUID); uid != "" {
		return kubernetesplugin.ClaimForUID(config.ClusterID, "v1", "Pod", uid), nil
	}
	if rawIP := strings.TrimSpace(endpoint.IP); rawIP != "" {
		address, err := netip.ParseAddr(rawIP)
		if err != nil {
			return graph.IdentityClaim{}, fmt.Errorf("invalid Hubble %s endpoint IP: %w", endpointName, err)
		}
		return graph.NetworkDestinationClaim(config.NetworkID, "ip/"+address.String())
	}
	return graph.IdentityClaim{}, &missingIdentityError{Endpoint: endpointName}
}

func hubbleEventID(sourceID string, flow hubbleFlow, event telemetry.Event) string {
	if flowID := strings.TrimSpace(flow.FlowID); flowID != "" {
		return "hubble:" + sourceID + ":" + flowID
	}
	stable := struct {
		ObservedAt time.Time
		Subject    graph.IdentityClaim
		Object     graph.IdentityClaim
		Operation  string
		Outcome    string
		Properties map[string]string
	}{event.ObservedAt, event.Subject, event.Object, event.Operation, event.Outcome, event.Properties}
	encoded, _ := json.Marshal(stable)
	digest := sha256.Sum256(encoded)
	return "hubble:" + sourceID + ":sha256:" + hex.EncodeToString(digest[:])
}
