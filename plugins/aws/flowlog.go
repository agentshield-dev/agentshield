package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

const vpcFlowLogFieldCount = 25

var errNoFlowData = errors.New("VPC Flow Log record contains no flow data")

// NormalizeVPCFlowLog maps one version 5 VPC Flow Log line in the 25-field
// custom order documented in https://agent-shield.dev/docs/plugins/aws/ to a telemetry event between
// network-destination claims for the source and destination addresses.
// The event ID digests the source ID and the complete record so Firehose
// redelivery is idempotent. NODATA and SKIPDATA records carry no flow and
// return an error that the Firehose handler skips.
func NormalizeVPCFlowLog(scope ProjectionContext, line string) (telemetry.Event, error) {
	scope.Partition = strings.TrimSpace(scope.Partition)
	scope.Region = strings.TrimSpace(scope.Region)
	scope.SourceID = strings.TrimSpace(scope.SourceID)
	if scope.Partition == "" || scope.Region == "" || scope.SourceID == "" {
		return telemetry.Event{}, errors.New("AWS VPC Flow Log normalization requires partition, region, and source ID")
	}
	fields := strings.Fields(line)
	if len(fields) != vpcFlowLogFieldCount {
		return telemetry.Event{}, fmt.Errorf("AWS VPC Flow Log record has %d fields, want %d", len(fields), vpcFlowLogFieldCount)
	}
	if fields[13] == "NODATA" || fields[13] == "SKIPDATA" {
		return telemetry.Event{}, errNoFlowData
	}
	if fields[0] != "5" || fields[13] != "OK" {
		return telemetry.Event{}, fmt.Errorf("unsupported AWS VPC Flow Log version %q or status %q", fields[0], fields[13])
	}
	if !validAccountID(fields[1]) || !strings.HasPrefix(fields[2], "eni-") || !validAWSComponent(fields[2]) {
		return telemetry.Event{}, errors.New("AWS VPC Flow Log requires valid account and network interface IDs")
	}
	if fields[21] != scope.Region || !strings.HasPrefix(fields[14], "vpc-") || !validAWSComponent(fields[14]) {
		return telemetry.Event{}, errors.New("AWS VPC Flow Log requires the configured region and a valid VPC ID")
	}
	sourceAddress, err := netip.ParseAddr(fields[3])
	if err != nil {
		return telemetry.Event{}, fmt.Errorf("invalid AWS VPC Flow Log source address: %w", err)
	}
	destinationAddress, err := netip.ParseAddr(fields[4])
	if err != nil {
		return telemetry.Event{}, fmt.Errorf("invalid AWS VPC Flow Log destination address: %w", err)
	}
	sourcePort, err := parseFlowUint(fields[5], 16, "source port")
	if err != nil {
		return telemetry.Event{}, err
	}
	destinationPort, err := parseFlowUint(fields[6], 16, "destination port")
	if err != nil {
		return telemetry.Event{}, err
	}
	protocolNumber, err := parseFlowUint(fields[7], 8, "protocol")
	if err != nil {
		return telemetry.Event{}, err
	}
	packets, err := strconv.ParseUint(fields[8], 10, 64)
	if err != nil || packets == 0 {
		return telemetry.Event{}, errors.New("AWS VPC Flow Log packet count must be positive")
	}
	if bytes, err := strconv.ParseUint(fields[9], 10, 64); err != nil || bytes == 0 {
		return telemetry.Event{}, errors.New("AWS VPC Flow Log byte count must be positive")
	}
	start, err := strconv.ParseInt(fields[10], 10, 64)
	if err != nil || start <= 0 {
		return telemetry.Event{}, errors.New("AWS VPC Flow Log start time must be a positive Unix timestamp")
	}
	end, err := strconv.ParseInt(fields[11], 10, 64)
	if err != nil || end < start {
		return telemetry.Event{}, errors.New("AWS VPC Flow Log end time must not precede its start time")
	}
	outcome := ""
	switch fields[12] {
	case "ACCEPT":
		outcome = "allowed"
	case "REJECT":
		outcome = "denied"
	default:
		return telemetry.Event{}, fmt.Errorf("unsupported AWS VPC Flow Log action %q", fields[12])
	}
	direction := strings.ToLower(fields[23])
	if direction != "ingress" && direction != "egress" {
		return telemetry.Event{}, fmt.Errorf("unsupported AWS VPC Flow Log direction %q", fields[23])
	}
	if _, err := parseFlowUint(fields[17], 8, "TCP flags"); err != nil {
		return telemetry.Event{}, err
	}
	if fields[18] != "IPv4" && fields[18] != "IPv6" {
		return telemetry.Event{}, fmt.Errorf("unsupported AWS VPC Flow Log address type %q", fields[18])
	}
	peerAddress := destinationAddress
	packetAddress := fields[20]
	if direction == "ingress" {
		peerAddress = sourceAddress
		packetAddress = fields[19]
	}
	if packetAddress != "-" {
		peerAddress, err = netip.ParseAddr(packetAddress)
		if err != nil {
			return telemetry.Event{}, fmt.Errorf("invalid AWS VPC Flow Log packet address: %w", err)
		}
	}
	local := resourceClaim(scope, fields[1], "network-interface", fields[2])
	peer, err := graph.NetworkDestinationClaim(
		"aws/"+scope.Partition+"/"+fields[1]+"/"+scope.Region+"/"+fields[14],
		"ip/"+peerAddress.String(),
	)
	if err != nil {
		return telemetry.Event{}, err
	}
	subject, object := local, peer
	if direction == "ingress" {
		subject, object = peer, local
	}
	properties := map[string]string{
		"protocol":         flowProtocol(protocolNumber),
		"source-port":      strconv.FormatUint(sourcePort, 10),
		"destination-port": strconv.FormatUint(destinationPort, 10),
	}
	if fields[24] != "-" {
		if _, err := parseFlowUint(fields[24], 16, "traffic path"); err != nil {
			return telemetry.Event{}, err
		}
		properties["traffic-path"] = fields[24]
	}
	canonical := strings.Join(fields, " ")
	digest := sha256.Sum256([]byte(scope.SourceID + "\x00" + canonical))
	eventID := "aws-vpc-flow:" + scope.SourceID + ":sha256:" + hex.EncodeToString(digest[:])
	return telemetry.Event{
		EventID: eventID, PluginID: PluginID, SourceID: scope.SourceID,
		ObservedAt: time.Unix(end, 0).UTC(), Kind: "network-flow", Subject: subject, Object: object,
		Operation: direction, Outcome: outcome, Coverage: "aws-vpc-flow-log", Count: packets,
		Properties: properties, RollupProperties: flowRollupProperties(properties), EvidenceIDs: []string{eventID},
	}, nil
}

func flowRollupProperties(properties map[string]string) map[string]string {
	result := map[string]string{
		"protocol": properties["protocol"], "destination-port": properties["destination-port"],
	}
	if value, found := properties["traffic-path"]; found {
		result["traffic-path"] = value
	}
	return result
}

func parseFlowUint(value string, bitSize int, name string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, bitSize)
	if err != nil {
		return 0, fmt.Errorf("AWS VPC Flow Log %s must be an unsigned integer", name)
	}
	return parsed, nil
}

func flowProtocol(number uint64) string {
	switch number {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return strconv.FormatUint(number, 10)
	}
}
