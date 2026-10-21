package agentgateway

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

// The access-log types and functions are unexported until an access-log
// transport calls ingestAccessLog; nothing in the binary produces records yet.
// See https://agent-shield.dev/docs/plugins/agentgateway/.

// accessLogConfig supplies the authorities used for endpoint claims.
// NetworkID defaults to ClusterID.
type accessLogConfig struct {
	ClusterID string
	NetworkID string
	SourceID  string
}

// accessLogRecord is the bounded subset of an agentgateway access log entry
// that AgentShield retains. It deliberately has no fields for credentials,
// headers, bodies, or principal names.
type accessLogRecord struct {
	RequestID     string
	ObservedAt    time.Time
	ClientIP      string
	BackendUID    string
	Method        string
	Route         string
	Operation     string
	ResponseCode  int
	Authenticated bool
}

// normalizeAccessLog maps record to a telemetry event from the client IP to
// the backend Pod. RequestID becomes the event ID when present; otherwise the
// ID is derived from the source ID and record content so retries are stable.
func normalizeAccessLog(config accessLogConfig, record accessLogRecord) (telemetry.Event, error) {
	config.ClusterID = strings.TrimSpace(config.ClusterID)
	config.NetworkID = strings.TrimSpace(config.NetworkID)
	config.SourceID = strings.TrimSpace(config.SourceID)
	if config.ClusterID == "" || config.SourceID == "" {
		return telemetry.Event{}, errors.New("agentgateway access-log normalization requires cluster and source IDs")
	}
	if config.NetworkID == "" {
		config.NetworkID = config.ClusterID
	}
	if record.ObservedAt.IsZero() {
		return telemetry.Event{}, errors.New("agentgateway access log requires its original observation timestamp")
	}
	address, err := netip.ParseAddr(strings.TrimSpace(record.ClientIP))
	if err != nil {
		return telemetry.Event{}, fmt.Errorf("invalid agentgateway client IP: %w", err)
	}
	client, err := graph.NetworkDestinationClaim(config.NetworkID, "ip/"+address.String())
	if err != nil {
		return telemetry.Event{}, err
	}
	backendUID := strings.TrimSpace(record.BackendUID)
	if backendUID == "" {
		return telemetry.Event{}, errors.New("agentgateway access log requires a backend Kubernetes UID")
	}
	method := strings.ToUpper(strings.TrimSpace(record.Method))
	operation := strings.TrimSpace(record.Operation)
	if method == "" || operation == "" || record.ResponseCode < 100 || record.ResponseCode > 599 {
		return telemetry.Event{}, errors.New("agentgateway access log requires method, operation, and valid response code")
	}
	if record.Authenticated {
		operation = "authenticated/" + operation
	}
	event := telemetry.Event{
		PluginID: PluginID, ObservedAt: record.ObservedAt.UTC(), Kind: telemetry.EventKindGatewayRequest, Subject: client,
		Object:    kubernetesplugin.ClaimForUID(config.ClusterID, "v1", "Pod", backendUID),
		Operation: operation, Outcome: accessOutcome(record.ResponseCode), Coverage: "agentgateway-access-log", Count: 1,
		Properties: map[string]string{
			"authenticated": strconv.FormatBool(record.Authenticated), "method": method,
			"response-code": strconv.Itoa(record.ResponseCode), "route": strings.TrimSpace(record.Route),
		},
		RollupProperties: map[string]string{
			"authenticated": strconv.FormatBool(record.Authenticated), "method": method,
			"response-code": strconv.Itoa(record.ResponseCode),
		},
		SourceID: config.SourceID,
	}
	event.EventID = accessLogEventID(config.SourceID, record, event)
	event.EvidenceIDs = []string{event.EventID}
	return event, nil
}

// ingestAccessLog normalizes record and submits it to pipeline, blocking while
// the pipeline queue is full.
func ingestAccessLog(ctx context.Context, pipeline *telemetry.Pipeline, config accessLogConfig, record accessLogRecord) error {
	if pipeline == nil {
		return errors.New("agentgateway telemetry pipeline is required")
	}
	event, err := normalizeAccessLog(config, record)
	if err != nil {
		return err
	}
	return telemetry.IngestWaiting(ctx, pipeline, event)
}

func accessOutcome(statusCode int) string {
	if statusCode >= 400 {
		return "denied"
	}
	return "allowed"
}

func accessLogEventID(sourceID string, record accessLogRecord, event telemetry.Event) string {
	if requestID := strings.TrimSpace(record.RequestID); requestID != "" {
		return "agentgateway:" + sourceID + ":" + requestID
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
	return "agentgateway:" + sourceID + ":sha256:" + hex.EncodeToString(digest[:])
}
