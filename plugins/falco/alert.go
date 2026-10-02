package falco

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
)

const (
	// ServiceName is the OTLP resource service.name the collector assigns to Falco alert logs.
	ServiceName = "falco"

	OperationSpawnShell = "spawn-shell"
	OutcomeObserved     = "observed"
	Coverage            = "falco-runtime-alert"

	podUIDField      = "k8s.pod.uid"
	containerIDField = "container.id"
)

type alertMapper struct {
	clusterID  string
	shellRules []string
}

// alert is the subset of a Falco json_output alert this mapper reads.
type alert struct {
	Time         string         `json:"time"`
	Rule         string         `json:"rule"`
	Priority     string         `json:"priority"`
	Source       string         `json:"source"`
	OutputFields map[string]any `json:"output_fields"`
}

func (mapper alertMapper) Match(record telemetry.LogRecord) bool {
	service, _ := record.ResourceAttribute("service.name")
	return service == ServiceName
}

func (mapper alertMapper) Map(_ context.Context, record telemetry.LogRecord) ([]telemetry.Event, error) {
	canonical, err := canonicalBody(record.Body)
	if err != nil {
		return nil, err
	}
	var decoded alert
	if err := json.Unmarshal(canonical, &decoded); err != nil {
		return nil, errors.New("Falco alert body is not a JSON alert object")
	}
	// Errors name fields, never payload values.
	if strings.TrimSpace(decoded.Source) == "" {
		return nil, errors.New("Falco alert requires a source")
	}
	// Alerts from other rules are normal Falco output, not malformed records.
	if !slices.Contains(mapper.shellRules, decoded.Rule) {
		return nil, telemetry.ErrSkipRecord
	}
	if decoded.Source != "syscall" {
		return nil, errors.New("Falco shell alert source is not syscall")
	}
	observedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(decoded.Time))
	if err != nil {
		return nil, errors.New("Falco alert requires its RFC 3339 event time")
	}
	podUID := outputField(decoded, podUIDField)
	if podUID == "" {
		return nil, fmt.Errorf("Falco alert requires output field %q", podUIDField)
	}
	shell, err := graph.ProcessClassClaim(mapper.clusterID, graph.ProcessClassShell)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	eventID := "falco/" + hex.EncodeToString(digest[:])
	properties := map[string]string{"falco/rule": decoded.Rule}
	if priority := strings.TrimSpace(decoded.Priority); priority != "" {
		properties["falco/priority"] = priority
	}
	if containerID := outputField(decoded, containerIDField); containerID != "" {
		properties["container-id"] = containerID
	}
	return []telemetry.Event{{
		EventID: eventID, ObservedAt: observedAt.UTC(), Kind: telemetry.EventKindProcessExec,
		Subject: kubernetesplugin.ClaimForUID(mapper.clusterID, "v1", "Pod", podUID), Object: shell,
		Operation: OperationSpawnShell, Outcome: OutcomeObserved, Coverage: Coverage, Count: 1,
		Properties: properties, EvidenceIDs: []string{eventID},
	}}, nil
}

// canonicalBody re-encodes the alert with sorted keys and exact numbers so a
// retried record yields the same event ID whether the collector forwarded the
// raw JSON line or a parsed map.
func canonicalBody(body any) ([]byte, error) {
	var value any
	switch typed := body.(type) {
	case string:
		decoder := json.NewDecoder(strings.NewReader(typed))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil || decoder.More() {
			return nil, errors.New("Falco alert body is not a JSON alert object")
		}
	case map[string]any:
		value = typed
	default:
		return nil, errors.New("Falco alert body must be a JSON string or map")
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errors.New("Falco alert body is not a JSON alert object")
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, errors.New("encode Falco alert body")
	}
	return bytes.TrimSpace(encoded.Bytes()), nil
}

func outputField(decoded alert, name string) string {
	value, ok := decoded.OutputFields[name].(string)
	if !ok {
		return ""
	}
	value = strings.TrimSpace(value)
	// Falco renders unavailable fields as "<NA>".
	if value == "<NA>" {
		return ""
	}
	return value
}
