package istio

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
)

const (
	activeProbeKindAttribute              = "agentshield.telemetry.kind"
	activeProbeEventIDAttribute           = "agentshield.event.id"
	activeProbeEvidenceIDAttribute        = "agentshield.evidence.id"
	activeProbeSubjectAPIVersionAttribute = "agentshield.subject.k8s.api_version"
	activeProbeSubjectKindAttribute       = "agentshield.subject.k8s.kind"
	activeProbeSubjectUIDAttribute        = "agentshield.subject.k8s.uid"
	activeProbeSubjectNamespaceAttribute  = "agentshield.subject.k8s.namespace"
	activeProbeSubjectNameAttribute       = "agentshield.subject.k8s.name"
	activeProbeObjectAPIVersionAttribute  = "agentshield.object.k8s.api_version"
	activeProbeObjectKindAttribute        = "agentshield.object.k8s.kind"
	activeProbeObjectUIDAttribute         = "agentshield.object.k8s.uid"
	activeProbeObjectNamespaceAttribute   = "agentshield.object.k8s.namespace"
	activeProbeObjectNameAttribute        = "agentshield.object.k8s.name"
	activeProbeObjectAuthorityAttribute   = "agentshield.object.authority"
	activeProbeOperationAttribute         = "agentshield.operation"
	activeProbeOutcomeAttribute           = "agentshield.outcome"
	activeProbeCoverageAttribute          = "agentshield.coverage"
	activeProbeCountAttribute             = "agentshield.count"
	activeProbeStatusesAttribute          = "agentshield.probe.http_statuses"
	activeProbeExpectedStatusAttribute    = "agentshield.probe.expected_status"
	activeProbeResultAttribute            = "agentshield.probe.result"
)

type activeProbeMapper struct {
	clusterID string
	resolver  *telemetryObjectResolver
}

type telemetryObjectResolver struct {
	mu        sync.RWMutex
	clusterID string
	claims    map[string]graph.IdentityClaim
}

func newTelemetryObjectResolver(clusterID string) *telemetryObjectResolver {
	return &telemetryObjectResolver{clusterID: clusterID, claims: make(map[string]graph.IdentityClaim)}
}

func (resolver *telemetryObjectResolver) Replace(objects map[string]ObservedObject) {
	claims := make(map[string]graph.IdentityClaim)
	for _, observation := range objects {
		item := observation.Object
		if item == nil || string(item.GetUID()) == "" {
			continue
		}
		claims[telemetryObjectKey(item.GetKind(), item.GetNamespace(), item.GetName())] = kubernetesplugin.ClaimFor(resolver.clusterID, item)
	}
	resolver.mu.Lock()
	resolver.claims = claims
	resolver.mu.Unlock()
}

func (resolver *telemetryObjectResolver) Resolve(kind, namespace, name string) (graph.IdentityClaim, bool) {
	if resolver == nil {
		return graph.IdentityClaim{}, false
	}
	resolver.mu.RLock()
	defer resolver.mu.RUnlock()
	claim, found := resolver.claims[telemetryObjectKey(kind, namespace, name)]
	return claim, found
}

func telemetryObjectKey(kind, namespace, name string) string {
	return strings.ToLower(strings.TrimSpace(kind) + "/" + strings.TrimSpace(namespace) + "/" + strings.TrimSpace(name))
}

// ActiveProbeObservation is the typed form of an active-probe record with
// UID-identified endpoints, used to build fixtures and replay records.
type ActiveProbeObservation struct {
	EventID           string
	ObservedAt        time.Time
	SubjectAPIVersion string
	SubjectKind       string
	SubjectUID        string
	ObjectAPIVersion  string
	ObjectKind        string
	ObjectUID         string
	Operation         string
	Outcome           string
	Coverage          string
	Count             uint64
	HTTPStatuses      string
	Result            string
}

// ActiveProbeLogRecord encodes observation as the OTLP log record the
// active-probe mapper accepts.
func ActiveProbeLogRecord(observation ActiveProbeObservation) telemetry.LogRecord {
	return telemetry.LogRecord{
		Timestamp: observation.ObservedAt,
		Attributes: map[string]any{
			activeProbeKindAttribute: "active-probe", activeProbeEventIDAttribute: observation.EventID,
			activeProbeEvidenceIDAttribute:        observation.EventID,
			activeProbeSubjectAPIVersionAttribute: observation.SubjectAPIVersion,
			activeProbeSubjectKindAttribute:       observation.SubjectKind, activeProbeSubjectUIDAttribute: observation.SubjectUID,
			activeProbeObjectAPIVersionAttribute: observation.ObjectAPIVersion,
			activeProbeObjectKindAttribute:       observation.ObjectKind, activeProbeObjectUIDAttribute: observation.ObjectUID,
			activeProbeOperationAttribute: observation.Operation, activeProbeOutcomeAttribute: observation.Outcome,
			activeProbeCoverageAttribute: observation.Coverage, activeProbeCountAttribute: int64(observation.Count),
			activeProbeStatusesAttribute: observation.HTTPStatuses, activeProbeResultAttribute: observation.Result,
		},
	}
}

func (mapper activeProbeMapper) Match(record telemetry.LogRecord) bool {
	kind, _ := record.Attribute(activeProbeKindAttribute)
	return kind == "active-probe"
}

func (mapper activeProbeMapper) Map(_ context.Context, record telemetry.LogRecord) ([]telemetry.Event, error) {
	values := []struct {
		name  string
		value string
	}{
		{activeProbeEventIDAttribute, stringAttribute(record, activeProbeEventIDAttribute)},
		{activeProbeSubjectAPIVersionAttribute, stringAttribute(record, activeProbeSubjectAPIVersionAttribute)},
		{activeProbeSubjectKindAttribute, stringAttribute(record, activeProbeSubjectKindAttribute)},
		{activeProbeObjectAPIVersionAttribute, stringAttribute(record, activeProbeObjectAPIVersionAttribute)},
		{activeProbeObjectKindAttribute, stringAttribute(record, activeProbeObjectKindAttribute)},
		{activeProbeOperationAttribute, stringAttribute(record, activeProbeOperationAttribute)},
		{activeProbeCoverageAttribute, stringAttribute(record, activeProbeCoverageAttribute)},
	}
	for _, item := range values {
		if strings.TrimSpace(item.value) == "" {
			return nil, fmt.Errorf("Istio active probe requires OTLP attribute %q", item.name)
		}
	}
	count, err := countAttribute(record, activeProbeCountAttribute)
	if err != nil {
		return nil, err
	}
	status := stringAttribute(record, activeProbeStatusesAttribute)
	outcome := stringAttribute(record, activeProbeOutcomeAttribute)
	if outcome == "" {
		outcome = "allowed"
		if status == "403" {
			outcome = "denied"
		}
	}
	result := stringAttribute(record, activeProbeResultAttribute)
	if result == "" {
		result = "observed"
		if expected := stringAttribute(record, activeProbeExpectedStatusAttribute); expected != "" && expected == status {
			result = "pass"
		}
	}
	evidenceID := stringAttribute(record, activeProbeEvidenceIDAttribute)
	if evidenceID == "" {
		evidenceID = values[0].value
	}
	subject, err := mapper.resolveClaim(record, true, values[1].value, values[2].value)
	if err != nil {
		return nil, err
	}
	object, err := mapper.resolveClaim(record, false, values[3].value, values[4].value)
	if err != nil {
		return nil, err
	}
	return []telemetry.Event{{
		EventID: values[0].value, ObservedAt: record.Timestamp, Kind: telemetry.EventKindActiveProbe,
		Subject: subject, Object: object,
		Operation: values[5].value, Outcome: outcome, Coverage: values[6].value, Count: count,
		Properties: map[string]string{
			"probe/http-statuses": status,
			"probe/result":        result,
		},
		RollupProperties: map[string]string{"probe/http-statuses": status, "probe/result": result},
		EvidenceIDs:      []string{evidenceID},
	}}, nil
}

func (mapper activeProbeMapper) resolveClaim(record telemetry.LogRecord, subject bool, apiVersion, kind string) (graph.IdentityClaim, error) {
	prefix := "agentshield.object.k8s."
	if subject {
		prefix = "agentshield.subject.k8s."
	}
	if uid := stringAttribute(record, prefix+"uid"); uid != "" && uid != "-" {
		return kubernetesplugin.ClaimForUID(mapper.clusterID, apiVersion, kind, uid), nil
	}
	namespace := stringAttribute(record, prefix+"namespace")
	name := stringAttribute(record, prefix+"name")
	if claim, found := mapper.resolver.Resolve(kind, namespace, name); found {
		return claim, nil
	}
	if !subject && strings.EqualFold(kind, "Service") {
		if authorityNamespace, authorityName, ok := serviceIdentityFromAuthority(stringAttribute(record, activeProbeObjectAuthorityAttribute)); ok {
			if claim, found := mapper.resolver.Resolve(kind, authorityNamespace, authorityName); found {
				return claim, nil
			}
		}
	}
	return graph.IdentityClaim{}, fmt.Errorf("Istio active probe could not resolve %s %s/%s", kind, namespace, name)
}

func serviceIdentityFromAuthority(authority string) (string, string, bool) {
	authority = strings.ToLower(strings.TrimSpace(authority))
	host := authority
	if candidate, port, found := strings.Cut(authority, ":"); found {
		if candidate == "" || port == "" || strings.Contains(port, ":") {
			return "", "", false
		}
		parsed, err := strconv.ParseUint(port, 10, 16)
		if err != nil || parsed == 0 {
			return "", "", false
		}
		host = candidate
	}
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	if len(labels) != 5 || labels[2] != "svc" || labels[3] != "cluster" || labels[4] != "local" || !validDNSLabel(labels[0]) || !validDNSLabel(labels[1]) {
		return "", "", false
	}
	return labels[1], labels[0], true
}

func stringAttribute(record telemetry.LogRecord, name string) string {
	value, found := record.Attribute(name)
	if !found || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func countAttribute(record telemetry.LogRecord, name string) (uint64, error) {
	value, found := record.Attribute(name)
	if !found {
		return 1, nil
	}
	switch typed := value.(type) {
	case int64:
		if typed > 0 {
			return uint64(typed), nil
		}
	case string:
		parsed, err := strconv.ParseUint(typed, 10, 64)
		if err == nil && parsed > 0 {
			return parsed, nil
		}
	}
	return 0, errors.New("Istio active probe count must be a positive integer")
}
