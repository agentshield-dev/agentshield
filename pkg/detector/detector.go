package detector

import (
	"strconv"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

// Risk orders signal severity. Reasoning promotes only signals of
// [RiskMedium] or higher.
type Risk string

// Risk levels. These values appear in stored rules and signals.
const (
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

// Rank orders risks from 1 (low) to 4 (critical). Unknown values rank as low.
func (risk Risk) Rank() int {
	switch risk {
	case RiskCritical:
		return 4
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	default:
		return 1
	}
}

// TimeWindow is an inclusive observation interval.
type TimeWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// InvestigationSignal asks reasoning to investigate the anchored resources
// within Window. ID is a content digest, so the same input and rule produce
// the same signal across retries. Rule fields are set only for CEL rule
// signals.
type InvestigationSignal struct {
	ID            string     `json:"id"`
	Risk          Risk       `json:"risk"`
	Reasons       []string   `json:"reasons"`
	AnchorIDs     []string   `json:"anchorIds"`
	Window        TimeWindow `json:"window"`
	RuleID        string     `json:"ruleId,omitempty"`
	RuleRevision  uint64     `json:"ruleRevision,omitempty"`
	RulesetDigest string     `json:"rulesetDigest,omitempty"`
	// RuleMode is RuleModeShadow for signals from unreviewed workload rules, which are recorded but never investigated.
	RuleMode RuleMode `json:"ruleMode,omitempty"`
}

// Config tunes the built-in novelty detector.
//
// Built-in telemetry novelty scores 1 for a new (kind, endpoints, operation,
// outcome) combination, adds 1 when the endpoint pair itself is new, and adds
// the destination role's SensitiveRoleWeights entry. Topology signals use
// fixed scores: 3 for a changed security envelope or other graph change, 4 for
// new external exposure, removed security semantics, or lost governance.
// Scores map to risk as 6+ critical, 4-5 high, 3 medium, and below 3 low.
//
// With the defaults, a new operation between known endpoints (score 1) is
// dropped, a new pair to an ordinary destination (2) is a low-risk signal that
// can inform but never promote a finding, and novelty toward a control-plane
// API, identity provider, or secrets store (4 or more) is high risk. This keeps
// routine churn below the model-call threshold while still reaching sensitive
// destinations on first contact.
type Config struct {
	// Window is the signal half-width for built-in signals and rules that do not set windowSeconds.
	Window time.Duration
	// SensitiveRoleWeights add to the score of novel communication and telemetry
	// toward destinations with the given network/role.
	SensitiveRoleWeights map[string]int
	// ExternalDestinationWeight adds to the score of a new communication path to a public destination.
	ExternalDestinationWeight int
	// SensitiveResourceKinds maps resource kinds whose creation grants privilege or intercepts
	// admission to the reason recorded on the resulting signal.
	SensitiveResourceKinds map[string]string
	// MinimumScore drops built-in signals below this score. Scores of 3 or more are medium risk
	// and eligible for agentic investigation; 2 is low risk and recorded only. Values below 1
	// are treated as 1.
	MinimumScore int
}

// DefaultConfig returns a five-minute window, weights for sensitive roles, and
// a minimum score of 2.
func DefaultConfig() Config {
	return Config{
		Window: 5 * time.Minute,
		SensitiveRoleWeights: map[string]int{
			graph.NetworkRoleControlPlaneAPI: 3,
		},
		ExternalDestinationWeight: 1,
		SensitiveResourceKinds: map[string]string{
			"kubernetes/clusterrolebinding":             "rbac_binding",
			"kubernetes/rolebinding":                    "rbac_binding",
			"kubernetes/mutatingwebhookconfiguration":   "admission_webhook",
			"kubernetes/validatingwebhookconfiguration": "admission_webhook",
		},
		MinimumScore: 2,
	}
}

func normalizedConfig(config Config) Config {
	if config.Window <= 0 {
		config.Window = DefaultConfig().Window
	}
	if config.MinimumScore < 1 {
		config.MinimumScore = 1
	}
	return config
}

func eventKey(parts ...string) string {
	var key strings.Builder
	for _, part := range parts {
		key.WriteString(strconv.Itoa(len(part)))
		key.WriteByte(':')
		key.WriteString(part)
	}
	return key.String()
}

func resourcesByID(snapshot graph.Snapshot) map[string]graph.Resource {
	result := make(map[string]graph.Resource, len(snapshot.Resources))
	for _, resource := range snapshot.Resources {
		result[resource.ID] = resource
	}
	return result
}

func relationshipKey(relationship graph.Relationship) string {
	return strings.Join([]string{relationship.SubjectID, string(relationship.Predicate), relationship.ObjectID, relationship.Qualifier}, "\x00")
}

func telemetryFingerprint(event graph.TelemetryEvent) string {
	return strings.Join([]string{event.Kind, event.SubjectID, event.ObjectID, event.Operation, event.Outcome}, "\x00")
}

func telemetryTime(event graph.TelemetryEvent) (time.Time, bool) {
	observedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(event.Properties["telemetry/first-seen"]))
	return observedAt.UTC(), err == nil
}

func latestTelemetryTime(snapshot graph.Snapshot) time.Time {
	var latest time.Time
	for _, event := range snapshot.Telemetry {
		if observedAt, ok := telemetryTime(event); ok && observedAt.After(latest) {
			latest = observedAt
		}
	}
	return latest
}
