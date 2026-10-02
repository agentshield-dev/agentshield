package telemetry

import "github.com/agentshield-dev/agentshield/pkg/graph"

// Event kinds emitted by in-tree telemetry mappers.
const (
	EventKindNetworkFlow    = "network-flow"
	EventKindGatewayRequest = "gateway-request"
	EventKindActiveProbe    = "active-probe"
	EventKindProcessExec    = "process-exec"
)

// EventKindDescription documents an event kind's operation and outcome
// vocabulary. It feeds generated detector-rule documentation.
type EventKindDescription struct {
	Kind               string
	Description        string
	Operation          string
	Outcome            string
	DestinationIPClass bool
	// Lease is the predicate of the leased relationship that rollups of this kind
	// project between subject and object; empty projects none. communicates-with
	// also exposes the object's network role to detection.
	Lease graph.Predicate
}

// EventKinds returns descriptions of every in-tree event kind.
func EventKinds() []EventKindDescription {
	return []EventKindDescription{
		{
			Kind: EventKindActiveProbe, Description: "An HTTP request observed between two workloads, such as a service mesh (Istio waypoint) access log or a synthetic probe.",
			Operation: "the HTTP method and path, including any query string, such as `GET /v1/items?page=2`", Outcome: "`denied` when the request was rejected by authorization (HTTP 403), otherwise `allowed`",
			Lease: graph.PredicateCommunicates,
		},
		{
			Kind: EventKindGatewayRequest, Description: "A request received by an API gateway from a client address.",
			Operation: "the gateway route operation, prefixed with `authenticated/` for authenticated requests", Outcome: "`allowed` (status below 400) or `denied`",
			Lease: graph.PredicateCommunicates,
		},
		{
			Kind: EventKindNetworkFlow, Description: "An observed L3/L4 network flow from the subject endpoint to the object endpoint.",
			Operation: "flow direction relative to the observed endpoint: `ingress`, `egress`, or `unknown`", Outcome: "lowercase datapath verdict, such as `forwarded`, `dropped`, `error`, or `audit`",
			DestinationIPClass: true, Lease: graph.PredicateCommunicates,
		},
		{
			Kind: EventKindProcessExec, Description: "A runtime-security sensor observed the subject workload start a process of the object process class.",
			Operation: "`spawn-shell` when an interactive shell started", Outcome: "`observed`; the sensor detects but does not block",
			Lease: graph.PredicateExecutes,
		},
	}
}

// LeasePredicate returns the leased relationship predicate for rollups of kind.
// Unregistered kinds retain the historical communicates-with lease.
func LeasePredicate(kind string) graph.Predicate {
	description, found := lookupEventKind(kind)
	if !found {
		return graph.PredicateCommunicates
	}
	return description.Lease
}

// IsCommunication reports whether kind records subject-to-object communication.
func IsCommunication(kind string) bool {
	return LeasePredicate(kind) == graph.PredicateCommunicates
}

// leaseRuleIDs are the immutable rule IDs of rollup-projected lease relationships.
var leaseRuleIDs = map[graph.Predicate]string{
	graph.PredicateCommunicates: "telemetry.communication-edge-lease",
	graph.PredicateExecutes:     "telemetry.process-execution-lease",
}

func lookupEventKind(kind string) (EventKindDescription, bool) {
	for _, description := range EventKinds() {
		if description.Kind == kind {
			return description, true
		}
	}
	return EventKindDescription{}, false
}
