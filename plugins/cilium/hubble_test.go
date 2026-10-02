package cilium

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
	kubernetesplugin "github.com/agentshield-dev/agentshield/plugins/kubernetes"
)

func TestNormalizeHubbleFlow(t *testing.T) {
	observedAt := time.Date(2026, 10, 4, 12, 30, 0, 0, time.FixedZone("offset", 3600))
	flow := hubbleFlow{
		FlowID: "flow-7", ObservedAt: observedAt,
		Source: hubbleEndpoint{KubernetesUID: "POD-UID"}, Destination: hubbleEndpoint{IP: "2001:0db8::1"},
		Verdict: "FORWARDED", Direction: "EGRESS", Protocol: "TCP", SourcePort: 43210, DestPort: 443,
	}
	event, err := normalizeHubbleFlow(hubbleConfig{ClusterID: "cluster-a", SourceID: "hubble-a"}, flow)
	if err != nil {
		t.Fatal(err)
	}
	if event.EventID != "hubble:hubble-a:flow-7" || !event.ObservedAt.Equal(observedAt) || event.ObservedAt.Location() != time.UTC {
		t.Fatalf("event identity/timestamp = %q %v", event.EventID, event.ObservedAt)
	}
	if event.Subject.ImmutableKey != "v1/pod/pod-uid" || event.Object.ImmutableKey != "ip/2001:db8::1" {
		t.Fatalf("endpoint claims = %#v %#v", event.Subject, event.Object)
	}
	wantProperties := map[string]string{"protocol": "tcp", "source-port": "43210", "destination-port": "443", "destination-ip-class": "special"}
	wantRollupProperties := map[string]string{"protocol": "tcp", "destination-port": "443", "destination-ip-class": "special"}
	if event.Operation != "egress" || event.Outcome != "forwarded" || event.Coverage != "hubble-flow" || !reflect.DeepEqual(event.Properties, wantProperties) || !reflect.DeepEqual(event.RollupProperties, wantRollupProperties) {
		t.Fatalf("normalized event = %#v", event)
	}
}

func TestNormalizeHubbleFlowClassifiesPrivateIPv4WithoutRetainingAddress(t *testing.T) {
	for _, test := range []struct {
		ip   string
		want string
	}{
		{ip: "10.1.2.3", want: "private"},
		{ip: "172.16.2.3", want: "private"},
		{ip: "172.31.2.3", want: "private"},
		{ip: "192.168.2.3", want: "private"},
		{ip: "172.32.2.3", want: "public"},
		{ip: "8.8.8.8", want: "public"},
		{ip: "100.64.1.2", want: "special"},
		{ip: "2001:db8::1", want: "special"},
	} {
		t.Run(test.ip, func(t *testing.T) {
			flow := hubbleFlow{
				ObservedAt: time.Date(2026, 10, 4, 12, 30, 0, 0, time.UTC),
				Source:     hubbleEndpoint{KubernetesUID: "source"}, Destination: hubbleEndpoint{IP: test.ip},
				Verdict: "FORWARDED", Direction: "EGRESS", Protocol: "TCP",
			}
			event, err := normalizeHubbleFlow(hubbleConfig{ClusterID: "cluster-a", SourceID: "hubble-a"}, flow)
			if err != nil {
				t.Fatal(err)
			}
			got := event.Properties["destination-ip-class"]
			if got != test.want {
				t.Fatalf("destination-ip-class=%q, want %q", got, test.want)
			}
			if _, exists := event.Properties["destination-ip"]; exists {
				t.Fatal("normalized telemetry retained the raw destination IP")
			}
		})
	}
}

func TestNormalizeHubbleFlowStableRetryID(t *testing.T) {
	flow := hubbleFlow{
		ObservedAt: time.Date(2026, 10, 4, 12, 30, 0, 0, time.UTC),
		Source:     hubbleEndpoint{KubernetesUID: "source"}, Destination: hubbleEndpoint{IP: "10.0.0.2"},
		Verdict: "DROPPED", Direction: "EGRESS", Protocol: "UDP", DestPort: 53,
	}
	first, err := normalizeHubbleFlow(hubbleConfig{ClusterID: "cluster-a", SourceID: "hubble-a"}, flow)
	if err != nil {
		t.Fatal(err)
	}
	second, err := normalizeHubbleFlow(hubbleConfig{ClusterID: "cluster-a", SourceID: "hubble-a"}, flow)
	if err != nil {
		t.Fatal(err)
	}
	if first.EventID != second.EventID || first.EventID == "" {
		t.Fatalf("retry IDs = %q and %q", first.EventID, second.EventID)
	}
}

func TestNormalizeHubbleFlowRejectsMissingIdentityAndMalformedFields(t *testing.T) {
	base := hubbleFlow{
		ObservedAt: time.Now(), Source: hubbleEndpoint{KubernetesUID: "source"},
		Verdict: "DROPPED", Direction: "EGRESS", Protocol: "TCP",
	}
	_, err := normalizeHubbleFlow(hubbleConfig{ClusterID: "cluster-a", SourceID: "hubble-a"}, base)
	var missing *missingIdentityError
	if !errors.As(err, &missing) || missing.Endpoint != "destination" {
		t.Fatalf("missing identity error = %v", err)
	}
	base.Destination = hubbleEndpoint{IP: "not-an-ip"}
	if _, err := normalizeHubbleFlow(hubbleConfig{ClusterID: "cluster-a", SourceID: "hubble-a"}, base); err == nil {
		t.Fatal("invalid destination IP was accepted")
	}
	base.Destination = hubbleEndpoint{IP: "10.0.0.2"}
	base.Protocol = "HTTP"
	if _, err := normalizeHubbleFlow(hubbleConfig{ClusterID: "cluster-a", SourceID: "hubble-a"}, base); err == nil {
		t.Fatal("L7 protocol was accepted")
	}
}

func TestHubblePipelineProjectsOnlyAfterSinkCommitAndBoundsRollups(t *testing.T) {
	sink := &controlledSink{release: make(chan struct{}), attempted: make(chan struct{}, 1)}
	rollup := telemetry.NewRollup(telemetry.RollupConfig{Window: time.Minute, Retention: time.Hour, MaxSeries: 1})
	committed := make(chan struct{}, 1)
	pipeline, err := telemetry.NewPipeline(telemetry.PipelineConfig{QueueCapacity: 2, MaxBatch: 1, FlushInterval: time.Hour, RetryMinimum: time.Millisecond, RetryMaximum: time.Millisecond}, sink, func(_ context.Context, events []telemetry.Event) error {
		rollup.ObserveBatch(events)
		committed <- struct{}{}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pipeline.Run(ctx) }()
	flow := hubbleFlow{
		ObservedAt: time.Now().UTC(), Source: hubbleEndpoint{KubernetesUID: "source"}, Destination: hubbleEndpoint{IP: "10.0.0.2"},
		Verdict: "FORWARDED", Direction: "EGRESS", Protocol: "TCP", DestPort: 443,
	}
	if err := ingestHubbleFlow(ctx, pipeline, hubbleConfig{ClusterID: "cluster-a", SourceID: "hubble-a"}, flow); err != nil {
		t.Fatal(err)
	}
	<-sink.attempted
	if got := len(rollup.Input().Telemetry); got != 0 {
		t.Fatalf("projected %d rollups before sink commit", got)
	}
	close(sink.release)
	select {
	case <-committed:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for sink commit")
	}
	if got := len(rollup.Input().Telemetry); got != 1 {
		t.Fatalf("rollups after commit = %d", got)
	}
	flow.ObservedAt = flow.ObservedAt.Add(2 * time.Minute)
	flow.Destination = hubbleEndpoint{IP: "10.0.0.3"}
	if err := ingestHubbleFlow(ctx, pipeline, hubbleConfig{ClusterID: "cluster-a", SourceID: "hubble-a"}, flow); err != nil {
		t.Fatal(err)
	}
	select {
	case <-committed:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for second sink commit")
	}
	if got := len(rollup.Input().Telemetry); got != 1 {
		t.Fatalf("bounded rollups = %d", got)
	}
	compileHubbleRollup(t, rollup.Input())
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

type controlledSink struct {
	release   chan struct{}
	attempted chan struct{}
}

func (sink *controlledSink) WriteBatch(ctx context.Context, _ []telemetry.Event) error {
	select {
	case sink.attempted <- struct{}{}:
	default:
	}
	select {
	case <-sink.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func compileHubbleRollup(t *testing.T, input graph.Input) {
	t.Helper()
	claims := make(map[graph.IdentityClaim]struct{})
	for _, event := range input.Telemetry {
		claims[event.Subject] = struct{}{}
		claims[event.Object] = struct{}{}
	}
	for claim := range claims {
		input.Resources = append(input.Resources, graph.ResourceAssertion{
			Claim: claim, Kind: "test/endpoint", PluginID: "test", SourceID: "test",
			RuleID: "test.endpoint", EvidenceIDs: []string{"test:" + claim.ImmutableKey},
		})
	}
	registry := graph.NewRegistry()
	if err := discovery.RegisterIdentitySchemes(registry, kubernetesplugin.Descriptor()); err != nil {
		t.Fatal(err)
	}
	if _, err := graph.NewCompiler(registry).Compile(input); err != nil {
		t.Fatal(err)
	}
}
