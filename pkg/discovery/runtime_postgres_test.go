package discovery

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/state"
)

var runtimeTestIdentityScheme = graph.IdentityScheme{Group: "runtime.test.agentshield.io", Version: "v1", Kind: "Resource"}

func TestPostgreSQLRuntimeRecoveryCheckpoints(t *testing.T) {
	databaseURL := os.Getenv("AGENTSHIELD_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set AGENTSHIELD_TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	registry := graph.NewRegistry()
	if err := registry.Register(graph.TrimmedIdentityScheme(runtimeTestIdentityScheme)); err != nil {
		t.Fatal(err)
	}
	store, err := state.Open(context.Background(), state.Config{DatabaseURL: databaseURL, MaxConnections: 4, MinConnections: 1}, graph.NewCompiler(registry))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	owner := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")) + "-" + time.Now().UTC().Format("150405.000000000")

	t.Run("process restart", func(t *testing.T) {
		sourceID := owner + "/restart"
		first := postgresTestRuntime(store, time.Hour, 100)
		postgresTestPublish(t, first, first.publications, sourceID, "inventory", 1, "a", "checkpoint")
		postgresTestPublish(t, first, first.publications, sourceID, "inventory", 2, "b", "delta")

		restarted := postgresTestRuntime(store, time.Hour, 100)
		postgresTestPublish(t, restarted, restarted.publications, sourceID, "inventory", 3, "c", "checkpoint")
		assertPostgresTestResources(t, store, sourceID, "c")
	})

	t.Run("cursor loss", func(t *testing.T) {
		runtime := postgresTestRuntime(store, time.Hour, 100)
		plugin := &postgresCursorLossPlugin{sourceID: owner + "/cursor-loss", running: make(chan struct{})}
		manager, err := NewManager(runtime, plugin)
		if err != nil {
			t.Fatal(err)
		}
		manager.restartBackoff = time.Millisecond
		manager.maxRestartBackoff = 2 * time.Millisecond
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		result := make(chan error, 1)
		go func() { result <- manager.Run(ctx) }()
		select {
		case <-plugin.running:
		case err := <-result:
			t.Fatalf("manager stopped: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("plugin was not restarted after cursor loss")
		}
		if got := plugin.attempts.Load(); got != 2 {
			t.Fatalf("plugin attempts = %d, want 2", got)
		}
		assertPostgresTestResources(t, store, plugin.sourceID, "after")
		cancel()
		if err := <-result; err != nil {
			t.Fatalf("manager shutdown: %v", err)
		}
	})

	t.Run("stale base", func(t *testing.T) {
		runtime := postgresTestRuntime(store, time.Hour, 100)
		sourceID := owner + "/stale-base"
		session := newPublicationSession()
		postgresTestPublish(t, runtime, session, sourceID, "inventory", 1, "a", "checkpoint")
		if _, err := store.ReplaceContribution(context.Background(), postgresTestStateContribution(sourceID, "inventory", 2, "b")); err != nil {
			t.Fatal(err)
		}
		if mode, err := runtime.publishContribution(context.Background(), "runtime-test", sourceID, postgresTestOutput(sourceID, "inventory", 3, "c"), session); mode != "delta" || !errors.Is(err, state.ErrContributionDeltaBaseMismatch) {
			t.Fatalf("stale publication mode=%q error=%v", mode, err)
		}
		postgresTestPublish(t, runtime, session, sourceID, "inventory", 4, "d", "checkpoint")
		assertPostgresTestResources(t, store, sourceID, "d")
	})

	t.Run("membership drift", func(t *testing.T) {
		runtime := postgresTestRuntime(store, time.Hour, 100)
		sourceID := owner + "/drift"
		session := newPublicationSession()
		postgresTestPublish(t, runtime, session, sourceID, "inventory", 1, "a", "checkpoint")
		key := publicationKey{pluginID: "runtime-test", sourceID: sourceID, name: "inventory"}
		publication := session.contributions[key]
		publication.output = postgresTestOutput(sourceID, "inventory", 1, "missing")
		session.contributions[key] = publication

		postgresTestPublish(t, runtime, session, sourceID, "inventory", 2, "b", "checkpoint")
		assertPostgresTestResources(t, store, sourceID, "b")
	})

	t.Run("periodic delta limit", func(t *testing.T) {
		runtime := postgresTestRuntime(store, time.Hour, 1)
		sourceID := owner + "/delta-limit"
		session := newPublicationSession()
		postgresTestPublish(t, runtime, session, sourceID, "inventory", 1, "a", "checkpoint")
		postgresTestPublish(t, runtime, session, sourceID, "inventory", 2, "b", "delta")
		postgresTestPublish(t, runtime, session, sourceID, "inventory", 3, "c", "checkpoint")
		assertPostgresTestResources(t, store, sourceID, "c")
	})

	t.Run("same generation retry at checkpoint boundary", func(t *testing.T) {
		runtime := postgresTestRuntime(store, time.Hour, 1)
		sourceID := owner + "/same-generation-retry"
		session := newPublicationSession()
		postgresTestPublish(t, runtime, session, sourceID, "inventory", 1, "a", "checkpoint")
		postgresTestPublish(t, runtime, session, sourceID, "inventory", 2, "b", "delta")
		retry := postgresTestOutput(sourceID, "inventory", 2, "b")
		retry.SourceObservedAt = time.Now().UTC()
		retry.Ready = false
		retry.SourceHealth = ""
		if mode, err := runtime.publishContribution(context.Background(), "runtime-test", sourceID, retry, session); err != nil || mode != "noop" {
			t.Fatalf("same-generation retry mode=%q error=%v, want noop nil", mode, err)
		}
		assertPostgresTestResources(t, store, sourceID, "b")
	})

	t.Run("periodic interval", func(t *testing.T) {
		runtime := postgresTestRuntime(store, time.Hour, 100)
		sourceID := owner + "/interval"
		session := newPublicationSession()
		postgresTestPublish(t, runtime, session, sourceID, "inventory", 1, "a", "checkpoint")
		key := publicationKey{pluginID: "runtime-test", sourceID: sourceID, name: "inventory"}
		publication := session.contributions[key]
		publication.checkpointAt = time.Now().Add(-2 * time.Hour)
		session.contributions[key] = publication

		postgresTestPublish(t, runtime, session, sourceID, "inventory", 2, "b", "checkpoint")
		assertPostgresTestResources(t, store, sourceID, "b")
	})
}

func postgresTestRuntime(store *state.Store, interval time.Duration, deltas uint64) *RuntimeService {
	return &RuntimeService{
		hub: NewHub(), store: store,
		config:       RuntimeConfig{CheckpointInterval: interval, CheckpointDeltas: deltas},
		publications: newPublicationSession(),
	}
}

type postgresCursorLossPlugin struct {
	sourceID string
	attempts atomic.Int32
	running  chan struct{}
}

func (p *postgresCursorLossPlugin) Descriptor() Descriptor {
	return Descriptor{ID: "runtime-cursor-test", Version: "1"}
}

func (p *postgresCursorLossPlugin) SourceID() string { return p.sourceID }

func (p *postgresCursorLossPlugin) Run(ctx context.Context, runtime Runtime) error {
	attempt := p.attempts.Add(1)
	generation, err := runtime.ContributionGeneration(ctx, "runtime-cursor-test", p.sourceID)
	if err != nil {
		return err
	}
	resourceKey := "before"
	if attempt > 1 {
		resourceKey = "after"
	}
	output := postgresTestOutput(p.sourceID, "inventory", generation+1, resourceKey)
	for index := range output.Input.Resources {
		output.Input.Resources[index].PluginID = "runtime-cursor-test"
	}
	if err := runtime.ReplaceContribution(ctx, "runtime-cursor-test", p.sourceID, output); err != nil {
		return err
	}
	if attempt == 1 {
		return errors.New("provider cursor lost")
	}
	close(p.running)
	<-ctx.Done()
	return ctx.Err()
}

func postgresTestPublish(t *testing.T, runtime *RuntimeService, session *publicationSession, sourceID, name string, generation uint64, resourceKey, wantMode string) {
	t.Helper()
	mode, err := runtime.publishContribution(context.Background(), "runtime-test", sourceID, postgresTestOutput(sourceID, name, generation, resourceKey), session)
	if err != nil || mode != wantMode {
		t.Fatalf("generation %d publication mode=%q error=%v, want %q", generation, mode, err, wantMode)
	}
}

func postgresTestOutput(sourceID, name string, generation uint64, resourceKey string) ContributionOutput {
	return ContributionOutput{
		Name: name, Generation: generation, Input: postgresTestInput(sourceID, resourceKey),
		Ready: true, SourceHealth: state.SourceHealthHealthy,
	}
}

func postgresTestStateContribution(sourceID, name string, generation uint64, resourceKey string) state.Contribution {
	return state.Contribution{
		PluginID: "runtime-test", SourceID: sourceID, Name: name, Generation: generation,
		Input: postgresTestInput(sourceID, resourceKey), Ready: true, SourceHealth: state.SourceHealthHealthy,
	}
}

func postgresTestInput(sourceID, resourceKey string) graph.Input {
	return graph.Input{Resources: []graph.ResourceAssertion{{
		Claim: graph.IdentityClaim{Scheme: runtimeTestIdentityScheme, AuthorityID: sourceID, ImmutableKey: resourceKey},
		Kind:  "test/resource", PluginID: "runtime-test", SourceID: sourceID, RuleID: "runtime-test.resource",
		EvidenceIDs: []string{"event-" + resourceKey},
	}}}
}

func assertPostgresTestResources(t *testing.T, store *state.Store, sourceID string, want ...string) {
	t.Helper()
	view, err := store.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, resource := range view.Snapshot.Resources {
		if resource.Identity.Scheme == runtimeTestIdentityScheme && resource.Identity.AuthorityID == sourceID {
			got = append(got, resource.Identity.ImmutableKey)
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("resources = %v, want %v", got, want)
	}
}
