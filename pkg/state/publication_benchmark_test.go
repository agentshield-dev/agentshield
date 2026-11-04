package state

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

func BenchmarkPostgreSQLPublication(b *testing.B) {
	for _, size := range []int{10_000, 50_000, 100_000} {
		b.Run(fmt.Sprintf("assertions=%d", size), func(b *testing.B) {
			store := benchmarkStore(b)
			inputs := [2]graph.Input{benchmarkInput(size, "a"), benchmarkInput(size, "b")}
			if _, err := store.ReplaceContribution(context.Background(), benchmarkContribution(1, inputs[0])); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if _, err := store.ReplaceContribution(context.Background(), benchmarkContribution(uint64(index+2), inputs[(index+1)%2])); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPostgreSQLInitialPublication(b *testing.B) {
	for _, size := range []int{10_000, 50_000, 100_000} {
		b.Run(fmt.Sprintf("assertions=%d", size), func(b *testing.B) {
			store := benchmarkStore(b)
			contribution := benchmarkContribution(1, benchmarkInput(size, "a"))
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if index > 0 {
					b.StopTimer()
					resetBenchmarkStore(b, store)
					b.StartTimer()
				}
				if _, err := store.ReplaceContribution(context.Background(), contribution); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPostgreSQLDeltaPublication(b *testing.B) {
	for _, size := range []int{10_000, 50_000, 100_000} {
		b.Run(fmt.Sprintf("assertions=%d", size), func(b *testing.B) {
			store := benchmarkStore(b)
			initial := benchmarkInput(size, "a")
			if _, err := store.ReplaceContribution(context.Background(), benchmarkContribution(1, initial)); err != nil {
				b.Fatal(err)
			}
			variants := [2]graph.ResourceAssertion{initial.Resources[size-1], benchmarkInput(size, "b").Resources[size-1]}
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				if _, err := store.ApplyContributionDelta(context.Background(), ContributionDelta{
					PluginID: "test", SourceID: "benchmark", Name: "inventory", BaseGeneration: uint64(index + 1), Generation: uint64(index + 2),
					Added: graph.Input{Resources: []graph.ResourceAssertion{variants[(index+1)%2]}}, Retracted: graph.Input{Resources: []graph.ResourceAssertion{variants[index%2]}},
					Ready: true, SourceHealth: SourceHealthHealthy,
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPostgreSQLLatest(b *testing.B) {
	for _, size := range []int{10_000, 50_000, 100_000} {
		b.Run(fmt.Sprintf("assertions=%d", size), func(b *testing.B) {
			store := benchmarkStore(b)
			if _, err := store.ReplaceContribution(context.Background(), benchmarkContribution(1, benchmarkInput(size, "a"))); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for range b.N {
				if _, err := store.Latest(context.Background()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func benchmarkStore(b *testing.B) *Store {
	b.Helper()
	databaseURL := os.Getenv("AGENTSHIELD_TEST_DATABASE_URL")
	if databaseURL == "" {
		b.Skip("set AGENTSHIELD_TEST_DATABASE_URL to run PostgreSQL benchmarks")
	}
	registry := graph.NewRegistry()
	if err := registry.Register(graph.TrimmedIdentityScheme(testIdentityScheme)); err != nil {
		b.Fatal(err)
	}
	store, err := Open(context.Background(), Config{DatabaseURL: databaseURL, MaxConnections: 8, MinConnections: 1}, graph.NewCompiler(registry))
	if err != nil {
		b.Fatal(err)
	}
	resetBenchmarkStore(b, store)
	b.Cleanup(func() { _ = store.Close() })
	return store
}

func resetBenchmarkStore(b *testing.B, store *Store) {
	b.Helper()
	if _, err := store.pool.Exec(context.Background(), `TRUNCATE deployment_rule_jobs, detection_signals, investigation_jobs, contributions, resource_identities, native_events, reasoning_cursors, findings RESTART IDENTITY CASCADE`); err != nil {
		store.Close()
		b.Fatal(err)
	}
}

func benchmarkContribution(generation uint64, input graph.Input) Contribution {
	return Contribution{
		PluginID: "test", SourceID: "benchmark", Name: "inventory", Generation: generation,
		Ready: true, SourceHealth: SourceHealthHealthy, Input: input,
	}
}

func benchmarkInput(size int, variant string) graph.Input {
	resources := make([]graph.ResourceAssertion, size)
	for index := range resources {
		key := fmt.Sprintf("resource-%08d", index)
		if index == size-1 {
			key += "-" + variant
		}
		resources[index] = graph.ResourceAssertion{
			Claim: graph.IdentityClaim{Scheme: testIdentityScheme, AuthorityID: "benchmark", ImmutableKey: key},
			Kind:  "test/resource", DisplayName: key, PluginID: "test", SourceID: "benchmark",
			RuleID: "benchmark.resource", EvidenceIDs: []string{"event-" + key},
		}
	}
	return graph.Input{Resources: resources}
}
