package state

import (
	"context"
	"fmt"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/graph"
)

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
