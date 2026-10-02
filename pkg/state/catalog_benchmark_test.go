package state

import (
	"context"
	"fmt"
	"testing"
)

func BenchmarkPostgreSQLResourcePage(b *testing.B) {
	for _, size := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("assertions=%d", size), func(b *testing.B) {
			store := benchmarkStore(b)
			if _, err := store.ReplaceContribution(context.Background(), benchmarkContribution(1, benchmarkInput(size, "a"))); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for range b.N {
				if _, err := store.QueryResources(context.Background(), ResourceQuery{Limit: 25}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPostgreSQLResourceDetail(b *testing.B) {
	for _, size := range []int{100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("assertions=%d", size), func(b *testing.B) {
			store := benchmarkStore(b)
			view, err := store.ReplaceContribution(context.Background(), benchmarkContribution(1, benchmarkInput(size, "a")))
			if err != nil {
				b.Fatal(err)
			}
			resourceID := view.Snapshot.Resources[size/2].ID
			b.ResetTimer()
			for range b.N {
				if _, err := store.GetResourceDetail(context.Background(), resourceID); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
