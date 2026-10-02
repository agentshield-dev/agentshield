package evals

import (
	"context"
	"fmt"
	"slices"
)

type ObservationAdapter interface {
	ID() string
	Manifest(Campaign, WorkloadContract) string
	WaitReady(context.Context, string, WorkloadContract) error
}

func observationAdapter(id string) (ObservationAdapter, error) {
	adapters := []ObservationAdapter{istioOTLPObservationAdapter{}}
	for _, adapter := range adapters {
		if adapter.ID() == id {
			return adapter, nil
		}
	}
	available := make([]string, 0, len(adapters))
	for _, adapter := range adapters {
		available = append(available, adapter.ID())
	}
	slices.Sort(available)
	return nil, fmt.Errorf("unknown observation adapter %q; available adapters: %v", id, available)
}
