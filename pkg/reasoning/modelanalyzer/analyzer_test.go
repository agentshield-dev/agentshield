package modelanalyzer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/agentshield-dev/agentshield/pkg/detector"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
)

func TestNewValidatesConfiguration(t *testing.T) {
	if _, err := New(reasoning.Client{}, Config{}); err == nil {
		t.Fatal("empty endpoint was accepted")
	}
	if _, err := New(reasoning.Client{Endpoint: "http://model-provider"}, Config{MaxAttempts: -1}); err == nil {
		t.Fatal("negative max attempts was accepted")
	}
	analyzer, err := New(reasoning.Client{Endpoint: "http://model-provider"}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if analyzer.config.MaxAttempts != 3 || analyzer.config.Analysis.Name != "agentshield-reasoning" {
		t.Fatalf("defaults = %#v", analyzer.config)
	}
}

func TestAnalyzeDoesNotRetryPermanentModelErrors(t *testing.T) {
	for _, test := range []struct {
		status   int
		requests int32
	}{
		{status: http.StatusBadRequest, requests: 1},
		{status: http.StatusTooManyRequests, requests: 3},
		{status: http.StatusInternalServerError, requests: 3},
	} {
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			http.Error(writer, "rejected", test.status)
		}))
		packet := reasoning.Packet{
			AnalysisID: "analysis", HydratedGraphSHA256: "graph", Resources: []reasoning.Resource{{ID: "r1"}},
			Signals: []detector.InvestigationSignal{{ID: "signal", Risk: detector.RiskMedium, AnchorIDs: []string{"r1"}}},
		}
		provider, err := reasoning.NewContextProvider(packet, reasoning.DefaultContextLimits())
		if err != nil {
			t.Fatal(err)
		}
		analyzer, err := New(reasoning.Client{Endpoint: server.URL}, Config{})
		if err != nil {
			t.Fatal(err)
		}
		run, err := analyzer.Analyze(context.Background(), packet, provider)
		server.Close()
		if err == nil || requests.Load() != test.requests || int32(run.Attempts) != test.requests {
			t.Fatalf("status %d: requests=%d attempts=%d err=%v", test.status, requests.Load(), run.Attempts, err)
		}
		if permanent := reasoning.IsPermanentModelError(err); permanent != (test.status == http.StatusBadRequest) {
			t.Fatalf("status %d: permanent=%t", test.status, permanent)
		}
	}
}
