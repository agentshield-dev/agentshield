package mcpserver

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
)

func TestStreamableHTTPServesMCPTools(t *testing.T) {
	provider, err := reasoning.NewContextProvider(reasoning.Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: "graph", Resources: []reasoning.Resource{{ID: "anchor"}},
	}, reasoning.DefaultContextLimits())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewHTTPHandler(provider))
	t.Cleanup(server.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "test-http-client", Version: "v1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint: server.URL, HTTPClient: server.Client(), DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeSession(t, session) })
	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 6 {
		t.Fatalf("tool count = %d, want 6", len(tools.Tools))
	}
}

func TestServerExposesBoundedContextTools(t *testing.T) {
	provider, err := reasoning.NewContextProvider(reasoning.Packet{
		AnalysisID: "analysis", HydratedGraphSHA256: "graph", Resources: []reasoning.Resource{{ID: "anchor"}},
	}, reasoning.DefaultContextLimits())
	if err != nil {
		t.Fatal(err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server := New(provider)
	serverConnected := make(chan error, 1)
	go func() {
		_, connectErr := server.Connect(context.Background(), serverTransport, nil)
		serverConnected <- connectErr
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeSession(t, session) })
	if err := <-serverConnected; err != nil {
		t.Fatal(err)
	}
	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 6 {
		t.Fatalf("tool count = %d, want 6", len(tools.Tools))
	}
	for _, tool := range tools.Tools {
		if tool.Name != "find_graph_paths" {
			continue
		}
		encoded, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(encoded, &schema); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(schema.Required, "predicates") {
			t.Fatalf("graph path schema requires optional predicates: %s", encoded)
		}
	}
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "get_security_neighborhood",
		Arguments: map[string]any{
			"anchorIds": []any{"anchor"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || result.StructuredContent == nil {
		t.Fatalf("tool result = %#v", result)
	}
	result, err = session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "find_graph_paths",
		Arguments: map[string]any{
			"anchorIds": []any{"anchor"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError || result.StructuredContent == nil {
		t.Fatalf("graph path result = %#v", result)
	}
}

func closeSession(t *testing.T, session *mcp.ClientSession) {
	t.Helper()
	if err := session.Close(); err != nil {
		t.Errorf("close client session: %v", err)
	}
}
