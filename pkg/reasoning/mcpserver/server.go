package mcpserver

import (
	"context"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/agentshield-dev/agentshield/pkg/graph"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
)

// QueryInput is the argument schema shared by single-template tools.
type QueryInput struct {
	AnchorIDs []string `json:"anchorIds" jsonschema:"resource IDs supplied by the analysis packet"`
}

// GraphPathInput is the argument schema for find_graph_paths, the multi-hop
// traversal tool.
type GraphPathInput struct {
	AnchorIDs  []string          `json:"anchorIds" jsonschema:"resource IDs supplied by the analysis packet"`
	Predicates []graph.Predicate `json:"predicates,omitempty" jsonschema:"optional relationship allowlist; the default includes every registered predicate except runs-on"`
}

// New returns an MCP server whose tools all query provider.
func New(provider *reasoning.ContextProvider) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "agentshield-graph", Version: "v1alpha1"}, nil)
	addContextTool(server, provider, "get_security_neighborhood", "Return a bounded one-hop security neighborhood for supplied resource anchors.", reasoning.TemplateSecurityNeighborhood)
	addContextTool(server, provider, "get_telemetry_chain", "Return bounded runtime observations connected to supplied resource anchors.", reasoning.TemplateTelemetryChain)
	addContextTool(server, provider, "get_governance_posture", "Return bounded governance relationships and facets connected to supplied resource anchors without inferring policy effect.", reasoning.TemplateGovernancePosture)
	addGraphPathTool(server, provider)
	addContextTool(server, provider, "get_incident_timeline", "Return bounded ordered runtime observations for supplied resource anchors across the current incident.", reasoning.TemplateIncidentTimeline)
	addContextTool(server, provider, "get_behavior_baseline", "Return bounded previously observed communication behavior for supplied resource anchors.", reasoning.TemplateBehaviorBaseline)
	return server
}

// addGraphPathTool registers the multi-hop traversal. It returns the subgraph
// reachable within the provider's path depth, not individual paths; the name is
// kept because the reasoning runtime calls it by name and recorded model
// transcripts and replayed packets refer to it.
func addGraphPathTool(server *mcp.Server, provider *reasoning.ContextProvider) {
	mcp.AddTool(server, &mcp.Tool{Name: "find_graph_paths", Description: "Return the bounded multi-hop subgraph (resources, relationships, and facets) reachable from supplied resource anchors within a fixed hop limit. It does not enumerate individual paths. By default traversal follows every predicate except runs-on; pass predicates to use an explicit allowlist."}, func(_ context.Context, _ *mcp.CallToolRequest, input GraphPathInput) (*mcp.CallToolResult, reasoning.ContextResult, error) {
		result, err := provider.Query(reasoning.ContextQuery{Token: provider.Token(), Template: reasoning.TemplateGraphPath, AnchorIDs: input.AnchorIDs, Predicates: input.Predicates})
		return nil, result, err
	})
}

// ServeStdio serves provider's tools over stdin and stdout until the session
// ends.
func ServeStdio(ctx context.Context, provider *reasoning.ContextProvider) error {
	session, err := New(provider).Connect(ctx, &mcp.StdioTransport{}, nil)
	if err != nil {
		return err
	}
	return session.Wait()
}

// NewHTTPHandler exposes the MCP server using the streamable HTTP transport.
// The caller must bind it to a loopback or otherwise authenticated listener:
// the pinned packet may contain sensitive graph and telemetry context.
func NewHTTPHandler(provider *reasoning.ContextProvider) http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return New(provider)
	}, nil)
}

// ConnectInMemory starts a server for provider on an in-process transport and
// returns a connected client session. The returned close function stops the
// server and closes the session; callers must call it.
func ConnectInMemory(ctx context.Context, provider *reasoning.ContextProvider) (*mcp.ClientSession, func() error, error) {
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverCtx, cancel := context.WithCancel(ctx)
	connected := make(chan error, 1)
	go func() {
		_, err := New(provider).Connect(serverCtx, serverTransport, nil)
		connected <- err
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "agentshield-reasoning", Version: "v1alpha1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("connect MCP client: %w", err)
	}
	if err := <-connected; err != nil {
		cancel()
		_ = session.Close()
		return nil, nil, fmt.Errorf("connect MCP server: %w", err)
	}
	closeSession := func() error {
		cancel()
		return session.Close()
	}
	return session, closeSession, nil
}

func addContextTool(server *mcp.Server, provider *reasoning.ContextProvider, name, description, template string) {
	mcp.AddTool(server, &mcp.Tool{Name: name, Description: description}, func(_ context.Context, _ *mcp.CallToolRequest, input QueryInput) (*mcp.CallToolResult, reasoning.ContextResult, error) {
		result, err := provider.Query(reasoning.ContextQuery{Token: provider.Token(), Template: template, AnchorIDs: input.AnchorIDs})
		return nil, result, err
	})
}
