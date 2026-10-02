// Command agentshield-reasoning-mcp serves reasoning context tools over
// streamable HTTP for a saved packet. It binds to loopback by default because
// the packet may contain sensitive graph and telemetry context.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/agentshield-dev/agentshield/internal/version"
	"github.com/agentshield-dev/agentshield/pkg/reasoning"
	"github.com/agentshield-dev/agentshield/pkg/reasoning/mcpserver"
	"github.com/spf13/pflag"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	flags := pflag.NewFlagSet("agentshield-reasoning-mcp", pflag.ContinueOnError)
	packetPath := flags.String("packet", "", "path to an immutable reasoning packet")
	telemetryContextPath := flags.String("telemetry-context", "", "path to pinned telemetry and candidate-path context")
	listen := flags.String("listen", "127.0.0.1:8090", "HTTP listen address; non-loopback exposure requires authenticated infrastructure")
	showVersion := flags.Bool("version", false, "print the version and exit")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println("agentshield-reasoning-mcp " + version.String())
		return nil
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *packetPath == "" {
		return errors.New("-packet is required")
	}
	if *listen == "" {
		return errors.New("--listen must not be empty")
	}
	encoded, err := os.ReadFile(*packetPath)
	if err != nil {
		return fmt.Errorf("read packet: %w", err)
	}
	var packet reasoning.Packet
	if err := json.Unmarshal(encoded, &packet); err != nil {
		return fmt.Errorf("decode packet: %w", err)
	}
	deferred := reasoning.PinnedTelemetryContext{
		Token:           reasoning.AnalysisToken{AnalysisID: packet.AnalysisID, GraphSHA256: packet.HydratedGraphSHA256},
		TelemetryWindow: packet.TelemetryWindow,
	}
	if *telemetryContextPath != "" {
		encodedContext, err := os.ReadFile(*telemetryContextPath)
		if err != nil {
			return fmt.Errorf("read telemetry context: %w", err)
		}
		if err := json.Unmarshal(encodedContext, &deferred); err != nil {
			return fmt.Errorf("decode telemetry context: %w", err)
		}
	}
	provider, err := reasoning.NewContextProviderWithTelemetry(packet, deferred, reasoning.DefaultContextLimits())
	if err != nil {
		return fmt.Errorf("create context provider: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	mux := http.NewServeMux()
	mcpHandler := mcpserver.NewHTTPHandler(provider)
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/mcp/", mcpHandler)
	server := &http.Server{
		Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second,
	}
	shutdown := make(chan struct{})
	go func() {
		defer close(shutdown)
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()
	fmt.Fprintf(os.Stderr, "AgentShield reasoning MCP listening on http://%s/mcp\n", *listen)
	err = server.ListenAndServe()
	stop()
	<-shutdown
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve MCP over HTTP: %w", err)
	}
	return nil
}
