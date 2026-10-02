package falco

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/agentshield-dev/agentshield/pkg/telemetry"
)

const (
	PluginID = "falco"
	// DefaultShellRule is the stock Falco rule that reports an interactive shell in a container.
	DefaultShellRule = "Terminal shell in container"
)

// Config configures the plugin.
type Config struct {
	ClusterID string
	SourceID  string
	// ShellRules are the Falco rule names that report an interactive shell.
	ShellRules []string
}

// Plugin is a telemetry-only capability. Falco alerts arrive through the shared
// OTLP receiver; the plugin owns no provider connection or contribution.
type Plugin struct {
	config Config
}

// SourceID implements [discovery.PluginInstance].
func (p *Plugin) SourceID() string { return p.config.SourceID }

// New validates config and applies the default shell rule.
func New(config Config) (*Plugin, error) {
	config.ClusterID = strings.TrimSpace(config.ClusterID)
	config.SourceID = strings.TrimSpace(config.SourceID)
	if config.ClusterID == "" || config.SourceID == "" {
		return nil, errors.New("Falco plugin requires cluster and source IDs")
	}
	rules := make([]string, 0, len(config.ShellRules))
	for _, rule := range config.ShellRules {
		if rule = strings.TrimSpace(rule); rule != "" {
			rules = append(rules, rule)
		}
	}
	if len(rules) == 0 {
		rules = []string{DefaultShellRule}
	}
	slices.Sort(rules)
	config.ShellRules = slices.Compact(rules)
	return &Plugin{config: config}, nil
}

// Descriptor declares the plugin. It consumes and publishes no collection and
// introduces no identity scheme; its claims use the Kubernetes and core
// ProcessClass schemes.
func Descriptor() discovery.Descriptor {
	return discovery.Descriptor{ID: PluginID, Version: "0.1.0", Description: "Falco runtime-security alert telemetry"}
}

// Descriptor implements [discovery.Plugin].
func (p *Plugin) Descriptor() discovery.Descriptor {
	return Descriptor()
}

// Run blocks until ctx ends; alerts arrive through the shared OTLP receiver.
func (p *Plugin) Run(ctx context.Context, _ discovery.Runtime) error {
	<-ctx.Done()
	return nil
}

// TelemetryMappings implements [discovery.TelemetryMappingProvider].
func (p *Plugin) TelemetryMappings() []telemetry.Mapping {
	return []telemetry.Mapping{{PluginID: PluginID, SourceID: p.config.SourceID, Mapper: alertMapper{clusterID: p.config.ClusterID, shellRules: p.config.ShellRules}}}
}
