package cilium

import (
	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/spf13/pflag"
)

// CLIConfig contains Cilium-owned runtime options.
type CLIConfig struct {
	ClusterID string
	SourceID  string
}

// RegisterFlags registers Cilium flags in the cilium-* namespace.
func (config *CLIConfig) RegisterFlags(flags *pflag.FlagSet) error {
	return discovery.RegisterPluginFlags(flags, PluginID, func(pluginFlags *discovery.PluginFlags) {
		pluginFlags.StringVar(&config.ClusterID, "cluster-id", "local", "stable Kubernetes authority ID used by Cilium")
		pluginFlags.StringVar(&config.SourceID, "source-id", "kubernetes/local", "stable Cilium source ID")
	})
}
