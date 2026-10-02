package agentgateway

import (
	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/spf13/pflag"
)

// CLIConfig contains agentgateway-owned runtime options.
type CLIConfig struct {
	ClusterID string
	SourceID  string
}

// RegisterFlags registers agentgateway flags in the agentgateway-* namespace.
func (config *CLIConfig) RegisterFlags(flags *pflag.FlagSet) error {
	return discovery.RegisterPluginFlags(flags, PluginID, func(pluginFlags *discovery.PluginFlags) {
		pluginFlags.StringVar(&config.ClusterID, "cluster-id", "local", "stable Kubernetes authority ID used by agentgateway")
		pluginFlags.StringVar(&config.SourceID, "source-id", "kubernetes/local", "stable agentgateway source ID")
	})
}
