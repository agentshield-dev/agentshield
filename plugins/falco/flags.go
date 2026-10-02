package falco

import (
	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/spf13/pflag"
)

// CLIConfig contains Falco-owned runtime options.
type CLIConfig struct {
	ClusterID string
	SourceID  string
}

// RegisterFlags registers Falco flags in the falco-* namespace.
func (config *CLIConfig) RegisterFlags(flags *pflag.FlagSet) error {
	return discovery.RegisterPluginFlags(flags, PluginID, func(pluginFlags *discovery.PluginFlags) {
		pluginFlags.StringVar(&config.ClusterID, "cluster-id", "local", "stable Kubernetes authority ID used by Falco alert telemetry")
		pluginFlags.StringVar(&config.SourceID, "source-id", "kubernetes/local", "stable Falco telemetry source ID")
	})
}
