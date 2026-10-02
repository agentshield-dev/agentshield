package istio

import (
	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/spf13/pflag"
)

// CLIConfig contains Istio-owned runtime options.
type CLIConfig struct {
	ClusterID     string
	NetworkID     string
	SourceID      string
	RootNamespace string
}

// RegisterFlags registers Istio flags in the istio-* namespace.
func (config *CLIConfig) RegisterFlags(flags *pflag.FlagSet) error {
	return discovery.RegisterPluginFlags(flags, PluginID, func(pluginFlags *discovery.PluginFlags) {
		pluginFlags.StringVar(&config.ClusterID, "cluster-id", "local", "stable Kubernetes authority ID used by Istio")
		pluginFlags.StringVar(&config.NetworkID, "network-id", "", "stable network realm authority ID; defaults to this plugin's cluster ID")
		pluginFlags.StringVar(&config.SourceID, "source-id", "kubernetes/local", "stable Istio source ID")
		pluginFlags.StringVar(&config.RootNamespace, "root-namespace", "istio-system", "Istio mesh root namespace")
	})
}
