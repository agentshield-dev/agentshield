package kubernetes

import (
	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/spf13/pflag"
)

// CLIConfig contains the Kubernetes-owned runtime options. Its cluster
// authority is separate from each consumer plugin's authority configuration;
// matching values are required when their identities must join.
type CLIConfig struct {
	Kubeconfig string
	ClusterID  string
	NetworkID  string
	SourceID   string
	Disabled   bool
}

// RegisterFlags registers Kubernetes flags in the kubernetes-* namespace.
func (config *CLIConfig) RegisterFlags(flags *pflag.FlagSet) error {
	return discovery.RegisterPluginFlags(flags, PluginID, func(pluginFlags *discovery.PluginFlags) {
		pluginFlags.StringVar(&config.Kubeconfig, "kubeconfig", "", "kubeconfig path; defaults to standard loading rules")
		pluginFlags.StringVar(&config.ClusterID, "cluster-id", "local", "stable Kubernetes authority ID")
		pluginFlags.StringVar(&config.NetworkID, "network-id", "", "stable network realm authority ID; defaults to this plugin's cluster ID")
		pluginFlags.StringVar(&config.SourceID, "source-id", "kubernetes/local", "stable Kubernetes source ID")
		pluginFlags.BoolVar(&config.Disabled, "disable", false, "disable Kubernetes source discovery")
	})
}
