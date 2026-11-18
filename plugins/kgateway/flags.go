package kgateway

import (
	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/spf13/pflag"
)

// CLIConfig contains kgateway-owned runtime options.
type CLIConfig struct {
	ClusterID       string
	NetworkID       string
	SourceID        string
	ControllerNames string
}

// RegisterFlags registers kgateway flags in the kgateway-* namespace.
func (config *CLIConfig) RegisterFlags(flags *pflag.FlagSet) error {
	return discovery.RegisterPluginFlags(flags, PluginID, func(pluginFlags *discovery.PluginFlags) {
		pluginFlags.StringVar(&config.ClusterID, "cluster-id", "local", "stable Kubernetes authority ID used by kgateway")
		pluginFlags.StringVar(&config.NetworkID, "network-id", "", "stable network realm authority ID for static Backend hosts; defaults to this plugin's cluster ID")
		pluginFlags.StringVar(&config.SourceID, "source-id", "kubernetes/local", "stable kgateway source ID")
		pluginFlags.StringVar(&config.ControllerNames, "controller-names", DefaultControllerName, "comma-separated GatewayClass controller names whose Gateways get kgateway coverage facets")
	})
}
