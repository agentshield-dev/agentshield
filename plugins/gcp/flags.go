package gcp

import (
	"fmt"
	"strings"
	"time"

	"github.com/agentshield-dev/agentshield/pkg/discovery"
	"github.com/spf13/pflag"
)

// CLIConfig contains GCP-owned runtime options.
type CLIConfig struct {
	Project      string
	Region       string
	PollInterval string
}

// RegisterFlags registers GCP flags in the gcp-* namespace.
func (config *CLIConfig) RegisterFlags(flags *pflag.FlagSet) error {
	return discovery.RegisterPluginFlags(flags, PluginID, func(pluginFlags *discovery.PluginFlags) {
		pluginFlags.StringVar(&config.Project, "project", "", "enable GCP Compute Engine discovery in this project ID or number")
		pluginFlags.StringVar(&config.Region, "region", "", "limit zonal and regional GCP resources to this region")
		pluginFlags.StringVar(&config.PollInterval, "poll-interval", defaultPollInterval.String(), "GCP inventory polling interval")
	})
}

// PollDuration parses PollInterval. It must be positive.
func (config CLIConfig) PollDuration() (time.Duration, error) {
	value, err := time.ParseDuration(strings.TrimSpace(config.PollInterval))
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid --gcp-poll-interval %q: use a positive duration such as 5m", config.PollInterval)
	}
	return value, nil
}
