package discovery

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func TestPluginFlagsRequireNamespaceAndRejectCollisions(t *testing.T) {
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	var first, second string
	if err := RegisterPluginFlags(flags, "kubernetes", func(pluginFlags *PluginFlags) {
		pluginFlags.StringVar(&first, "cluster-id", "local", "cluster")
	}); err != nil {
		t.Fatal(err)
	}
	if flags.Lookup("kubernetes-cluster-id") == nil || flags.Lookup("cluster-id") != nil {
		t.Fatal("plugin flag was not registered exclusively in its namespace")
	}
	if err := RegisterPluginFlags(flags, "kubernetes", func(pluginFlags *PluginFlags) {
		pluginFlags.StringVar(&second, "cluster-id", "other", "cluster")
	}); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("duplicate plugin flag error = %v, want collision", err)
	}
	if err := RegisterPluginFlags(flags, "istio", func(pluginFlags *PluginFlags) {
		pluginFlags.StringVar(&second, "cluster_id", "other", "cluster")
	}); err == nil {
		t.Fatal("accepted a flag suffix outside the namespace naming convention")
	}
}
