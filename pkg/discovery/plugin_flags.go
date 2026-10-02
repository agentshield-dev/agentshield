package discovery

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/pflag"
)

var pluginFlagSuffixPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// PluginFlags registers flags in a plugin-owned namespace. Plugins receive
// only this wrapper, so every registered name must be prefixed with the
// plugin's ID.
type PluginFlags struct {
	flags  *pflag.FlagSet
	prefix string
	err    error
}

// RegisterPluginFlags runs register with a namespace-bound flag registrar.
// It rejects invalid plugin IDs and any collision with a flag already present.
func RegisterPluginFlags(flags *pflag.FlagSet, pluginID string, register func(*PluginFlags)) error {
	if flags == nil || register == nil {
		return fmt.Errorf("plugin flags and registrar are required")
	}
	if pluginID == "" || strings.TrimSpace(pluginID) != pluginID || strings.ContainsAny(pluginID, " \t\n") {
		return fmt.Errorf("invalid plugin flag namespace %q", pluginID)
	}
	registrar := &PluginFlags{flags: flags, prefix: pluginID + "-"}
	register(registrar)
	return registrar.err
}

// StringVar adds a string flag below the plugin namespace.
func (flags *PluginFlags) StringVar(target *string, name, value, usage string) {
	flags.add(name, func(fullName string) { flags.flags.StringVar(target, fullName, value, usage) })
}

// BoolVar adds a boolean flag below the plugin namespace.
func (flags *PluginFlags) BoolVar(target *bool, name string, value bool, usage string) {
	flags.add(name, func(fullName string) { flags.flags.BoolVar(target, fullName, value, usage) })
}

func (flags *PluginFlags) add(name string, register func(string)) {
	if flags.err != nil {
		return
	}
	if !pluginFlagSuffixPattern.MatchString(name) {
		flags.err = fmt.Errorf("invalid plugin flag name %q: use a lowercase suffix without a namespace", name)
		return
	}
	fullName := flags.prefix + name
	if flags.flags.Lookup(fullName) != nil {
		flags.err = fmt.Errorf("plugin flag collision: --%s is already registered", fullName)
		return
	}
	register(fullName)
}
