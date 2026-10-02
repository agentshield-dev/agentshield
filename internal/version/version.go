// Package version reports which build of AgentShield is running. Release and
// image builds set Version and Commit with
//
//	-ldflags "-X github.com/agentshield-dev/agentshield/internal/version.Version=v1.2.3
//	          -X github.com/agentshield-dev/agentshield/internal/version.Commit=<sha>"
//
// Other builds fall back to the module version and VCS revision that the Go
// toolchain stamps into the binary, when it has them.
package version

import (
	"fmt"
	"runtime/debug"
)

// Version and Commit are set at link time; see the package documentation.
var (
	Version = "dev"
	Commit  = "unknown"
)

// String returns "<version> (commit <commit>)" for --version output and the
// startup log line.
func String() string {
	version, commit := resolve(Version, Commit, debug.ReadBuildInfo)
	return fmt.Sprintf("%s (commit %s)", version, commit)
}

// resolve prefers link-time values and fills defaults from build info, which
// `go install module@version` and builds inside a Git checkout record.
func resolve(version, commit string, readBuildInfo func() (*debug.BuildInfo, bool)) (string, string) {
	if version != "dev" && commit != "unknown" {
		return version, commit
	}
	info, ok := readBuildInfo()
	if !ok {
		return version, commit
	}
	if version == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}
	if commit == "unknown" {
		var revision string
		var modified bool
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.modified":
				modified = setting.Value == "true"
			}
		}
		if revision != "" {
			commit = revision
			if modified {
				commit += "-dirty"
			}
		}
	}
	return version, commit
}
