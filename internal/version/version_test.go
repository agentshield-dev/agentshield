package version

import (
	"runtime/debug"
	"testing"
)

func TestResolve(t *testing.T) {
	stamped := func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{Version: "(devel)"},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "abc123"},
				{Key: "vcs.modified", Value: "true"},
			},
		}, true
	}
	installed := func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, true
	}
	missing := func() (*debug.BuildInfo, bool) { return nil, false }

	for _, test := range []struct {
		name                    string
		version, commit         string
		read                    func() (*debug.BuildInfo, bool)
		wantVersion, wantCommit string
	}{
		{"ldflags win", "v0.1.0", "deadbeef", stamped, "v0.1.0", "deadbeef"},
		{"vcs fallback", "dev", "unknown", stamped, "dev", "abc123-dirty"},
		{"module version fallback", "dev", "unknown", installed, "v1.2.3", "unknown"},
		{"injected version keeps vcs commit", "v0.1.0", "unknown", stamped, "v0.1.0", "abc123-dirty"},
		{"no build info", "dev", "unknown", missing, "dev", "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			version, commit := resolve(test.version, test.commit, test.read)
			if version != test.wantVersion || commit != test.wantCommit {
				t.Fatalf("resolve = %q, %q; want %q, %q", version, commit, test.wantVersion, test.wantCommit)
			}
		})
	}
}
