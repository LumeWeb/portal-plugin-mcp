package build

import (
	"go.lumeweb.com/portal/build"
)

// Build metadata variables populated at build time via -ldflags.
var (
	Version      string
	GitCommit    string
	GitBranch    string
	BuildTime    string
	GoVersion    string
	Platform     string
	Architecture string
)

// GetInfo returns build metadata information constructed from the build-time variables.
func GetInfo() build.BuildInfo {
	return build.New(Version, GitCommit, GitBranch, BuildTime, GoVersion, Platform, Architecture)
}
