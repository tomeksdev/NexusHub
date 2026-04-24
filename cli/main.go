package main

import "github.com/tomeksdev/NexusHub/cli/cmd"

// Populated via -ldflags at release time. Kept here (not in cmd/) so
// main owns the build-time identity and the cmd package stays testable.
var (
	buildVersion = "dev"
	buildCommit  = "unknown"
)

func main() {
	cmd.SetBuildInfo(buildVersion, buildCommit)
	cmd.Execute()
}
