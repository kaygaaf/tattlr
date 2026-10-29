// Command tattlr reads local AI coding agent logs and tells on them.
package main

import (
	"os"
	"runtime/debug"

	"github.com/kaygaaf/tattlr/internal/cli"
)

// version is set by GoReleaser. `go install ...@v0.1.0` leaves it alone, so
// fall back to the module version Go recorded in the binary.
var version = "dev"

func main() {
	cli.Version = resolveVersion(version)
	os.Exit(cli.Run(os.Args[1:], cli.OSEnv()))
}

func resolveVersion(v string) string {
	if v != "dev" {
		return v
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return v
}
