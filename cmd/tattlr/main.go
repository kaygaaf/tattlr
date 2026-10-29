// Command tattlr reads local AI coding agent logs and tells on them.
package main

import (
	"os"
	"runtime/debug"
	"strings"

	"github.com/kaygaaf/tattlr/internal/cli"
)

// version is set by GoReleaser. `go install ...@v0.1.0` leaves it alone, so
// fall back to the module version Go recorded in the binary.
var version = "dev"

func main() {
	mod := ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		mod = bi.Main.Version
	}
	cli.Version = resolveVersion(version, mod)
	os.Exit(cli.Run(os.Args[1:], cli.OSEnv()))
}

// resolveVersion picks the version to print. Release builds and go install
// both come out as "0.1.0", without the leading v that Go module versions have.
func resolveVersion(ldflag, module string) string {
	v := ldflag
	if v == "dev" && module != "" && module != "(devel)" {
		v = module
	}
	return strings.TrimPrefix(v, "v")
}
