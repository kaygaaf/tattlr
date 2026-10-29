// Command tattlr reads local AI coding agent logs and tells on them.
package main

import (
	"os"

	"github.com/kaygaaf/tattlr/internal/cli"
)

var version = "dev"

func main() {
	cli.Version = version
	os.Exit(cli.Run(os.Args[1:], cli.OSEnv()))
}
