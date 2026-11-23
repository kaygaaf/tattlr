package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kaygaaf/tattlr/internal/repo"
	"github.com/kaygaaf/tattlr/internal/report"
	"github.com/kaygaaf/tattlr/internal/rules"
)

func runRepo(args []string, env Env) int {
	fs := flag.NewFlagSet("repo", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	format := fs.String("format", "text", "output format: text, json, sarif or markdown")
	failOn := fs.String("fail-on", "", "exit 1 if anything at or above this severity is found (low, medium, high, critical)")
	noColor := fs.Bool("no-color", false, "turn off colors")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Usage: tattlr repo [flags] [path]\n\n"+
			"Reads a checkout (default: the current folder) and flags session-start\n"+
			"hooks, folder-open tasks, local MCP commands, and instruction files that\n"+
			"tell an agent to run something without looking. It does not run anything\n"+
			"in the repo.\n\nFlags:")
		fs.PrintDefaults()
	}
	var path string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		path, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	switch {
	case fs.NArg() > 1 || (fs.NArg() == 1 && path != ""):
		fmt.Fprintln(env.Stderr, "tattlr: repo takes one path")
		return 2
	case fs.NArg() == 1:
		path = fs.Arg(0)
	case path == "":
		path = "."
	}
	switch *format = strings.ToLower(*format); *format {
	case "text", "json", "sarif":
	case "markdown", "md":
		*format = "markdown"
	default:
		fmt.Fprintf(env.Stderr, "tattlr: unknown format %q (try text, json, sarif or markdown)\n", *format)
		return 2
	}
	var threshold rules.Severity
	if *failOn != "" {
		if threshold = rules.ParseSeverity(*failOn); threshold == 0 {
			fmt.Fprintf(env.Stderr, "tattlr: unknown severity %q\n", *failOn)
			return 2
		}
	}

	res, err := repo.Check(path)
	if err != nil {
		fmt.Fprintln(env.Stderr, "tattlr:", err)
		return 1
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(env.Stderr, "tattlr: warning:", w)
	}
	switch *format {
	case "json":
		err = report.RepoJSON(env.Stdout, res)
	case "sarif":
		root, _ := os.Getwd()
		err = report.RepoSARIF(env.Stdout, res, report.SARIFOptions{Version: Version, SrcRoot: root})
	case "markdown":
		report.RepoMarkdown(env.Stdout, res)
	default:
		color := env.TTY && !*noColor && env.Getenv("NO_COLOR") == "" && env.Getenv("TERM") != "dumb"
		if f := env.Getenv("FORCE_COLOR"); f != "" && f != "0" && !*noColor {
			color = true
		}
		report.RepoText(env.Stdout, res, color)
	}
	if err != nil {
		fmt.Fprintln(env.Stderr, "tattlr:", err)
		return 1
	}
	if threshold > 0 {
		for _, f := range res.Findings {
			if f.Severity >= threshold {
				return 1
			}
		}
	}
	return 0
}
