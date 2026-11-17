package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kaygaaf/tattlr/internal/report"
	"github.com/kaygaaf/tattlr/internal/rules"
	"github.com/kaygaaf/tattlr/internal/workflows"
)

func runWorkflows(args []string, env Env) int {
	fs := flag.NewFlagSet("workflows", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	format := fs.String("format", "text", "output format: text, json, sarif or markdown")
	failOn := fs.String("fail-on", "", "exit 1 if anything at or above this severity is found (low, medium, high, critical)")
	noColor := fs.Bool("no-color", false, "turn off colors")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Usage: tattlr workflows [flags] [path]\n\n"+
			"Reads .github/workflows in path (default: the current folder) and flags\n"+
			"agent steps that people outside the repo can steer.\n\nFlags:")
		fs.PrintDefaults()
	}
	// allow the path before the flags too
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
		fmt.Fprintln(env.Stderr, "tattlr: workflows takes one path")
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

	res, err := workflows.Check(path)
	if err != nil {
		fmt.Fprintln(env.Stderr, "tattlr:", err)
		return 1
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(env.Stderr, "tattlr: warning:", w)
	}
	switch *format {
	case "json":
		err = report.WorkflowsJSON(env.Stdout, res)
	case "sarif":
		root, _ := os.Getwd()
		err = report.WorkflowsSARIF(env.Stdout, res, report.SARIFOptions{Version: Version, SrcRoot: root})
	case "markdown":
		report.WorkflowsMarkdown(env.Stdout, res)
	default:
		color := env.TTY && !*noColor && env.Getenv("NO_COLOR") == "" && env.Getenv("TERM") != "dumb"
		if f := env.Getenv("FORCE_COLOR"); f != "" && f != "0" && !*noColor {
			color = true
		}
		report.WorkflowsText(env.Stdout, res, color)
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
