// Package cli wires the tattlr subcommands together.
package cli

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/report"
	"github.com/kaygaaf/tattlr/internal/rules"
	"github.com/kaygaaf/tattlr/internal/scan"
	"github.com/kaygaaf/tattlr/internal/trap"
)

// Version is set at build time.
var Version = "dev"

// Env is everything the commands touch from the outside world, so tests can
// swap it out.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Home   string
	Now    time.Time
	TTY    bool // stdout is a terminal
	InTTY  bool // stdin is a terminal
	Getenv func(string) string
	Bin    string // absolute path of this tattlr binary
}

// OSEnv builds an Env from the real process.
func OSEnv() Env {
	return Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Home: scan.Home(), Now: time.Now(),
		TTY: isTTY(os.Stdout), InTTY: isTTY(os.Stdin), Getenv: os.Getenv, Bin: selfPath()}
}

func selfPath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	return p
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

const usage = `tattlr: keep YOLO mode, get a tattletale.

Usage:
  tattlr scan [flags]      read local agent logs and print a rap sheet
  tattlr trap [flags]      plant fake credentials that agents should never touch
  tattlr protect install   hook tattlr into Claude Code, Codex and Cursor so it can block live
  tattlr protect status    show what is hooked up and what tattlr stopped lately
  tattlr protect uninstall take the hooks back out
  tattlr hook <agent>      what the agent hooks call (reads one tool call as JSON on stdin)
  tattlr rules             list what tattlr looks for
  tattlr version

Run "tattlr <command> -h" for flags.
`

// Run executes tattlr with args (without the program name) and returns the
// exit code.
func Run(args []string, env Env) int {
	if env.Getenv == nil {
		env.Getenv = func(string) string { return "" }
	}
	if len(args) == 0 {
		args = []string{"scan"}
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:], env)
	case "trap":
		return runTrap(args[1:], env)
	case "rules":
		return runRules(env)
	case "protect":
		return runProtect(args[1:], env)
	case "hook":
		return runHook(args[1:], env)
	case "version", "--version", "-v":
		fmt.Fprintln(env.Stdout, "tattlr", Version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(env.Stdout, usage)
		return 0
	default:
		if strings.HasPrefix(args[0], "-") {
			return runScan(args, env)
		}
		fmt.Fprintf(env.Stderr, "tattlr: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

type multi []string

func (m *multi) String() string { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*m = append(*m, p)
		}
	}
	return nil
}

func runScan(args []string, env Env) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	var agents multi
	since := fs.String("since", "", "only look at activity after this: 24h, 7d, 2w or 2026-10-01")
	fs.Var(&agents, "agent", "only these agents (claude, codex, gemini, openclaw, cursor); repeat or comma separate")
	project := fs.String("project", "", "only projects whose path contains this")
	asJSON := fs.Bool("json", false, "print JSON instead of the rap sheet")
	card := fs.String("card", "", "also write a shareable card to this file (.svg, or .png if rsvg-convert, resvg or Chrome is installed)")
	noColor := fs.Bool("no-color", false, "turn off colors")
	home := fs.String("home", env.Home, "home folder to look in")
	top := fs.Int("top", 8, "how many offenses to list")
	moments := fs.Int("moments", 5, "how many worst moments to list")
	failOn := fs.String("fail-on", "", "exit 1 if anything at or above this severity is found (low, medium, high, critical)")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Usage: tattlr scan [flags]\n\nReads local agent logs. Nothing is uploaded.\n\nFlags:")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	o := scan.Options{Home: *home, Project: *project, Now: env.Now}
	if *since != "" {
		t, err := ParseSince(*since, env.Now)
		if err != nil {
			fmt.Fprintln(env.Stderr, "tattlr:", err)
			return 2
		}
		o.Since = t
	}
	for _, a := range agents {
		n, ok := agentAlias(a)
		if !ok {
			fmt.Fprintf(env.Stderr, "tattlr: unknown agent %q (try: %s)\n", a, strings.Join(event.AllAgents, ", "))
			return 2
		}
		o.Agents = append(o.Agents, n)
	}
	var threshold rules.Severity
	if *failOn != "" {
		if threshold = rules.ParseSeverity(*failOn); threshold == 0 {
			fmt.Fprintf(env.Stderr, "tattlr: unknown severity %q\n", *failOn)
			return 2
		}
	}

	res, err := scan.Run(o)
	if err != nil {
		fmt.Fprintln(env.Stderr, "tattlr:", err)
		return 1
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(env.Stderr, "tattlr: warning:", w)
	}
	if *asJSON {
		if err := report.JSON(env.Stdout, res); err != nil {
			fmt.Fprintln(env.Stderr, "tattlr:", err)
			return 1
		}
	} else {
		color := env.TTY && !*noColor && env.Getenv("NO_COLOR") == "" && env.Getenv("TERM") != "dumb"
		if env.Getenv("FORCE_COLOR") != "" && !*noColor {
			color = true
		}
		report.Text(env.Stdout, res, report.TextOptions{Color: color, Top: *top, Moments: *moments})
	}
	if *card != "" {
		if err := report.WriteCard(*card, res, nil); err != nil {
			fmt.Fprintln(env.Stderr, "tattlr:", err)
			return 1
		}
		if !*asJSON {
			fmt.Fprintf(env.Stdout, " Card saved to %s\n\n", *card)
		}
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

func agentAlias(a string) (string, bool) {
	switch strings.ToLower(a) {
	case "claude", "claude-code", "claudecode", "cc":
		return event.AgentClaude, true
	case "codex", "codex-cli":
		return event.AgentCodex, true
	case "gemini", "gemini-cli":
		return event.AgentGemini, true
	case "openclaw", "claw":
		return event.AgentOpenClaw, true
	case "cursor", "cursor-agent", "cursor-cli":
		return event.AgentCursor, true
	}
	return "", false
}

var relRe = regexp.MustCompile(`^(\d+)\s*(m|min|h|d|w|mo|y)$`)

// ParseSince accepts 30m, 24h, 7d, 2w, 3mo, 1y, a date or an RFC 3339 time.
func ParseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if m := relRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		switch m[2] {
		case "m", "min":
			return now.Add(-time.Duration(n) * time.Minute), nil
		case "h":
			return now.Add(-time.Duration(n) * time.Hour), nil
		case "d":
			return now.AddDate(0, 0, -n), nil
		case "w":
			return now.AddDate(0, 0, -7*n), nil
		case "mo":
			return now.AddDate(0, -n, 0), nil
		case "y":
			return now.AddDate(-n, 0, 0), nil
		}
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, strings.ToUpper(s)); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("can't read --since %q; use something like 24h, 7d, 2w or 2026-10-01", s)
}

func runTrap(args []string, env Env) int {
	fs := flag.NewFlagSet("trap", flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	var envDirs multi
	yes := fs.Bool("yes", false, "don't ask, just plant")
	remove := fs.Bool("remove", false, "remove every canary tattlr planted")
	list := fs.Bool("list", false, "show planted canaries")
	ssh := fs.Bool("ssh", false, "also plant a decoy SSH key at ~/.ssh/id_ed25519_backup")
	fs.Var(&envDirs, "env", "also drop a decoy .env in this folder (only if it has none); repeatable")
	home := fs.String("home", env.Home, "home folder to plant in")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, `Usage: tattlr trap [flags]

Plants fake credentials that no agent has a reason to touch:
  a [tattlr-canary] profile in ~/.aws/credentials
  a decoy ~/.config/tattlr/decoy/.env
The keys are random and work nowhere. "tattlr scan" flags any session that
reads them or uses them. Undo it all with "tattlr trap --remove".

Flags:`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	out := env.Stdout

	if *list {
		reg, err := trap.Load(*home)
		if err != nil {
			fmt.Fprintln(env.Stderr, "tattlr:", err)
			return 1
		}
		if len(reg.Traps) == 0 {
			fmt.Fprintln(out, "No canaries planted. Run `tattlr trap` to plant some.")
			return 0
		}
		for _, t := range reg.Traps {
			fmt.Fprintf(out, "%-12s %s  (planted %s)\n", t.Kind, t.Path, t.Planted.Local().Format("2006-01-02 15:04 MST"))
		}
		return 0
	}

	if *remove {
		msgs, err := trap.Remove(*home)
		for _, m := range msgs {
			fmt.Fprintln(out, m)
		}
		if err != nil {
			fmt.Fprintln(env.Stderr, "tattlr:", err)
			return 1
		}
		if len(msgs) == 0 {
			fmt.Fprintln(out, "No canaries to remove.")
		}
		return 0
	}

	opts := trap.Options{SSH: *ssh, EnvDirs: envDirs}
	plans, err := trap.Preview(*home, opts)
	if err != nil {
		fmt.Fprintln(env.Stderr, "tattlr:", err)
		return 1
	}
	todo := 0
	fmt.Fprintln(out, "tattlr will plant these fake credentials:")
	for _, p := range plans {
		if p.Skip != "" {
			fmt.Fprintf(out, "  skip  %s (%s)\n", p.Path, p.Skip)
			continue
		}
		todo++
		fmt.Fprintf(out, "  %s: %s\n", p.Path, p.Action)
	}
	if todo == 0 {
		fmt.Fprintln(out, "Nothing new to plant.")
		return 0
	}
	fmt.Fprintln(out, "The keys are random and work nowhere. Nothing is sent anywhere. Undo with `tattlr trap --remove`.")
	if !*yes {
		if !env.InTTY {
			fmt.Fprintln(env.Stderr, "tattlr: not a terminal, so I can't ask. Re-run with --yes to plant.")
			return 1
		}
		fmt.Fprint(out, "Plant them? [y/N] ")
		line, _ := bufio.NewReader(env.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Fprintln(out, "Okay, nothing planted.")
			return 0
		}
	}
	planted, err := trap.Plant(*home, opts, env.Now)
	for _, t := range planted {
		fmt.Fprintf(out, "planted %s\n", t.Path)
	}
	if err != nil {
		fmt.Fprintln(env.Stderr, "tattlr:", err)
		return 1
	}
	fmt.Fprintf(out, "Done. %d canaries on record in %s\n", len(planted), trap.RegistryPath(*home))
	fmt.Fprintln(out, "From now on `tattlr scan` flags any session that reads or uses them.")
	return 0
}

func runRules(env Env) int {
	var ids []string
	for id := range rules.Catalog {
		ids = append(ids, id)
	}
	sortRules(ids)
	for _, id := range ids {
		r := rules.Catalog[id]
		fmt.Fprintf(env.Stdout, "%-9s %-12s %-16s %s\n", r.Severity, r.Category, r.ID, r.Title)
	}
	return 0
}

func sortRules(ids []string) {
	sort.Slice(ids, func(i, j int) bool {
		a, b := rules.Catalog[ids[i]], rules.Catalog[ids[j]]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return ids[i] < ids[j]
	})
}
