package report

import (
	"fmt"
	"io"
)

// Welcome is what a first run on a machine with no agent logs prints: what
// tattlr is, in about 30 seconds of reading, and three things to try.
func Welcome(w io.Writer, home string, color bool) {
	p := painter{color}
	bold := func(s string) string { return p.c("1", s) }
	dim := func(s string) string { return p.c("2", s) }
	cmd := func(c, what string) {
		fmt.Fprintf(w, "   %s %s\n", p.c("1;36", fmt.Sprintf("%-23s", c)), what)
	}
	where := tilde(home, home)

	fmt.Fprintln(w)
	fmt.Fprintf(w, " %s  %s\n", p.c("1;97;41", " TATTLR "), bold("keep YOLO mode, get a tattletale"))
	fmt.Fprintln(w)
	fmt.Fprintf(w, " Nothing to tell on yet. No Claude Code, Codex, Gemini CLI, OpenClaw or\n Cursor logs under %s.\n", where)
	fmt.Fprintln(w)
	fmt.Fprintln(w, " Here's the idea. Your coding agents log every command they run. tattlr")
	fmt.Fprintln(w, " reads those logs and points out the sketchy ones: reading your SSH keys,")
	fmt.Fprintln(w, " curl | sh, force pushes, sending secrets somewhere. It can also hook into")
	fmt.Fprintln(w, " the agents and block that stuff before it runs, so you can leave approvals")
	fmt.Fprintln(w, " off and still sleep. It all runs on this machine. No account, no uploads.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, bold(" Try this:"))
	cmd("tattlr trap", "plant fake keys that no agent should touch")
	cmd("tattlr protect install", "block risky calls live, in every agent")
	cmd("tattlr scan", "run again once your agent has had a go")
	fmt.Fprintln(w)
	fmt.Fprintln(w, dim(" Logs somewhere else? tattlr scan --home /path. Everything else: tattlr help"))
	fmt.Fprintln(w)
}
