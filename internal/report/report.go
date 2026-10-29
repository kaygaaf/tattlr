// Package report renders scan results as a terminal rap sheet, JSON, or an
// SVG card.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kaygaaf/tattlr/internal/rules"
	"github.com/kaygaaf/tattlr/internal/scan"
)

// JSON writes the result as indented JSON.
func JSON(w io.Writer, r *scan.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// TextOptions controls the terminal output.
type TextOptions struct {
	Color   bool
	Top     int // offenses to show
	Moments int // worst moments to show
	Width   int
	Loc     *time.Location
}

type painter struct{ on bool }

func (p painter) c(code, s string) string {
	if !p.on || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p painter) sev(s rules.Severity, text string) string {
	switch s {
	case rules.Critical:
		return p.c("1;38;5;231;48;5;160", text)
	case rules.High:
		return p.c("1;31", text)
	case rules.Medium:
		return p.c("33", text)
	default:
		return p.c("2", text)
	}
}

var sevLabel = map[rules.Severity]string{rules.Critical: "CRIT", rules.High: "HIGH", rules.Medium: "MED ", rules.Low: "LOW "}

// Text writes the colored rap sheet.
func Text(w io.Writer, r *scan.Result, o TextOptions) {
	if o.Top == 0 {
		o.Top = 8
	}
	if o.Moments == 0 {
		o.Moments = 5
	}
	if o.Width == 0 {
		o.Width = 100
	}
	if o.Loc == nil {
		o.Loc = time.Local
	}
	p := painter{o.Color}
	bold := func(s string) string { return p.c("1", s) }
	dim := func(s string) string { return p.c("2", s) }

	if r.ToolCalls == 0 && r.Protect == nil && r.Logs == 0 {
		Welcome(w, r.HomeDir(), o.Color)
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, " %s  %s  %s\n", p.c("1;38;5;231;48;5;160", " TATTLR "), bold("RAP SHEET"), dim(summaryLine(r, o.Loc, false)))
	fmt.Fprintln(w)

	if r.ToolCalls == 0 {
		protectSection(w, r, o, p)
		switch {
		case r.Protect != nil && r.Logs == 0:
			fmt.Fprintln(w, " No agent session logs found, only the live hook log above.")
		case r.Logs > 0:
			fmt.Fprintln(w, " Nothing matched. Try dropping --since, --agent or --project.")
		default:
			fmt.Fprintln(w, " No agent activity found.")
		}
		fmt.Fprintln(w, dim(" Looked for Claude Code, Codex, Gemini CLI, OpenClaw and Cursor logs under "+tilde(r.HomeDir(), r.HomeDir())))
		fmt.Fprintln(w)
		return
	}

	for _, line := range headline(r) {
		fmt.Fprintf(w, " %s\n", line)
	}
	fmt.Fprintln(w)

	// Per-agent table.
	fmt.Fprintf(w, " %s\n", bold(fmt.Sprintf("%-13s %8s %6s %8s %5s %5s %5s %5s %6s  %s",
		"AGENT", "SESSIONS", "CALLS", "FLAGGED", "CRIT", "HIGH", "MED", "LOW", "SCORE", "VERDICT")))
	for _, a := range r.Agents {
		cell := func(n int, s rules.Severity) string {
			txt := fmt.Sprintf("%5d", n)
			if n == 0 {
				return dim(txt)
			}
			return p.sev(s, txt)
		}
		verdict := a.Verdict
		switch {
		case a.Score >= 120:
			verdict = p.c("1;31", verdict)
		case a.Score >= 50:
			verdict = p.c("31", verdict)
		case a.Score == 0:
			verdict = p.c("32", verdict)
		}
		fmt.Fprintf(w, " %-13s %8d %6d %8d %s %s %s %s %6d  %s\n", a.Agent, a.Sessions, a.ToolCalls, a.Flagged,
			cell(a.BySeverity["critical"], rules.Critical), cell(a.BySeverity["high"], rules.High),
			cell(a.BySeverity["medium"], rules.Medium), cell(a.BySeverity["low"], rules.Low), a.Score, verdict)
	}
	fmt.Fprintln(w)
	protectSection(w, r, o, p)

	if len(r.Offenses) == 0 {
		return
	}

	fmt.Fprintf(w, " %s\n", bold("TOP OFFENSES"))
	for i, off := range r.Offenses {
		if i == o.Top {
			fmt.Fprintf(w, " %s\n", dim(fmt.Sprintf("  ...and %d more kinds, see --json", len(r.Offenses)-o.Top)))
			break
		}
		fmt.Fprintf(w, " %4dx  %s  %-42s %s\n", off.Count, p.sev(off.Severity, sevLabel[off.Severity]), off.Title,
			dim(strings.Join(off.Agents, ", ")))
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, " %s\n", bold("WORST MOMENTS"))
	for i, m := range r.Moments {
		if i == o.Moments {
			break
		}
		e := m.Event
		when := "unknown time"
		if !e.Time.IsZero() {
			when = e.Time.In(o.Loc).Format("Jan 02 15:04")
		}
		proj := tilde(e.Project, r.HomeDir())
		if proj == "" {
			proj = "unknown project"
		}
		fmt.Fprintf(w, " %s  %s  %s  %s\n", p.sev(m.Severity, sevLabel[m.Severity]), when, bold(e.Agent), dim(proj))
		var titles string
		const tag = "  (tried it, tattlr blocked it)"
		if m.Blocked {
			titles = joinFit(m.Titles, o.Width-7-len(tag)) + p.c("1;32", tag)
		} else {
			titles = joinFit(m.Titles, o.Width-7)
		}
		fmt.Fprintf(w, "       %s\n", titles)
		fmt.Fprintf(w, "       %s\n", p.c("36", clip(tilde(m.Evidence, r.HomeDir()), o.Width-7)))
	}
	fmt.Fprintln(w)
	for _, line := range footer(r) {
		fmt.Fprintf(w, " %s\n", dim(line))
	}
	fmt.Fprintln(w)
}

// protectSection shows what the live hooks stopped, newest first.
func protectSection(w io.Writer, r *scan.Result, o TextOptions, p painter) {
	ps := r.Protect
	if ps == nil {
		return
	}
	bold := func(s string) string { return p.c("1", s) }
	dim := func(s string) string { return p.c("2", s) }
	sum := fmt.Sprintf("%s checked live, %d blocked, %d asked", plural(ps.Checked, "call"), ps.Blocked, ps.Asked)
	if ps.Would > 0 {
		sum += fmt.Sprintf(", %d would have been blocked (observe mode)", ps.Would)
	}
	fmt.Fprintf(w, " %s  %s\n", bold("TATTLR STOPPED"), dim(sum))
	for i, e := range ps.Stopped {
		if i == o.Moments {
			fmt.Fprintf(w, " %s\n", dim(fmt.Sprintf("  ...and %d more, see --json", len(ps.Stopped)-o.Moments)))
			break
		}
		label, color := "BLOCKED", "1;31"
		switch {
		case e.Decision == "ask":
			label, color = "ASKED  ", "33"
		case e.Decision != "deny":
			label, color = "WOULD  ", "2"
		}
		var titles []string
		for _, id := range e.Rules {
			if info, ok := rules.Catalog[id]; ok {
				titles = append(titles, info.Title)
			}
		}
		fmt.Fprintf(w, " %s  %s  %s  %s\n", p.c(color, label), e.Time.In(o.Loc).Format("Jan 02 15:04"), bold(e.Agent),
			joinFit(titles, o.Width-27-len(e.Agent)))
		fmt.Fprintf(w, "          %s\n", p.c("36", clip(tilde(e.Evidence, r.HomeDir()), o.Width-10)))
	}
	fmt.Fprintln(w)
}

func summaryLine(r *scan.Result, loc *time.Location, flagged bool) string {
	parts := []string{plural(r.Sessions, "session"), plural(r.ToolCalls, "tool call")}
	if flagged {
		parts = append(parts, plural(r.Flagged, "flagged call"))
	}
	if !r.First.IsZero() {
		a, b := r.First.In(loc), r.Last.In(loc)
		switch {
		case a.Format("2006-01-02") == b.Format("2006-01-02"):
			parts = append(parts, b.Format("Jan 2 2006"))
		case a.Year() == b.Year():
			parts = append(parts, a.Format("Jan 2")+" to "+b.Format("Jan 2 2006"))
		default:
			parts = append(parts, a.Format("Jan 2 2006")+" to "+b.Format("Jan 2 2006"))
		}
	}
	return strings.Join(parts, ", ")
}

// footer is the privacy note plus at most one nudge, so the end of the
// sheet stays short.
func footer(r *scan.Result) []string {
	out := []string{fmt.Sprintf("Read %s on this machine. Nothing was uploaded. Secrets in commands are masked.", plural(r.Logs, "log file"))}
	switch {
	case r.Protect == nil:
		out = append(out, "Next: `tattlr protect install` blocks this stuff before it runs. YOLO mode stays on.")
	case r.Canaries == 0:
		out = append(out, "Next: `tattlr trap` plants fake keys, so a snooping agent gets caught in the act.")
	default:
		out = append(out, "Share it: `tattlr scan --card card.png` makes an image with no paths or commands on it.")
	}
	return out
}

// headline is the one or two lines people screenshot: who is worst and the
// worst thing that happened. Dry on purpose.
func headline(r *scan.Result) []string {
	if r.Flagged == 0 {
		return []string{fmt.Sprintf("%s, nothing sketchy. Suspiciously well behaved.", plural(r.ToolCalls, "tool call"))}
	}
	out := []string{fmt.Sprintf("%d of %s looked sketchy.", r.Flagged, plural(r.ToolCalls, "tool call"))}
	if len(r.Agents) > 0 && r.Agents[0].Score > 0 {
		a := r.Agents[0]
		out[0] += fmt.Sprintf(" Most wanted: %s (%s).", a.Agent, a.Verdict)
	}
	attempt := false
	if len(r.Offenses) > 0 {
		attempt = onlyAttempts(r, r.Offenses[0].Rule)
		if q := quip(r.Offenses[0], attempt); q != "" {
			out = append(out, q)
		}
	}
	if ps := r.Protect; ps != nil && ps.Blocked > 0 && !attempt {
		out = append(out, fmt.Sprintf("tattlr blocked %s before %s ran.", plural(ps.Blocked, "call"), map[bool]string{true: "it", false: "they"}[ps.Blocked == 1]))
	}
	return out
}

// onlyAttempts reports whether every worst moment that tripped rule was
// blocked by the live hook, so a quip should not claim it happened.
func onlyAttempts(r *scan.Result, rule string) bool {
	seen := false
	for _, m := range r.Moments {
		for _, id := range m.Rules {
			if id == rule {
				if !m.Blocked {
					return false
				}
				seen = true
			}
		}
	}
	return seen
}

func quip(o scan.Offense, blocked bool) string {
	if blocked {
		return fmt.Sprintf("Worst attempt: %s. Blocked before it ran.", strings.ToLower(o.Title[:1])+o.Title[1:])
	}
	times := timesWord(o.Count)
	switch o.Rule {
	case "canary":
		return fmt.Sprintf("The fake keys got read %s. Nobody asked for them.", times)
	case "tainted-egress":
		return "Something read the fake keys and then went online. Bold."
	case "exfil":
		return fmt.Sprintf("Secrets got sent over the network %s.", times)
	case "remote-code":
		return fmt.Sprintf("curl | sh happened %s.", times)
	case "disk-wipe":
		return "Something pointed dd at a disk. Check your backups, then your agent."
	case "self-protect":
		return "Something tried to switch tattlr off. Noted."
	case "secret-read":
		return fmt.Sprintf("Secret files got opened %s.", times)
	case "git-force-push":
		return fmt.Sprintf("Force pushed %s. Hope it was your branch.", times)
	}
	return ""
}

func timesWord(n int) string {
	switch n {
	case 1:
		return "once"
	case 2:
		return "twice"
	}
	return fmt.Sprintf("%d times", n)
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	if strings.HasSuffix(word, "y") && !strings.HasSuffix(word, "ey") {
		return fmt.Sprintf("%d %sies", n, strings.TrimSuffix(word, "y"))
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// homeRe only matches where a path starts, so /srv/home/.aws stays as is.
var homeRe = regexp.MustCompile(`(^|[\s'"=@:(])(?:/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)(/|\b)`)

// tilde shortens home paths to ~ so screenshots do not leak usernames.
// The scanned home comes first, since it can live anywhere.
func tilde(s, home string) string {
	if home = strings.TrimSuffix(home, "/"); home != "" && home != "/" {
		if s == home {
			return "~"
		}
		s = strings.ReplaceAll(s, home+"/", "~/")
		if strings.HasSuffix(s, " "+home) {
			s = strings.TrimSuffix(s, home) + "~"
		}
	}
	return homeRe.ReplaceAllString(s, "${1}~${2}")
}

// joinFit joins titles with commas and swaps whatever does not fit in n
// columns for "+N more", so lines never wrap mid word.
func joinFit(titles []string, n int) string {
	out := ""
	for i, t := range titles {
		next := t
		if out != "" {
			next = out + ", " + t
		}
		rest := len(titles) - i - 1
		budget := n
		if rest > 0 {
			budget -= len(fmt.Sprintf(" +%d more", rest))
		}
		if utf8.RuneCountInString(next) > budget && out != "" {
			return fmt.Sprintf("%s +%d more", out, len(titles)-i)
		}
		out = next
	}
	return out
}

func clip(s string, n int) string {
	if n < 10 {
		n = 10
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-3]) + "..."
}
