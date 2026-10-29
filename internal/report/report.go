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
		return p.c("1;97;41", text)
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

	fmt.Fprintln(w)
	fmt.Fprintf(w, " %s  %s\n", p.c("1;97;41", " TATTLR "), bold("RAP SHEET"))
	fmt.Fprintf(w, " %s\n", dim(summaryLine(r, o.Loc)))
	fmt.Fprintln(w)

	if r.ToolCalls == 0 {
		fmt.Fprintln(w, " No agent activity found. Either your agents are saints or tattlr looked in the wrong place.")
		fmt.Fprintln(w, dim(" Looked for Claude Code, Codex, Gemini CLI, OpenClaw and Cursor logs under "+tilde(r.HomeDir())))
		fmt.Fprintln(w)
		return
	}

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

	if len(r.Offenses) == 0 {
		fmt.Fprintln(w, p.c("32", " Nothing risky found. Suspiciously well behaved."))
		fmt.Fprintln(w)
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
		proj := tilde(e.Project)
		if proj == "" {
			proj = "unknown project"
		}
		fmt.Fprintf(w, " %s  %s  %s  %s\n", p.sev(m.Severity, sevLabel[m.Severity]), when, bold(e.Agent), dim(proj))
		fmt.Fprintf(w, "       %s\n", strings.Join(m.Titles, ", "))
		fmt.Fprintf(w, "       %s\n", p.c("36", clip(tilde(m.Evidence), o.Width-7)))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, " %s\n", dim(footer(r)))
	fmt.Fprintln(w)
}

func summaryLine(r *scan.Result, loc *time.Location) string {
	parts := []string{
		plural(r.Sessions, "session"),
		plural(r.ToolCalls, "tool call"),
		plural(r.Flagged, "flagged call"),
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

func footer(r *scan.Result) string {
	s := fmt.Sprintf("Read %s locally. Nothing left this machine. Secrets in commands are masked.", plural(r.Logs, "log file"))
	if r.Canaries == 0 {
		s += " Tip: run `tattlr trap` to plant fake keys and catch snoops."
	} else {
		s += fmt.Sprintf(" %s planted.", plural(r.Canaries, "canary"))
	}
	return s
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

var homeRe = regexp.MustCompile(`(?:/Users/[^/\s'"]+|/home/[^/\s'"]+|/root)(/|\b)`)

// tilde shortens home paths to ~ so screenshots do not leak usernames.
func tilde(s string) string {
	return homeRe.ReplaceAllString(s, "~$1")
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
