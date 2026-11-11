package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kaygaaf/tattlr/internal/scan"
)

// MarkdownOptions controls the Markdown output.
type MarkdownOptions struct {
	Top     int // offenses to show
	Moments int // worst moments to show
	Loc     *time.Location
}

var sevEmoji = map[string]string{"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

// Markdown writes a GitHub flavored summary: good for a CI job summary, a
// PR comment or an issue.
func Markdown(w io.Writer, r *scan.Result, o MarkdownOptions) {
	if o.Top == 0 {
		o.Top = 8
	}
	if o.Moments == 0 {
		o.Moments = 5
	}
	if o.Loc == nil {
		o.Loc = time.UTC
	}
	home := r.HomeDir()
	fmt.Fprintln(w, "## tattlr rap sheet")
	fmt.Fprintln(w)
	if r.ToolCalls == 0 {
		switch {
		case r.Logs > 0:
			fmt.Fprintf(w, "Read %s but nothing matched the filters.\n", plural(r.Logs, "log file"))
		default:
			fmt.Fprintf(w, "No agent logs found under `%s`. Nothing to report.\n", mdCode(home))
		}
		return
	}
	fmt.Fprintf(w, "%s.\n\n", summaryLine(r, o.Loc, true))
	for _, line := range headline(r) {
		fmt.Fprintf(w, "%s  \n", mdText(line))
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "| Agent | Sessions | Calls | Flagged | Crit | High | Med | Low | Score | Verdict |")
	fmt.Fprintln(w, "|---|--:|--:|--:|--:|--:|--:|--:|--:|---|")
	for _, a := range r.Agents {
		fmt.Fprintf(w, "| %s | %d | %d | %d | %d | %d | %d | %d | %d | %s |\n", a.Agent, a.Sessions, a.ToolCalls, a.Flagged,
			a.BySeverity["critical"], a.BySeverity["high"], a.BySeverity["medium"], a.BySeverity["low"], a.Score, a.Verdict)
	}
	fmt.Fprintln(w)

	if ps := r.Protect; ps != nil {
		fmt.Fprintf(w, "Live hooks checked %s: %d blocked, %d asked.\n\n", plural(ps.Checked, "call"), ps.Blocked, ps.Asked)
	}

	if len(r.Offenses) > 0 {
		fmt.Fprintln(w, "### Top offenses")
		fmt.Fprintln(w)
		fmt.Fprintln(w, "| Severity | Offense | Count | Agents |")
		fmt.Fprintln(w, "|---|---|--:|---|")
		for i, off := range r.Offenses {
			if i == o.Top {
				fmt.Fprintf(w, "\n...and %d more kinds. Run `tattlr scan --json` for all of them.\n", len(r.Offenses)-o.Top)
				break
			}
			s := off.Severity.String()
			fmt.Fprintf(w, "| %s %s | %s | %d | %s |\n", sevEmoji[s], s, mdText(off.Title), off.Count, strings.Join(off.Agents, ", "))
		}
		fmt.Fprintln(w)
	}

	if len(r.Moments) > 0 {
		fmt.Fprintln(w, "### Worst moments")
		fmt.Fprintln(w)
		for i, m := range r.Moments {
			if i == o.Moments {
				break
			}
			e := m.Event
			when := "unknown time"
			if !e.Time.IsZero() {
				when = e.Time.In(o.Loc).Format("Jan 02 15:04 MST")
			}
			s := m.Severity.String()
			line := fmt.Sprintf("- %s **%s** %s, %s", sevEmoji[s], s, mdText(e.Agent), when)
			if p := tilde(e.Project, home); p != "" {
				line += fmt.Sprintf(", `%s`", mdCode(p))
			}
			fmt.Fprintln(w, line+"  ")
			titles := mdText(strings.Join(m.Titles, ", "))
			if m.Blocked {
				titles += " (tried it, tattlr blocked it)"
			}
			fmt.Fprintf(w, "  %s  \n", titles)
			fmt.Fprintf(w, "  `%s`\n", mdCode(clip(tilde(m.Evidence, home), 160)))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "<sub>Read %s. Secrets in commands are masked. <a href=\"https://github.com/kaygaaf/tattlr\">tattlr</a></sub>\n",
		plural(r.Logs, "log file"))
}

// mdText keeps table cells and list items from breaking.
func mdText(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// mdCode makes s safe inside a single backtick code span outside a table.
func mdCode(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	return strings.ReplaceAll(s, "\n", " ")
}
