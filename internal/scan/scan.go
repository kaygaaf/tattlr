// Package scan finds agent logs, runs the rules over every tool call and
// adds up the results.
package scan

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers"
	"github.com/kaygaaf/tattlr/internal/rules"
	"github.com/kaygaaf/tattlr/internal/trap"
)

// Options narrows a scan.
type Options struct {
	Home    string    // home dir to look in
	Since   time.Time // drop events before this; zero means everything
	Agents  []string  // only these agents; empty means all
	Project string    // only projects whose path contains this
	Now     time.Time
}

// AgentStats is one row of the rap sheet.
type AgentStats struct {
	Agent      string         `json:"agent"`
	Sessions   int            `json:"sessions"`
	ToolCalls  int            `json:"tool_calls"`
	Flagged    int            `json:"flagged_calls"`
	BySeverity map[string]int `json:"by_severity"`
	Score      int            `json:"score"`
	Verdict    string         `json:"verdict"`
}

// Offense counts how often a rule fired.
type Offense struct {
	Rule     string         `json:"rule"`
	Title    string         `json:"title"`
	Category string         `json:"category"`
	Severity rules.Severity `json:"severity"`
	Count    int            `json:"count"`
	Agents   []string       `json:"agents"`
}

// Moment is one flagged tool call with every rule it tripped.
type Moment struct {
	Severity rules.Severity `json:"severity"`
	Titles   []string       `json:"offenses"`
	Rules    []string       `json:"rules"`
	Evidence string         `json:"evidence"`
	Event    event.Event    `json:"event"`
}

// Result is everything a report needs.
type Result struct {
	Generated time.Time       `json:"generated"`
	Since     *time.Time      `json:"since,omitempty"`
	First     time.Time       `json:"first_event,omitempty"`
	Last      time.Time       `json:"last_event,omitempty"`
	Logs      int             `json:"logs_read"`
	Sessions  int             `json:"sessions"`
	ToolCalls int             `json:"tool_calls"`
	Flagged   int             `json:"flagged_calls"`
	Score     int             `json:"score"`
	Canaries  int             `json:"canaries_planted"`
	Agents    []AgentStats    `json:"agents"`
	Offenses  []Offense       `json:"offenses"`
	Moments   []Moment        `json:"moments"`
	Findings  []rules.Finding `json:"findings"`
	Warnings  []string        `json:"warnings,omitempty"`
	Home      string          `json:"-"`
}

// HomeDir is the home folder that was scanned.
func (r *Result) HomeDir() string { return r.Home }

// Run does the scan.
func Run(o Options) (*Result, error) {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	reg, err := trap.Load(o.Home)
	if err != nil {
		return nil, err
	}
	en := &rules.Engine{Home: o.Home, Canaries: reg.Canaries()}
	res := &Result{Generated: o.Now, Canaries: len(reg.Traps), Home: o.Home}
	if !o.Since.IsZero() {
		s := o.Since
		res.Since = &s
	}

	want := map[string]bool{}
	for _, a := range o.Agents {
		want[a] = true
	}
	stats := map[string]*AgentStats{}
	offenses := map[string]*Offense{}
	offAgents := map[string]map[string]bool{}

	for _, p := range parsers.All() {
		if len(want) > 0 && !want[p.Agent()] {
			continue
		}
		st := &AgentStats{Agent: p.Agent(), BySeverity: map[string]int{}}
		// Count sessions by id, not by file: Claude Code subagent
		// transcripts live in their own files but share the parent's id.
		seenSession := map[string]bool{}
		for _, f := range p.Discover(o.Home) {
			res.Logs++
			s, err := p.Parse(f)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %v", f, err))
			}
			if s == nil {
				continue
			}
			for _, e := range s.Events {
				if !o.Since.IsZero() && !e.Time.IsZero() && e.Time.Before(o.Since) {
					continue
				}
				if o.Project != "" && !strings.Contains(strings.ToLower(e.Project), strings.ToLower(o.Project)) {
					continue
				}
				if !seenSession[s.ID] {
					seenSession[s.ID] = true
					st.Sessions++
				}
				st.ToolCalls++
				if res.First.IsZero() || e.Time.Before(res.First) {
					res.First = e.Time
				}
				if e.Time.After(res.Last) {
					res.Last = e.Time
				}
				fs := en.Check(e)
				if len(fs) == 0 {
					continue
				}
				st.Flagged++
				m := Moment{Event: fs[0].Event, Evidence: fs[0].Evidence}
				sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity > fs[j].Severity })
				for _, f := range fs {
					res.Findings = append(res.Findings, f)
					st.BySeverity[f.Severity.String()]++
					st.Score += f.Severity.Weight()
					m.Titles = append(m.Titles, f.Title)
					m.Rules = append(m.Rules, f.Rule)
					if f.Severity > m.Severity {
						m.Severity = f.Severity
					}
					off := offenses[f.Rule]
					if off == nil {
						off = &Offense{Rule: f.Rule, Title: f.Title, Category: f.Category}
						offenses[f.Rule] = off
						offAgents[f.Rule] = map[string]bool{}
					}
					off.Count++
					if f.Severity > off.Severity {
						off.Severity = f.Severity
					}
					offAgents[f.Rule][e.Agent] = true
				}
				res.Moments = append(res.Moments, m)
			}
		}
		if st.Sessions > 0 {
			st.Verdict = Verdict(st.Score)
			stats[p.Agent()] = st
		}
	}

	for _, st := range stats {
		res.Agents = append(res.Agents, *st)
		res.Sessions += st.Sessions
		res.ToolCalls += st.ToolCalls
		res.Flagged += st.Flagged
		res.Score += st.Score
	}
	sort.Slice(res.Agents, func(i, j int) bool {
		a, b := res.Agents[i], res.Agents[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.Agent < b.Agent
	})
	for id, off := range offenses {
		for a := range offAgents[id] {
			off.Agents = append(off.Agents, a)
		}
		sort.Strings(off.Agents)
		res.Offenses = append(res.Offenses, *off)
	}
	sort.Slice(res.Offenses, func(i, j int) bool {
		a, b := res.Offenses[i], res.Offenses[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Rule < b.Rule
	})
	sort.SliceStable(res.Moments, func(i, j int) bool {
		a, b := res.Moments[i], res.Moments[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if len(a.Rules) != len(b.Rules) {
			return len(a.Rules) > len(b.Rules)
		}
		return a.Event.Time.After(b.Event.Time)
	})
	sort.SliceStable(res.Findings, func(i, j int) bool {
		return res.Findings[i].Event.Time.Before(res.Findings[j].Event.Time)
	})
	return res, nil
}

// Verdict turns a score into a label for the rap sheet.
func Verdict(score int) string {
	switch {
	case score == 0:
		return "clean record"
	case score < 15:
		return "petty offender"
	case score < 50:
		return "repeat offender"
	case score < 120:
		return "menace"
	default:
		return "public enemy"
	}
}

// Home returns the user's home dir, honoring $HOME.
func Home() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}
