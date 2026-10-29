// Package scan finds agent logs, runs the rules over every tool call and
// adds up the results.
package scan

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kaygaaf/tattlr/internal/audit"
	"github.com/kaygaaf/tattlr/internal/config"
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
	// Blocked is set when the live hook denied this exact call, so the log
	// shows an attempt rather than something that ran.
	Blocked bool `json:"blocked,omitempty"`
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
	Protect   *ProtectStats   `json:"protect,omitempty"`
	Warnings  []string        `json:"warnings,omitempty"`
	Home      string          `json:"-"`
}

// ProtectStats sums up the live hook audit log written by tattlr protect.
type ProtectStats struct {
	Checked int `json:"checked"`
	Blocked int `json:"blocked"`
	Asked   int `json:"asked"`
	// Would counts calls observe mode let through but would have stopped.
	Would int `json:"would_block"`
	// Stopped lists the newest blocked, asked or would-block calls first.
	Stopped []audit.Entry `json:"stopped"`
}

const maxStopped = 50

// deniedKey ties an audit entry to the session log line for the same call.
func deniedKey(session, evidence string) string {
	return session + "\x00" + strings.TrimSpace(evidence)
}

func eventKeys(e event.Event) []string {
	var ks []string
	for _, v := range []string{e.Command, e.Path, e.URL, e.Args} {
		if strings.TrimSpace(v) != "" {
			ks = append(ks, deniedKey(e.SessionID, v))
		}
	}
	return ks
}

func readAudit(o Options, want map[string]bool) (*ProtectStats, map[string]bool, error) {
	es, err := audit.Read(config.AuditPath(o.Home))
	if err != nil || len(es) == 0 {
		return nil, nil, err
	}
	ps := &ProtectStats{}
	denied := map[string]bool{}
	for _, e := range es {
		if !o.Since.IsZero() && e.Time.Before(o.Since) {
			continue
		}
		if len(want) > 0 && !want[e.Agent] {
			continue
		}
		if o.Project != "" && !strings.Contains(strings.ToLower(e.Cwd), strings.ToLower(o.Project)) {
			continue
		}
		if e.Tool == "" && e.Error != "" {
			continue // a payload tattlr could not read
		}
		ps.Checked++
		switch {
		case e.Decision == "deny":
			ps.Blocked++
			if e.Session != "" && e.Evidence != "" {
				denied[deniedKey(e.Session, e.Evidence)] = true
			}
		case e.Decision == "ask":
			ps.Asked++
		case e.Would == "deny" || e.Would == "ask":
			ps.Would++
		default:
			continue
		}
		ps.Stopped = append(ps.Stopped, e)
	}
	if ps.Checked == 0 {
		return nil, nil, nil
	}
	sort.SliceStable(ps.Stopped, func(i, j int) bool { return ps.Stopped[i].Time.After(ps.Stopped[j].Time) })
	if len(ps.Stopped) > maxStopped {
		ps.Stopped = ps.Stopped[:maxStopped]
	}
	return ps, denied, nil
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
	ps, denied, err := readAudit(o, want)
	if err != nil {
		res.Warnings = append(res.Warnings, "audit log: "+err.Error())
	} else {
		res.Protect = ps
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
		var sessions []*event.Session
		for _, f := range p.Discover(o.Home) {
			res.Logs++
			s, err := p.Parse(f)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %v", f, err))
			}
			if s != nil {
				sessions = append(sessions, s)
			}
		}
		// Forked, resumed and set-aside Claude transcripts repeat earlier
		// calls under the same tool_use id. Oldest session wins.
		var seenCall map[string]bool
		if u, ok := p.(interface{ UniqueCallIDs() bool }); ok && u.UniqueCallIDs() {
			seenCall = map[string]bool{}
			sort.SliceStable(sessions, func(i, j int) bool { return sessionStart(sessions[i]).Before(sessionStart(sessions[j])) })
		}
		for _, s := range sessions {
			for _, e := range s.Events {
				if seenCall != nil && e.CallID != "" {
					if seenCall[e.CallID] {
						continue
					}
					seenCall[e.CallID] = true
				}
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
				for _, k := range eventKeys(e) {
					if denied[k] {
						m.Blocked = true
					}
				}
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

// sessionStart is the earliest time in a parsed file. Copied lines keep
// their original timestamps, so a fork sorts after the session it copied.
func sessionStart(s *event.Session) time.Time {
	t := s.Start
	for _, e := range s.Events {
		if !e.Time.IsZero() && (t.IsZero() || e.Time.Before(t)) {
			t = e.Time
		}
	}
	return t
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
