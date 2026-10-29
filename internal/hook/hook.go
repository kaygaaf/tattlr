// Package hook answers live pre-tool-use hooks from coding agents. Each
// agent sends JSON on stdin and expects its own answer format back; the
// rules and the policy are shared.
package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kaygaaf/tattlr/internal/audit"
	"github.com/kaygaaf/tattlr/internal/config"
	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/policy"
	"github.com/kaygaaf/tattlr/internal/redact"
	"github.com/kaygaaf/tattlr/internal/rules"
	"github.com/kaygaaf/tattlr/internal/trap"
)

// Agents lists the hook adapters.
var Agents = []string{"claude", "codex", "cursor", "gemini", "openclaw"}

// Options configure one hook run.
type Options struct {
	Home string
	Bin  string // the tattlr binary, protected from edits
	Now  func() time.Time
	// NoLog skips the audit log (used by the self-test in protect status).
	NoLog bool
}

// call is what an adapter pulls out of the agent's payload.
type call struct {
	agent     string // event.Agent* name
	hookEvent string
	session   string
	cwd       string
	tool      string
	events    []event.Event
	// skip means this payload is not a tool call we judge (wrong event).
	skip bool
}

// Result is the decision plus what was written back.
type Result struct {
	Decision policy.Decision
	Mode     policy.Mode
	Exit     int
}

const maxInput = 16 << 20

// Run reads one payload from in, writes the agent's answer to out and
// returns the process exit code.
func Run(agent string, in io.Reader, out, errw io.Writer, o Options) int {
	return RunResult(agent, in, out, errw, o).Exit
}

// RunResult is Run that also returns the decision.
func RunResult(agent string, in io.Reader, out, errw io.Writer, o Options) Result {
	if o.Now == nil {
		o.Now = time.Now
	}
	ad, ok := adapters[agent]
	if !ok {
		fmt.Fprintf(errw, "tattlr hook: unknown agent %q (use %s)\n", agent, strings.Join(Agents, ", "))
		return Result{Exit: 1}
	}

	pol, perr := policy.Load(config.PolicyPath(o.Home))
	if perr != nil {
		// A broken policy must not switch protection off. Fall back to the
		// default and say so.
		fmt.Fprintf(errw, "tattlr: %v (using the default policy)\n", perr)
		pol = policy.Default()
	}

	raw, err := io.ReadAll(io.LimitReader(in, maxInput))
	var c call
	if err == nil {
		c, err = ad.parse(raw)
	}
	if err != nil {
		return failure(ad, c, pol, out, errw, o, agent, err)
	}
	if c.skip {
		ad.write(out, c, policy.Decision{}, "")
		return Result{Mode: pol.Mode}
	}

	d, ev := judge(c, pol, o)
	reason := explain(d, c)
	exit := ad.write(out, c, d, reason)
	if !o.NoLog {
		e := audit.Entry{
			Time: o.Now().UTC(), Agent: c.agent, HookEvent: c.hookEvent, Session: c.session, Cwd: c.cwd,
			Tool: c.tool, Kind: string(ev.Kind), Evidence: rules.Evidence(ev), Decision: d.Action.String(),
			Mode: string(pol.Mode), Rules: d.Rules, Reason: d.Reason, Tainted: d.Taints,
		}
		if len(c.events) > 1 {
			e.Evidence = redact.Line(fmt.Sprintf("%s (%d files)", e.Evidence, len(c.events)), 300)
		}
		if d.Severity > 0 {
			e.Severity = d.Severity.String()
		}
		if pol.Mode == policy.Observe && d.Would != policy.Allow {
			e.Would = d.Would.String()
		}
		if perr != nil {
			e.Error = perr.Error()
		}
		if err := audit.Append(config.AuditPath(o.Home), e); err != nil {
			fmt.Fprintf(errw, "tattlr: could not write the audit log: %v\n", err)
		}
	}
	return Result{Decision: d, Mode: pol.Mode, Exit: exit}
}

// judge runs the rules over every event in the call and decides.
func judge(c call, pol *policy.Policy, o Options) (policy.Decision, event.Event) {
	var canaries []rules.Canary
	if reg, err := trap.Load(o.Home); err == nil {
		canaries = reg.Canaries()
	}
	en := &rules.Engine{Home: o.Home, Canaries: canaries, Protected: protected(o), Cwd: c.cwd}

	var fs []rules.Finding
	seen := map[string]bool{}
	egress := false
	for _, e := range c.events {
		for _, f := range en.Check(e) {
			if !seen[f.Rule] {
				seen[f.Rule] = true
				fs = append(fs, f)
			}
		}
		if rules.IsEgress(e) {
			egress = true
		}
	}
	main := event.Event{Tool: c.tool}
	if len(c.events) > 0 {
		main = c.events[0]
	}
	if egress && c.session != "" {
		recent, _ := audit.Tail(config.AuditPath(o.Home), 256<<10)
		if audit.Tainted(recent, c.agent, c.session) {
			info := rules.Catalog[rules.RuleTaintedEgress]
			fs = append(fs, rules.Finding{Rule: info.ID, Title: info.Title, Category: info.Category,
				Severity: info.Severity, Detail: "this session read a canary earlier", Evidence: rules.Evidence(main)})
		}
	}
	// Most severe first, so the reason leads with the worst thing.
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity > fs[j].Severity })
	var d policy.Decision
	for i, e := range c.events {
		di := pol.Decide(fs, e, o.Home)
		if i == 0 || di.Action > d.Action || di.Would > d.Would {
			d = di
		}
	}
	if len(c.events) == 0 {
		d = pol.Decide(fs, main, o.Home)
	}
	return d, main
}

func protected(o Options) []string {
	ps := config.Protected(o.Home, o.Bin)
	if st, err := readInstalledBin(o.Home); err == nil && st != "" && st != o.Bin {
		ps = append(ps, st)
	}
	return ps
}

// readInstalledBin returns the binary path recorded by protect install.
func readInstalledBin(home string) (string, error) {
	b, err := os.ReadFile(config.StatePath(home))
	if err != nil {
		return "", err
	}
	var s struct {
		Bin string `json:"bin"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return "", err
	}
	return s.Bin, nil
}

// explain writes the message the agent (and the user) sees.
func explain(d policy.Decision, _ call) string {
	if d.Action == policy.Allow || d.Reason == "" {
		return ""
	}
	r := "tattlr: " + d.Reason + "."
	switch d.Action {
	case policy.Deny:
		r += " This call is blocked by your tattlr policy. Do not retry it another way; tell the user what you were trying to do."
	case policy.Ask:
		r += " tattlr wants a human to OK this."
	}
	return r
}

// failure handles a payload we could not read: fail open by default, fail
// closed in strict mode.
func failure(ad adapter, c call, pol *policy.Policy, out, errw io.Writer, o Options, agent string, err error) Result {
	msg := "tattlr hook could not read the request: " + err.Error()
	fmt.Fprintln(errw, msg)
	if !o.NoLog {
		_ = audit.Append(config.AuditPath(o.Home), audit.Entry{Time: o.Now().UTC(), Agent: agent,
			Decision: map[bool]string{true: "deny", false: "allow"}[pol.Mode == policy.Strict],
			Mode:     string(pol.Mode), Error: redact.Line(err.Error(), 200)})
	}
	if pol.Mode == policy.Strict {
		d := policy.Decision{Action: policy.Deny, Would: policy.Deny, Reason: "hook error"}
		return Result{Decision: d, Mode: pol.Mode, Exit: ad.write(out, c, d, "tattlr (strict mode) blocked this because the hook failed: "+err.Error())}
	}
	ad.write(out, c, policy.Decision{}, "")
	return Result{Mode: pol.Mode}
}

// abs makes a path absolute against cwd for display and matching.
func abs(p, cwd string) string {
	if p == "" || filepath.IsAbs(p) || strings.HasPrefix(p, "~") || cwd == "" {
		return p
	}
	return filepath.Join(cwd, p)
}
