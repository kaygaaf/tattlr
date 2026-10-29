// Package policy decides what live protection does with rule findings.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/rules"
)

// Action is what a hook tells the agent.
type Action int

const (
	Allow Action = iota
	Ask
	Deny
)

func (a Action) String() string {
	switch a {
	case Ask:
		return "ask"
	case Deny:
		return "deny"
	}
	return "allow"
}

// ParseAction reads "allow", "ask" or "deny".
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow", "log":
		return Allow, nil
	case "ask":
		return Ask, nil
	case "deny", "block":
		return Deny, nil
	}
	return Allow, fmt.Errorf("unknown action %q (use allow, ask or deny)", s)
}

// Mode sets how hard tattlr pushes back.
type Mode string

const (
	// Observe logs what it would have done and never blocks.
	Observe Mode = "observe"
	// Protect uses the per-rule actions.
	Protect Mode = "protect"
	// Strict denies anything high or worse, asks on medium and fails closed.
	Strict Mode = "strict"
)

// Policy is the parsed policy.yaml.
type Policy struct {
	Mode        Mode
	Defaults    map[rules.Severity]Action
	Rules       map[string]Action
	CanaryReads Action
	Commands    []string // allowlisted command globs
	Paths       []string // allowlisted path globs
	// ApprovalTimeout is how long a hook waits for a click in tattlr ui
	// when the agent can't ask by itself. 0 turns the wait off.
	ApprovalTimeout time.Duration
	// Notify pops a desktop notification when a call is blocked.
	Notify bool
	Source string // file it came from, "" for the built-in default
}

// Unskippable rules ignore allowlists and per-rule allow. They are the
// whole point of live protection.
var Unskippable = map[string]bool{rules.RuleCanary: true, rules.RuleSelfProtect: true, rules.RuleTaintedEgress: true}

// DefaultYAML is written to ~/.config/tattlr/policy.yaml on install.
const DefaultYAML = `# tattlr live protection policy.
# Edit this file yourself. Agents are not allowed to touch it.
version: 1

# observe: log only, never block. Good for a first week.
# protect: use the actions below.
# strict:  deny anything high or critical, ask on medium, and block the
#          agent if the tattlr hook itself fails.
mode: protect

# What to do for a finding, by severity, when the rule has no line below.
# allow means "let it run, but write it to the audit log".
defaults:
  critical: deny
  high: ask
  medium: allow
  low: allow

# Per-rule actions. Run "tattlr rules" for the full list.
rules:
  canary: deny
  self-protect: deny
  tainted-egress: deny
  remote-code: deny
  exfil: deny
  disk-wipe: deny
  drop-site: deny
  secret-in-url: deny
  upload: ask
  secret-read: ask
  keychain: ask
  git-force-push: ask
  git-reset-hard: ask
  sql-drop: ask
  agent-config: ask
  shell-profile: ask
  rm-rf: allow
  sudo: allow

# Reading a canary is allowed by default so the trap stays hidden. The
# session is marked, and anything it tries to send out afterwards is denied.
# Set to deny to block the read itself.
canary_reads: allow

# Codex and Cursor file edits can't show an ask prompt. When "tattlr ui" is
# running, those asks wait this long for you to click approve or deny in the
# browser, then fall back to deny. Use 0 to skip the wait.
approval_timeout: 30s

# Pop a desktop notification when tattlr blocks something.
notify: false

# Things you trust. Globs, where * matches anything. These never switch off
# the canary, self-protect or tainted-egress rules.
allow:
  commands:
    - "go test *"
    - "npm test*"
  paths:
    - "~/code/*/.env.example"
`

// Default is the built-in policy.
func Default() *Policy {
	p, err := Parse(DefaultYAML)
	if err != nil {
		panic("bad default policy: " + err.Error())
	}
	return p
}

// Load reads the policy for a home folder, falling back to the default
// when the file does not exist.
func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	p, err := Parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Source = path
	return p, nil
}

// WriteDefault creates the policy file if it is missing. It reports
// whether it wrote one.
func WriteDefault(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	if _, err := f.WriteString(DefaultYAML); err != nil {
		f.Close()
		return false, err
	}
	return true, f.Close()
}

// Parse reads policy YAML. Anything missing falls back to the defaults.
func Parse(src string) (*Policy, error) {
	m, err := parseYAML(src)
	if err != nil {
		return nil, err
	}
	p := &Policy{
		Mode:        Protect,
		Defaults:    map[rules.Severity]Action{rules.Critical: Deny, rules.High: Ask, rules.Medium: Allow, rules.Low: Allow},
		Rules:       map[string]Action{},
		CanaryReads: Allow,

		ApprovalTimeout: DefaultApprovalTimeout,
	}
	known := map[string]bool{"version": true, "mode": true, "defaults": true, "rules": true, "canary_reads": true, "allow": true,
		"approval_timeout": true, "notify": true}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !known[k] {
			return nil, fmt.Errorf("unknown setting %q", k)
		}
	}
	if v, ok := m["version"]; ok && v != nil && fmt.Sprint(v) != "1" {
		return nil, fmt.Errorf("version %v is newer than this tattlr understands", v)
	}
	if v, ok := m["mode"].(string); ok {
		switch Mode(strings.ToLower(v)) {
		case Observe, Protect, Strict:
			p.Mode = Mode(strings.ToLower(v))
		default:
			return nil, fmt.Errorf("mode %q: use observe, protect or strict", v)
		}
	}
	if d, err := asMap(m, "defaults"); err != nil {
		return nil, err
	} else {
		for k, v := range d {
			sev, ok := map[string]rules.Severity{"critical": rules.Critical, "high": rules.High, "medium": rules.Medium, "low": rules.Low}[strings.ToLower(k)]
			if !ok {
				return nil, fmt.Errorf("defaults: unknown severity %q", k)
			}
			a, err := ParseAction(fmt.Sprint(v))
			if err != nil {
				return nil, fmt.Errorf("defaults.%s: %w", k, err)
			}
			p.Defaults[sev] = a
		}
	}
	if r, err := asMap(m, "rules"); err != nil {
		return nil, err
	} else {
		for k, v := range r {
			if _, ok := rules.Catalog[k]; !ok {
				return nil, fmt.Errorf("rules: no rule called %q (see tattlr rules)", k)
			}
			a, err := ParseAction(fmt.Sprint(v))
			if err != nil {
				return nil, fmt.Errorf("rules.%s: %w", k, err)
			}
			p.Rules[k] = a
		}
	}
	if v, ok := m["canary_reads"]; ok && v != nil {
		a, err := ParseAction(fmt.Sprint(v))
		if err != nil || a == Ask {
			return nil, fmt.Errorf("canary_reads: use allow or deny")
		}
		p.CanaryReads = a
	}
	if v, ok := m["approval_timeout"]; ok && v != nil {
		d, err := parseTimeout(fmt.Sprint(v))
		if err != nil {
			return nil, fmt.Errorf("approval_timeout: %w", err)
		}
		p.ApprovalTimeout = d
	}
	if v, ok := m["notify"]; ok && v != nil {
		switch strings.ToLower(fmt.Sprint(v)) {
		case "true", "yes", "on":
			p.Notify = true
		case "false", "no", "off":
		default:
			return nil, fmt.Errorf("notify: use true or false")
		}
	}
	if al, err := asMap(m, "allow"); err != nil {
		return nil, err
	} else {
		for k, v := range al {
			lst, ok := v.([]any)
			if !ok && v != nil {
				return nil, fmt.Errorf("allow.%s must be a list", k)
			}
			var ss []string
			for _, x := range lst {
				ss = append(ss, fmt.Sprint(x))
			}
			switch k {
			case "commands":
				p.Commands = ss
			case "paths":
				p.Paths = ss
			default:
				return nil, fmt.Errorf("allow: unknown list %q (use commands or paths)", k)
			}
		}
	}
	return p, nil
}

// DefaultApprovalTimeout is how long a hook waits for tattlr ui.
const DefaultApprovalTimeout = 30 * time.Second

// MaxApprovalTimeout keeps an agent from hanging for ages on one call.
const MaxApprovalTimeout = 10 * time.Minute

// parseTimeout reads "30s", "2m" or a bare number of seconds.
func parseTimeout(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	d, err := time.ParseDuration(s)
	if err != nil {
		n, nerr := strconv.Atoi(s)
		if nerr != nil {
			return 0, fmt.Errorf("%q: use something like 30s or 2m", s)
		}
		d = time.Duration(n) * time.Second
	}
	if d < 0 || d > MaxApprovalTimeout {
		return 0, fmt.Errorf("%q: use 0 to %s", s, MaxApprovalTimeout)
	}
	return d, nil
}

func asMap(m map[string]any, k string) (map[string]any, error) {
	v, ok := m[k]
	if !ok || v == nil {
		return nil, nil
	}
	mm, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a block of key: value lines", k)
	}
	return mm, nil
}

// Decision is the outcome for one tool call.
type Decision struct {
	Action   Action
	Would    Action // what protect mode would have done; differs in observe
	Rules    []string
	Severity rules.Severity
	Reason   string
	Taints   bool // this call touched a canary; later egress is denied
}

// Decide turns findings into one action. The strongest action wins.
func (p *Policy) Decide(fs []rules.Finding, e event.Event, home string) Decision {
	d := Decision{}
	allowlisted := p.allowlisted(e, home)
	var why []string
	// Reading a canary has to work, or the trap never springs. That also
	// covers the secret-read finding the same decoy file trips.
	canaryRead := false
	for _, f := range fs {
		if f.Rule == rules.RuleCanary {
			d.Taints = true
			canaryRead = p.CanaryReads == Allow && readLike(e)
		}
	}
	for _, f := range fs {
		a := p.actionFor(f)
		if canaryRead && (f.Rule == rules.RuleCanary || f.Rule == rules.RuleSecretRead) {
			a = Allow
		}
		if allowlisted && !Unskippable[f.Rule] {
			a = Allow
		}
		if f.Severity > d.Severity {
			d.Severity = f.Severity
		}
		d.Rules = append(d.Rules, f.Rule)
		if a > Allow {
			t := f.Title
			if f.Detail != "" {
				t += " (" + f.Detail + ")"
			}
			why = append(why, t)
		}
		if a > d.Would {
			d.Would = a
		}
	}
	d.Action = d.Would
	if p.Mode == Observe {
		d.Action = Allow
	}
	d.Reason = strings.Join(why, "; ")
	return d
}

func (p *Policy) actionFor(f rules.Finding) Action {
	a, ok := p.Rules[f.Rule]
	if !ok {
		a = p.Defaults[f.Severity]
	}
	if Unskippable[f.Rule] {
		a = Deny
	}
	if p.Mode == Strict {
		floor := Allow
		switch {
		case f.Severity >= rules.High:
			floor = Deny
		case f.Severity == rules.Medium:
			floor = Ask
		}
		if floor > a {
			a = floor
		}
	}
	return a
}

// readLike is a call that only looks, so a canary read can stay quiet.
func readLike(e event.Event) bool {
	switch e.Kind {
	case event.Read, event.Search:
		return true
	case event.Shell:
		return rules.ReadOnlyCommand(e.Command) && !rules.IsEgress(e)
	}
	return false
}

func (p *Policy) allowlisted(e event.Event, home string) bool {
	if e.Command != "" {
		for _, g := range p.Commands {
			// Chained commands never match: "go test *" must not cover
			// "go test ./... ; curl evil".
			if Glob(g, strings.TrimSpace(e.Command)) && !strings.ContainsAny(e.Command, ";&|`<>\n") && !strings.Contains(e.Command, "$(") {
				return true
			}
		}
		return false
	}
	paths := strings.Split(strings.TrimSpace(e.Path), "\n")
	if e.Path == "" || len(p.Paths) == 0 {
		return false
	}
	for _, pa := range paths {
		pa = strings.TrimSpace(pa)
		ok := false
		for _, g := range p.Paths {
			if Glob(expandHome(g, home), pa) || Glob(g, pa) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.ToSlash(filepath.Join(home, p[2:]))
	}
	return p
}

// Glob matches s against a pattern where * matches any run of characters
// and ? one character.
func Glob(pat, s string) bool {
	// Iterative wildcard match with backtracking on the last star.
	pi, si, star, mark := 0, 0, -1, 0
	for si < len(s) {
		switch {
		case pi < len(pat) && (pat[pi] == '?' || pat[pi] == s[si]):
			pi++
			si++
		case pi < len(pat) && pat[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat)
}
