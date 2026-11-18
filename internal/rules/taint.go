package rules

import (
	"path"
	"strings"
	"time"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/pathx"
	"github.com/kaygaaf/tattlr/internal/redact"
)

// RuleSecretThenEgress links two calls in one session: one that read a
// real secret and a later one that sends a file or talks to a drop site.
// Each on its own is only high; together they look like the whole attack.
const RuleSecretThenEgress = "secret-then-egress"

func init() {
	Catalog[RuleSecretThenEgress] = Info{RuleSecretThenEgress, "Sent data out after reading a secret", "network", Critical}
}

// Taint is what one session did with real secrets so far: the first call
// that read one, and the files the secret got copied into.
type Taint struct {
	At     time.Time `json:"at,omitempty"`
	What   string    `json:"what,omitempty"` // evidence of the read
	Copies []string  `json:"copies,omitempty"`
}

// Tainted reports whether the session read a secret.
func (t *Taint) Tainted() bool { return t != nil && t.What != "" }

// secretRules mark a session. Canaries have their own, stricter rule.
var secretRules = map[string]bool{RuleSecretRead: true, RuleKeychain: true, RuleEnvDump: true}

// ReadsSecret reports whether a call with these rules read a real secret.
func ReadsSecret(ruleIDs []string) bool {
	for _, r := range ruleIDs {
		if secretRules[r] {
			return true
		}
	}
	return false
}

// Track updates t with one call and the findings it got. It returns the
// files this call copied a secret (or a copy of one) into.
func (en *Engine) Track(t *Taint, e event.Event, fs []Finding) []string {
	read := false
	for _, f := range fs {
		if secretRules[f.Rule] {
			read = true
		}
	}
	if read && t.What == "" {
		t.At, t.What = e.Time, redact.Line(evidence(e), 120)
	}
	if e.Kind != event.Shell || (!read && len(t.Copies) == 0) {
		return nil
	}
	segs := splitShell(e.Command)
	// A copy of a copy counts too: cp .env /tmp/a && cp /tmp/a /tmp/b.
	src := read
	if !src {
		for _, w := range words(e.Command) {
			if t.has(en.fileKey(w)) {
				src = true
				break
			}
		}
	}
	if !src {
		return nil
	}
	var added []string
	for _, s := range segs {
		targets := append([]string{}, s.Out...)
		targets = append(targets, shellWriteTargets(prog(s), s.Args)...)
		for _, x := range targets {
			k := en.fileKey(x)
			if k == "" || k == "/dev/null" || strings.HasPrefix(x, "&") || t.has(k) || secretKind(x, en.Home) != "" {
				continue
			}
			t.Copies = append(t.Copies, k)
			added = append(added, k)
		}
	}
	return added
}

func (t *Taint) has(k string) bool {
	if k == "" {
		return false
	}
	for _, c := range t.Copies {
		if c == k {
			return true
		}
	}
	return false
}

// fileKey makes a file token comparable across calls in one session.
func (en *Engine) fileKey(w string) string {
	w = strings.Trim(strings.TrimPrefix(w, "@"), `"'`)
	if w == "" || w == "-" || strings.Contains(w, "://") || strings.HasPrefix(w, "-") {
		return ""
	}
	if en.Cwd != "" && !strings.HasPrefix(w, "/") && !strings.HasPrefix(w, "~") && !strings.HasPrefix(w, "$") {
		w = path.Join(strings.ReplaceAll(en.Cwd, "\\", "/"), w)
	}
	return normPath(path.Clean(normPath(w, en.Home)), en.Home)
}

// SecretEgress returns a secret-then-egress finding when a tainted session
// sends something out. Plain network calls like npm install don't count:
// only uploads, drop sites, copying files to another host, and network
// calls that name a file the secret was copied into.
func (en *Engine) SecretEgress(t *Taint, e event.Event, fs []Finding) (Finding, bool) {
	if !t.Tainted() {
		return Finding{}, false
	}
	how := ""
	for _, f := range fs {
		switch f.Rule {
		case RuleExfil, RuleCanary, RuleTaintedEgress:
			// Already critical on its own.
			return Finding{}, false
		case RuleUpload:
			how = "uploaded a file"
		case RuleDropSite:
			if how == "" {
				how = "talked to " + f.Detail
			}
		}
	}
	if !IsEgress(e) && how == "" {
		return Finding{}, false
	}
	// Naming the copy says the most, so it wins over "uploaded a file".
	for _, w := range words(e.Command + " " + e.Args + " " + e.URL) {
		if k := en.fileKey(w); t.has(k) {
			how = "sent " + k + ", a copy of the secret"
			break
		}
	}
	if how == "" && e.Kind == event.Shell {
		for _, s := range splitShell(e.Command) {
			switch prog(s) {
			case "scp", "rsync", "sftp":
				if hasRemote(s.Args[1:]) {
					how = "copied files with " + prog(s)
				}
			}
		}
	}
	if how == "" {
		return Finding{}, false
	}
	detail := "read a secret"
	if !t.At.IsZero() {
		at := t.At.Local()
		f := "15:04"
		if !e.Time.IsZero() && e.Time.Local().Format("2006-01-02") != at.Format("2006-01-02") {
			f = "Jan 2 15:04"
		}
		detail += " at " + at.Format(f)
	}
	detail += " (" + en.foldHome(t.What) + "), then " + how
	info := Catalog[RuleSecretThenEgress]
	return Finding{Rule: info.ID, Title: info.Title, Category: info.Category, Severity: info.Severity,
		Detail: detail, Evidence: evidence(e), Event: scrub(e)}, true
}

// foldHome writes home folders in s as "~", so details don't leak a
// user name.
func (en *Engine) foldHome(s string) string {
	fs := strings.Fields(s)
	for i, f := range fs {
		if strings.HasPrefix(f, "/") || strings.HasPrefix(f, "$HOME") || strings.HasPrefix(f, "${HOME}") || pathx.HasDrive(f) {
			fs[i] = normPath(f, en.Home)
		}
	}
	return strings.Join(fs, " ")
}
