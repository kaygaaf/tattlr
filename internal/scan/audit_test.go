package scan

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kaygaaf/tattlr/internal/audit"
	"github.com/kaygaaf/tattlr/internal/config"
)

func TestScanReadsAuditLog(t *testing.T) {
	home := t.TempDir()
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	p := config.AuditPath(home)
	for i, e := range []audit.Entry{
		{Agent: "claude-code", Tool: "Read", Decision: "allow", Tainted: true, Cwd: "/home/k/code/app"},
		{Agent: "claude-code", Tool: "Bash", Decision: "deny", Rules: []string{"tainted-egress"}, Cwd: "/home/k/code/app"},
		{Agent: "codex", Tool: "Bash", Decision: "ask", Rules: []string{"git-force-push"}, Cwd: "/home/k/code/site"},
		{Agent: "cursor", Tool: "Shell", Decision: "allow", Would: "deny", Mode: "observe", Cwd: "/home/k/code/app"},
		{Agent: "claude-code", Error: "bad JSON", Decision: "allow"},
	} {
		e.Time = now.Add(time.Duration(i-10) * time.Hour)
		if err := audit.Append(p, e); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Run(Options{Home: home, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	ps := r.Protect
	if ps == nil || ps.Checked != 4 || ps.Blocked != 1 || ps.Asked != 1 || ps.Would != 1 || len(ps.Stopped) != 3 {
		t.Fatalf("protect stats: %+v", ps)
	}
	if ps.Stopped[0].Agent != "cursor" {
		t.Errorf("not newest first: %+v", ps.Stopped[0])
	}
	r, _ = Run(Options{Home: home, Now: now, Agents: []string{"codex"}})
	if r.Protect == nil || r.Protect.Checked != 1 {
		t.Errorf("agent filter: %+v", r.Protect)
	}
	r, _ = Run(Options{Home: home, Now: now, Since: now.Add(-7 * time.Hour)})
	if r.Protect == nil || r.Protect.Checked != 1 {
		t.Errorf("since filter: %+v", r.Protect)
	}
	r, _ = Run(Options{Home: home, Now: now, Project: "site"})
	if r.Protect == nil || r.Protect.Checked != 1 {
		t.Errorf("project filter: %+v", r.Protect)
	}
}

// The live Codex fixture has two runs of the same injection: one before the
// hook was trusted (the curl ran) and one after (the hook denied it).
func TestMomentsMarkedBlockedFromAudit(t *testing.T) {
	home := filepath.Join("..", "..", "testdata", "live", "codex-0.165")
	r, err := Run(Options{Home: home, Now: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if r.Protect == nil || r.Protect.Blocked != 1 {
		t.Fatalf("protect stats: %+v", r.Protect)
	}
	var blocked, ran int
	for _, m := range r.Moments {
		if !strings.HasPrefix(m.Event.Command, "curl ") {
			continue
		}
		if m.Blocked {
			blocked++
			if m.Event.SessionID != "01a187a4-b4dc-7561-aec9-2dfe79168c02" {
				t.Errorf("wrong session marked blocked: %s", m.Event.SessionID)
			}
		} else {
			ran++
		}
	}
	if blocked != 1 || ran != 1 {
		t.Errorf("curl moments: blocked=%d ran=%d, want 1 and 1", blocked, ran)
	}
}
