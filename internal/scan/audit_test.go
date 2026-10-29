package scan

import (
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
