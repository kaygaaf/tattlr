package scan

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func home() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "testdata", "home")
}

func TestRunFixtures(t *testing.T) {
	res, err := Run(Options{Home: home(), Now: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Agents) != 5 {
		t.Fatalf("agents = %d, want 5", len(res.Agents))
	}
	if res.Sessions != 10 {
		t.Errorf("sessions = %d, want 10", res.Sessions)
	}
	if res.Canaries != 2 {
		t.Errorf("canaries = %d", res.Canaries)
	}
	byRule := map[string]int{}
	for _, o := range res.Offenses {
		byRule[o.Rule] = o.Count
	}
	for _, r := range []string{"canary", "remote-code", "rm-rf", "git-force-push", "secret-read", "exfil",
		"disk-wipe", "shell-profile", "agent-config", "persistence", "keychain", "drop-site", "sudo"} {
		if byRule[r] == 0 {
			t.Errorf("expected rule %s to fire; got %v", r, byRule)
		}
	}
	// Canary: aws credentials read + --profile tattlr-canary + decoy .env read.
	if byRule["canary"] != 3 {
		t.Errorf("canary hits = %d, want 3", byRule["canary"])
	}
	if res.Moments[0].Severity.String() != "critical" {
		t.Errorf("worst moment is %v", res.Moments[0].Severity)
	}
	// No secret values from the fixtures should survive into the output.
	b, _ := json.Marshal(res)
	for _, leak := range []string{"sk_live_51Hfake", "AKIA2TATTLRC4N4RY7Q", "b3BlbnNzaC1rZXkt", "tattlr-canary-fake-0c1d2e3f", "sk-tattlr-canary-9e8d7c6b5a"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("JSON output leaks %q", leak)
		}
	}
}

func TestFilters(t *testing.T) {
	cases := []struct {
		name     string
		o        Options
		sessions int
	}{
		{"agent", Options{Agents: []string{"codex"}}, 2},
		{"project", Options{Project: "billing"}, 1},
		{"since", Options{Since: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}, 8},
		{"nothing", Options{Project: "does-not-exist"}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.o.Home = home()
			res, err := Run(c.o)
			if err != nil {
				t.Fatal(err)
			}
			if res.Sessions != c.sessions {
				t.Errorf("sessions = %d, want %d", res.Sessions, c.sessions)
			}
		})
	}
}

func TestVerdict(t *testing.T) {
	cases := map[int]string{0: "clean record", 3: "petty offender", 30: "repeat offender", 80: "menace", 500: "public enemy"}
	for in, want := range cases {
		if got := Verdict(in); got != want {
			t.Errorf("Verdict(%d) = %q, want %q", in, got, want)
		}
	}
}
