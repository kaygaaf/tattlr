package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepoCommand(t *testing.T) {
	dir := filepath.Join(fixtures(), "..", "repo")
	hook := filepath.Join(dir, "session-hook")
	cases := []struct {
		name string
		args []string
		code int
		want []string
		not  []string
	}{
		{"session hook", []string{"repo", "--fail-on", "high", hook}, 1, []string{"HIGH", "bash .hidden/setup.sh"}, []string{"tattlr hook claude"}},
		{"instruction", []string{"repo", "--fail-on", "high", filepath.Join(dir, "hidden-instruction")}, 1, []string{"not to read a file"}, nil},
		{"mcp", []string{"repo", "--fail-on", "high", filepath.Join(dir, "local-mcp")}, 1, []string{"./bin/setup"}, []string{"npx", "example.com"}},
		{"folder open", []string{"repo", "--fail-on", "high", filepath.Join(dir, "folder-open")}, 1, []string{"folder opens", "./scripts/welcome.sh"}, []string{"go test"}},
		{"boring", []string{"repo", "--fail-on", "high", filepath.Join(dir, "boring")}, 0, []string{"Nothing in this checkout"}, []string{"HIGH"}},
		{"flags before path", []string{"repo", "--fail-on", "high", hook}, 1, []string{"Session-start hook"}, nil},
		{"markdown", []string{"repo", "--format", "md", hook}, 0, []string{"## tattlr repo", "Session-start hook", "does not run anything"}, nil},
		{"bad format", []string{"repo", "--format", "xml", hook}, 2, nil, nil},
		{"bad severity", []string{"repo", "--fail-on", "scary", hook}, 2, nil, nil},
		{"two paths", []string{"repo", hook, hook}, 2, nil, nil},
		{"missing", []string{"repo", filepath.Join(dir, "nope")}, 1, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errs := run(t, fixtures(), "", false, c.args...)
			if code != c.code {
				t.Fatalf("exit %d, want %d; stderr: %s\nstdout: %s", code, c.code, errs, out)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q in:\n%s", w, out)
				}
			}
			for _, w := range c.not {
				if strings.Contains(out, w) {
					t.Errorf("unexpected %q in:\n%s", w, out)
				}
			}
		})
	}
}

func TestRepoJSONAndSARIF(t *testing.T) {
	hook := filepath.Join(fixtures(), "..", "repo", "session-hook")
	_, out, _ := run(t, fixtures(), "", false, "repo", "--format", "json", hook)
	var res struct {
		Findings []struct {
			Rule     string `json:"rule"`
			Severity string `json:"severity"`
			Line     int    `json:"line"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Rule != "repo-session-hook" || res.Findings[0].Severity != "high" || res.Findings[0].Line < 1 {
		t.Fatalf("json: %s", out)
	}

	_, out, _ = run(t, fixtures(), "", false, "repo", "--format", "sarif", hook)
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs) == 0 || len(log.Runs[0].Results) != 1 {
		t.Fatalf("sarif: %s", out)
	}
	r := log.Runs[0].Results[0]
	if r.RuleID != "repo-session-hook" || r.Locations[0].PhysicalLocation.Region.StartLine < 1 {
		t.Fatalf("sarif result: %+v", r)
	}
}

func TestProtectStatusNamesProjectHook(t *testing.T) {
	dir := filepath.Join(fixtures(), "..", "repo", "session-hook")
	t.Chdir(dir)
	home := t.TempDir()
	code, out, errs := run(t, home, "", false, "protect", "status")
	if code != 0 {
		t.Fatalf("exit %d: %s\n%s", code, errs, out)
	}
	for _, want := range []string{"SessionStart", "bash .hidden/setup.sh", ".claude/settings.json", "before any PreToolUse hook"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "tattlr hook claude") {
		t.Fatalf("flagged our hook:\n%s", out)
	}

	// JSON includes the same note.
	_, out, _ = run(t, home, "", false, "protect", "status", "--json")
	if !strings.Contains(out, "bash .hidden/setup.sh") || !strings.Contains(out, "project_hooks") {
		t.Fatalf("json status:\n%s", out)
	}
}
