package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkflowsCommand(t *testing.T) {
	dir := filepath.Join(fixtures(), "..", "workflows")
	labeler := filepath.Join(dir, "codex-labeler.yml")
	cases := []struct {
		name string
		args []string
		code int
		want []string
	}{
		{"folder", []string{"workflows", dir}, 0, []string{"WORKFLOWS", "5 files checked", "CRIT", "codex-labeler.yml:28"}},
		{"flags after path", []string{"workflows", labeler, "--fail-on", "critical"}, 1, []string{"allow-users"}},
		{"flags before path", []string{"workflows", "--fail-on", "critical", filepath.Join(dir, "claude-mention.yml")}, 0, []string{"LOW"}},
		{"clean", []string{"workflows", filepath.Join(dir, "nightly.yml")}, 0, []string{"No agent steps"}},
		{"markdown", []string{"workflows", "--format", "md", labeler}, 0, []string{"## tattlr workflows", "| 🔴 critical |"}},
		{"bad format", []string{"workflows", "--format", "xml", dir}, 2, nil},
		{"bad severity", []string{"workflows", "--fail-on", "scary", dir}, 2, nil},
		{"two paths", []string{"workflows", dir, dir}, 2, nil},
		{"missing", []string{"workflows", filepath.Join(dir, "nope")}, 1, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errs := run(t, fixtures(), "", false, c.args...)
			if code != c.code {
				t.Fatalf("exit %d, want %d; stderr: %s", code, c.code, errs)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q in:\n%s", w, out)
				}
			}
		})
	}
}

func TestWorkflowsJSONAndSARIF(t *testing.T) {
	labeler := filepath.Join(fixtures(), "..", "workflows", "codex-labeler.yml")
	_, out, _ := run(t, fixtures(), "", false, "workflows", "--format", "json", labeler)
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
	if len(res.Findings) == 0 || res.Findings[0].Severity != "critical" || res.Findings[0].Line != 28 {
		t.Fatalf("json: %s", out)
	}

	_, out, _ = run(t, fixtures(), "", false, "workflows", "--format", "sarif", labeler)
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
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
	r := log.Runs[0].Results[0]
	loc := r.Locations[0].PhysicalLocation
	if r.RuleID != "workflow-untrusted-prompt" || loc.Region.StartLine != 28 || !strings.HasSuffix(loc.ArtifactLocation.URI, "testdata/workflows/codex-labeler.yml") {
		t.Fatalf("sarif: %+v", r)
	}
}
