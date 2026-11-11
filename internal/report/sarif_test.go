package report

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/rules"
	"github.com/kaygaaf/tattlr/internal/scan"
)

type sarifDoc struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID         string         `json:"id"`
					Properties map[string]any `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			RuleIndex int    `json:"ruleIndex"`
			Level     string `json:"level"`
			Message   struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI       string `json:"uri"`
						URIBaseID string `json:"uriBaseId"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
		} `json:"results"`
	} `json:"runs"`
}

func decodeSARIF(t *testing.T, r *scan.Result, o SARIFOptions) sarifDoc {
	t.Helper()
	var b bytes.Buffer
	if err := SARIF(&b, r, o); err != nil {
		t.Fatal(err)
	}
	var d sarifDoc
	if err := json.Unmarshal(b.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Version != "2.1.0" || len(d.Runs) != 1 || d.Runs[0].Tool.Driver.Name != "tattlr" {
		t.Fatalf("bad header: %+v", d)
	}
	return d
}

func TestSARIF(t *testing.T) {
	res := result(t)
	d := decodeSARIF(t, res, SARIFOptions{Version: "1.2.3"})
	run := d.Runs[0]
	if len(run.Results) != len(res.Findings) {
		t.Fatalf("got %d results for %d findings", len(run.Results), len(res.Findings))
	}
	if len(run.Tool.Driver.Rules) < len(rules.Catalog) {
		t.Errorf("only %d rules listed", len(run.Tool.Driver.Rules))
	}
	seen := map[string]bool{}
	for _, r := range run.Results {
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("ruleIndex %d does not point at %s", r.RuleIndex, r.RuleID)
		}
		if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("%s: no location", r.RuleID)
		}
		fp := r.PartialFingerprints["tattlrFinding/v1"]
		if fp == "" || seen[fp] {
			t.Errorf("%s: missing or repeated fingerprint %q", r.RuleID, fp)
		}
		seen[fp] = true
		if strings.Contains(r.Message.Text, "/Users/kay") {
			t.Errorf("home path leaked: %s", r.Message.Text)
		}
	}
	for _, r := range run.Tool.Driver.Rules {
		if r.Properties["security-severity"] == nil {
			t.Errorf("%s: no security-severity", r.ID)
		}
	}
}

func TestSARIFLocations(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	log := filepath.Join(t.TempDir(), "session.jsonl")
	in := filepath.Join(root, "config", ".env")
	mk := func(path string) rules.Finding {
		return rules.Finding{Rule: rules.RuleSecretRead, Title: "Read a secret file", Severity: rules.High,
			Evidence: "read " + path, Event: event.Event{Agent: "codex", Path: path, Source: log, Time: time.Unix(0, 0)}}
	}
	res := &scan.Result{Findings: []rules.Finding{mk(in), mk("/etc/shadow"), mk("")}}
	got := decodeSARIF(t, res, SARIFOptions{SrcRoot: root}).Runs[0].Results
	first := got[0].Locations[0].PhysicalLocation.ArtifactLocation
	if first.URI != "config/.env" || first.URIBaseID != "SRCROOT" {
		t.Errorf("in-repo file: %+v", first)
	}
	for _, r := range got[1:] {
		loc := r.Locations[0].PhysicalLocation.ArtifactLocation
		if !strings.HasPrefix(loc.URI, "file:///") || !strings.HasSuffix(loc.URI, "session.jsonl") || loc.URIBaseID != "" {
			t.Errorf("outside file should point at the log: %+v", loc)
		}
	}
	if got[0].Level != "error" {
		t.Errorf("high should be error, got %s", got[0].Level)
	}
}

func TestSARIFEmpty(t *testing.T) {
	var b bytes.Buffer
	if err := SARIF(&b, &scan.Result{}, SARIFOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"results": []`) {
		t.Errorf("an empty scan needs an empty results array, code scanning rejects null:\n%s", b.String())
	}
}

func TestMarkdown(t *testing.T) {
	var b bytes.Buffer
	Markdown(&b, result(t), MarkdownOptions{Loc: time.UTC})
	out := b.String()
	for _, want := range []string{"## tattlr rap sheet", "| claude-code |", "### Top offenses", "### Worst moments", "Touched a tattlr canary"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "/Users/kay") || strings.Contains(out, "\u2014") {
		t.Errorf("home path or em dash in:\n%s", out)
	}

	b.Reset()
	Markdown(&b, &scan.Result{Home: "/home/runner"}, MarkdownOptions{})
	if !strings.Contains(b.String(), "No agent logs found under `/home/runner`") {
		t.Errorf("empty: %s", b.String())
	}
}

func TestMdText(t *testing.T) {
	if got := mdText("a|b\nc"); got != `a\|b c` {
		t.Errorf("mdText: %q", got)
	}
	if got := mdCode("echo `id` | sh"); got != "echo 'id' | sh" {
		t.Errorf("mdCode: %q", got)
	}
}
