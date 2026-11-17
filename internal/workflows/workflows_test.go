package workflows

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaygaaf/tattlr/internal/rules"
)

func fixture(t *testing.T, name string) []Finding {
	t.Helper()
	res, err := Check(filepath.Join("..", "..", "testdata", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) > 0 {
		t.Fatalf("warnings: %v", res.Warnings)
	}
	return res.Findings
}

func find(fs []Finding, rule string) *Finding {
	for i := range fs {
		if fs[i].Rule == rule {
			return &fs[i]
		}
	}
	return nil
}

func TestCodexLabeler(t *testing.T) {
	fs := fixture(t, "codex-labeler.yml")
	p := find(fs, RulePrompt)
	if p == nil || p.Severity != rules.Critical {
		t.Fatalf("want a critical %s, got %+v", RulePrompt, fs)
	}
	if p.Line != 28 || p.Job != "gather-labels" || p.Step != "openai/codex-action@main" {
		t.Errorf("wrong place: %+v", p)
	}
	if !strings.Contains(p.Detail, "github.event.issue.title") || !strings.Contains(p.Detail, `allow-users is "*"`) {
		t.Errorf("detail: %s", p.Detail)
	}
	if o := find(fs, RuleOpen); o == nil || o.Line != 23 {
		t.Errorf("want %s on line 23, got %+v", RuleOpen, o)
	}
	// contents: read and only the model key: nothing to report there
	if find(fs, RuleWrite) != nil || find(fs, RuleTrigger) != nil {
		t.Errorf("unexpected: %+v", fs)
	}
}

func TestCLITriage(t *testing.T) {
	fs := fixture(t, "cli-triage.yml")
	p := find(fs, RulePrompt)
	if p == nil || p.Severity != rules.Critical || !strings.Contains(p.Detail, "$COMMENT") || p.Line != 22 {
		t.Fatalf("prompt finding: %+v", fs)
	}
	w := find(fs, RuleWrite)
	if w == nil || w.Severity != rules.Critical {
		t.Fatalf("write finding: %+v", fs)
	}
	if !strings.Contains(w.Detail, "contents: write") || !strings.Contains(w.Detail, "NPM_TOKEN") || strings.Contains(w.Detail, "ANTHROPIC") {
		t.Errorf("write detail: %s", w.Detail)
	}
	if s := find(fs, RuleSandbox); s == nil || !strings.Contains(s.Detail, "--dangerously-skip-permissions") {
		t.Errorf("sandbox finding: %+v", s)
	}
	if find(fs, RuleOpen) == nil {
		t.Error("a bare CLI step on issue_comment should count as open to anyone")
	}
}

func TestClaudeMention(t *testing.T) {
	fs := fixture(t, "claude-mention.yml")
	if len(fs) != 1 || fs[0].Rule != RuleTrigger || fs[0].Severity != rules.Low {
		t.Fatalf("want just the low trigger note, got %+v", fs)
	}
}

func TestGatedGeminiReview(t *testing.T) {
	fs := fixture(t, "gemini-review.yml")
	if find(fs, RuleOpen) != nil {
		t.Errorf("action without a wildcard is not open: %+v", fs)
	}
	p := find(fs, RulePrompt)
	if p == nil || p.Severity != rules.High {
		t.Fatalf("prompt finding: %+v", fs)
	}
	if w := find(fs, RuleWrite); w == nil || w.Severity != rules.High || !strings.Contains(w.Detail, "packages: write") {
		t.Errorf("write finding: %+v", w)
	}
}

func TestPushAndScheduleAreIgnored(t *testing.T) {
	if fs := fixture(t, "nightly.yml"); len(fs) != 0 {
		t.Fatalf("got %+v", fs)
	}
}

func TestCheckFolderSortsWorstFirst(t *testing.T) {
	res, err := Check(filepath.Join("..", "..", "testdata", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 5 {
		t.Fatalf("files: %v", res.Files)
	}
	for i := 1; i < len(res.Findings); i++ {
		if res.Findings[i].Severity > res.Findings[i-1].Severity {
			t.Fatalf("not sorted: %+v", res.Findings)
		}
	}
}

func TestCheckFile(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string
	}{
		{"trigger as a string", "on: issues\njobs:\n  a:\n    steps:\n      - run: gemini -p \"${{ github.event.issue.body }}\"\n",
			[]string{RulePrompt, RuleOpen}},
		{"actor check on the step", "on: [issues]\njobs:\n  a:\n    steps:\n      - if: github.actor == 'me'\n        run: codex exec hi\n",
			[]string{RuleTrigger}},
		{"env set at job level", "on: discussion\njobs:\n  a:\n    env:\n      T: ${{ github.event.discussion.title }}\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: sum up ${{ env.T }}\n",
			[]string{RulePrompt}},
		{"secrets dumped", "on: issues\njobs:\n  a:\n    steps:\n      - uses: openai/codex-action@v1\n        env:\n          ALL: ${{ toJSON(secrets) }}\n        with:\n          allow-users: '*'\n",
			[]string{RuleOpen, RuleWrite}},
		{"codex sandbox input", "on: issues\njobs:\n  a:\n    steps:\n      - uses: openai/codex-action@v1\n        with:\n          allow-users: '*'\n          sandbox: workspace-write\n",
			[]string{RuleOpen, RuleSandbox}},
		{"not an agent", "on: issues\njobs:\n  a:\n    steps:\n      - run: echo \"${{ github.event.issue.body }}\"\n", nil},
		{"reusable workflow job", "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/x.yml\n", nil},
		{"empty", "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs, err := CheckFile("x.yml", []byte(c.src))
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range fs {
				got = append(got, f.Rule)
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestBadYAML(t *testing.T) {
	if _, err := CheckFile("x.yml", []byte("on: [issues\n")); err == nil {
		t.Error("want an error")
	}
}
