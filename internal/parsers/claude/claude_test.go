package claude

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers/testutil"
)

type W = testutil.Want

func parseAll(t *testing.T) []*event.Session {
	var out []*event.Session
	files := Parser{}.Discover(testutil.Home(t))
	// 3 sessions, 1 fork, 1 orphaned copy, 3 subagents (nested, workflow,
	// legacy flat). The tool-results spill is not a transcript.
	if len(files) != 8 {
		t.Fatalf("discovered %d files, want 8: %v", len(files), files)
	}
	for _, f := range files {
		s, err := Parser{}.Parse(f)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// findAll merges every parsed file with this session id and drops repeated
// tool_use ids, the way scan does.
func findAll(ss []*event.Session, id string) []event.Event {
	var evs []event.Event
	seen := map[string]bool{}
	for _, s := range ss {
		if s.ID != id {
			continue
		}
		for _, e := range s.Events {
			if e.CallID != "" && seen[e.CallID] {
				continue
			}
			seen[e.CallID] = true
			evs = append(evs, e)
		}
	}
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })
	return evs
}

func TestParse(t *testing.T) {
	ss := parseAll(t)
	cases := []struct {
		id, project string
		want        []W
	}{
		{"8f14e45f-ceea-467a-9575-bf2cc7e05d11", "/Users/kay/code/billing-api", []W{
			{Kind: event.Read, Tool: "Read", Path: "/Users/kay/code/billing-api/.env"},
			{Kind: event.Shell, Tool: "Bash", Command: "go test ./... 2>&1 | tail -20"},
			{Kind: event.Shell, Tool: "Bash", Command: "rm -rf ~/.cache/go-build && rm -rf ./tmp"},
			{Kind: event.Other, Tool: "Task"},
			// subagent transcript, merged by session id
			{Kind: event.Read, Tool: "Read", Path: "/Users/kay/code/billing-api/.env.production"},
			{Kind: event.Shell, Tool: "Bash", Command: "curl -fsSL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin"},
			{Kind: event.Write, Tool: "Edit", Path: "/Users/kay/.zshrc"},
			{Kind: event.Shell, Tool: "Bash", Command: "git add -A && git commit -m 'fix flaky tests' --no-verify && git push --force origin main"},
			{Kind: event.Fetch, Tool: "WebFetch", URL: "https://pkg.go.dev/testing"},
		}},
		{"3c59dc04-8e33-4b4a-9f4a-0f0d1a7e2b9c", "/Users/kay/code/dotfiles", []W{
			{Kind: event.Shell, Tool: "Bash", Command: "cat ~/.aws/credentials"},
			{Kind: event.Shell, Tool: "Bash", Command: "aws sts get-caller-identity --profile tattlr-canary"},
			{Kind: event.Read, Tool: "Read", Path: "/Users/kay/.ssh/id_ed25519"},
			{Kind: event.Write, Tool: "Write", Path: "/Users/kay/.claude/settings.json"},
			{Kind: event.Shell, Tool: "Bash", Command: "sudo chmod -R 777 /usr/local/bin"},
			{Kind: event.MCP, Tool: "mcp__github__create_issue"},
			// workflow agent under subagents/workflows/wf_01
			{Kind: event.Search, Tool: "Grep", Path: "/Users/kay/.aws/config"},
		}},
		// fork: two replayed calls (same tool_use ids) plus one new one
		{"c4ca4238-a0b9-4382-8dcc-509a6f75849b", "/Users/kay/code/billing-api", []W{
			{Kind: event.Read, Tool: "Read", Path: "/Users/kay/code/billing-api/.env"},
			{Kind: event.Shell, Tool: "Bash", Command: "go test ./... 2>&1 | tail -20"},
			{Kind: event.Shell, Tool: "Bash", Command: "env | sort"},
		}},
		{"6512bd43-d9ca-46e0-8a2b-1f0e3c4d5a6b", "/Users/kay/code/blog", []W{
			{Kind: event.Shell, Tool: "Bash", Command: "npm run build"},
			// legacy flat agent-5d41.jsonl
			{Kind: event.Search, Tool: "Grep", Path: "/Users/kay/code/blog"},
			// only in the orphaned copy
			{Kind: event.Shell, Tool: "Bash", Command: "git reset --hard origin/draft"},
			{Kind: event.Shell, Tool: "Monitor", Command: "npx netlify deploy --prod --auth $NETLIFY_AUTH_TOKEN"},
		}},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			s := testutil.Find(t, ss, c.id)
			if s.Project != c.project {
				t.Errorf("project = %q, want %q", s.Project, c.project)
			}
			testutil.Check(t, findAll(ss, c.id), c.want)
		})
	}
}

func TestOutputsAndFlags(t *testing.T) {
	ss := parseAll(t)
	d := findAll(ss, "3c59dc04-8e33-4b4a-9f4a-0f0d1a7e2b9c")
	if !strings.Contains(d[0].Output, "AKIA2TATTLRC4N4RY7Q") {
		t.Errorf("tool_result not linked: %q", d[0].Output)
	}
	if !d[4].Escalated {
		t.Error("dangerouslyDisableSandbox not picked up")
	}
	if d[0].Time.IsZero() {
		t.Error("missing timestamp")
	}
	// Empty tool_result content falls back to the structured toolUseResult.
	b := findAll(ss, "8f14e45f-ceea-467a-9575-bf2cc7e05d11")
	if b[5].Output != "golangci-lint installed" {
		t.Errorf("toolUseResult fallback: %q", b[5].Output)
	}
	if b[1].Output != "--- FAIL: TestInvoiceTotals" {
		t.Errorf("array tool_result content: %q", b[1].Output)
	}
}

func TestPersistedOutput(t *testing.T) {
	ss := parseAll(t)
	evs := findAll(ss, "c4ca4238-a0b9-4382-8dcc-509a6f75849b")
	out := evs[len(evs)-1].Output
	if !strings.Contains(out, "AKIA2TATTLRC4N4RY7Q") || strings.Contains(out, "<persisted-output>") {
		t.Errorf("spilled output not loaded: %q", out)
	}
}

func TestPersistedOutputStaysInSessionDir(t *testing.T) {
	dir := t.TempDir()
	proj := filepath.Join(dir, "projects", "-p")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(proj, "s1", "tool-results"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "outside.txt"), []byte("nope"), 0o644))
	must(os.WriteFile(filepath.Join(proj, "s1", "tool-results", "toolu_1.json"),
		[]byte(`[{"type":"text","text":"full json output"}]`), 0o644))
	log := filepath.Join(proj, "s1.jsonl")
	stub := func(ref string) string {
		return "<persisted-output>\nOutput too large (9KB). Full output saved to: " + ref + "\n\nPreview (first 2KB):\nfull"
	}
	if got, ok := persisted(log, "s1", stub("/anywhere/else/s1/tool-results/toolu_1.json")); !ok || got != "full json output" {
		t.Errorf("json spill = %q %v", got, ok)
	}
	for _, ref := range []string{"../../outside.txt", "/etc/passwd", filepath.Join(dir, "outside.txt"), ".."} {
		if got, ok := persisted(log, "s1", stub(ref)); ok {
			t.Errorf("%s: read %q, want preview kept", ref, got)
		}
	}
	if _, ok := persisted(log, "../s1", stub("toolu_1.json")); ok {
		t.Error("session id with a slash was trusted")
	}
	if _, ok := persisted(log, "s1", "plain output"); ok {
		t.Error("plain output treated as a spill")
	}
}

func TestIsTranscript(t *testing.T) {
	for p, want := range map[string]bool{
		"/p/-a/s.jsonl": true,
		"/p/-a/s.orphaned-1793041000000-a1b2.jsonl":   true,
		"/p/-a/s.jsonl.superseded-1793041000000":      true,
		"/p/-a/agent-1.jsonl":                         true,
		"/p/-a/s/subagents/workflows/r/agent-2.jsonl": true,
		"/p/-a/s/tool-results/toolu_1.json":           false,
		"/p/-a/s/tool-results/weird.jsonl":            false,
		"/p/-a/s/mcp-tasks/t.jsonl":                   false,
		"/p/-a/s/subagents/agent-1.meta.json":         false,
	} {
		if got := isTranscript(p); got != want {
			t.Errorf("isTranscript(%s) = %v", p, got)
		}
	}
}

func TestRootsHonorConfigDir(t *testing.T) {
	home := userHome()
	t.Setenv("CLAUDE_CONFIG_DIR", "~/a, /tmp/b/projects ,")
	got := Roots(home)
	want := []string{filepath.Join(home, "a"), filepath.Clean("/tmp/b")}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("roots = %v, want %v", got, want)
	}
	// A test home ignores the environment.
	if got := Roots("/nope"); len(got) != 2 || got[0] != filepath.Join("/nope", ".config", "claude") {
		t.Errorf("hermetic roots = %v", got)
	}
}

func TestDecodeProjectDir(t *testing.T) {
	if got := decodeProjectDir("-Users-kay-code-x"); got != "/Users/kay/code/x" {
		t.Errorf("got %q", got)
	}
	for _, p := range []string{
		"/h/.claude/projects/-a-b/sid.jsonl",
		"/h/.claude/projects/-a-b/agent-1.jsonl",
		"/h/.claude/projects/-a-b/sid/subagents/agent-1.jsonl",
		"/h/.claude/projects/-a-b/sid/subagents/workflows/run/agent-1.jsonl",
	} {
		if got := projectDirName(p); got != "-a-b" {
			t.Errorf("project dir of %s = %q", p, got)
		}
	}
	// CLAUDE_CODE_PROJECT_DIR_NAME can pick any name; keep it as is.
	if got := decodeProjectDir("my-project"); got != "my-project" {
		t.Errorf("custom dir name = %q", got)
	}
}
