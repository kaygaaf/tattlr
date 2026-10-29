package claude

import (
	"strings"
	"testing"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers/testutil"
)

type W = testutil.Want

func parseAll(t *testing.T) []*event.Session {
	var out []*event.Session
	files := Parser{}.Discover(testutil.Home(t))
	if len(files) != 2 {
		t.Fatalf("discovered %d files, want 2: %v", len(files), files)
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
		}},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			s := testutil.Find(t, ss, c.id)
			if s.Project != c.project {
				t.Errorf("project = %q, want %q", s.Project, c.project)
			}
			testutil.Check(t, s.Events, c.want)
		})
	}
}

func TestOutputsAndFlags(t *testing.T) {
	s := testutil.Find(t, parseAll(t), "3c59dc04-8e33-4b4a-9f4a-0f0d1a7e2b9c")
	if !strings.Contains(s.Events[0].Output, "AKIA2TATTLRC4N4RY7Q") {
		t.Errorf("tool_result not linked: %q", s.Events[0].Output)
	}
	if !s.Events[4].Escalated {
		t.Error("dangerouslyDisableSandbox not picked up")
	}
	if s.Events[0].Time.IsZero() {
		t.Error("missing timestamp")
	}
}

func TestDecodeProjectDir(t *testing.T) {
	if got := decodeProjectDir("-Users-kay-code-x"); got != "/Users/kay/code/x" {
		t.Errorf("got %q", got)
	}
}
