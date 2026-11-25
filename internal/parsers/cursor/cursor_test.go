package cursor

import (
	"testing"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers/testutil"
)

type W = testutil.Want

func TestParse(t *testing.T) {
	files := Parser{}.Discover(testutil.Home(t))
	if len(files) != 2 {
		t.Fatalf("discovered %v", files)
	}
	var ss []*event.Session
	for _, f := range files {
		s, err := Parser{}.Parse(f)
		if err != nil {
			t.Fatal(err)
		}
		ss = append(ss, s)
	}
	s := testutil.Find(t, ss, "6a1f2e3d-4c5b-4a69-8778-695a4b3c2d1e")
	if s.Parent != "" {
		t.Errorf("main transcript has parent %q", s.Parent)
	}
	if s.ID != "6a1f2e3d-4c5b-4a69-8778-695a4b3c2d1e" {
		t.Errorf("id = %q", s.ID)
	}
	// The folder name is lossy ("mobile-app" vs "mobile/app"); tattlr uses
	// touched paths to recover the real one.
	if s.Project != "/Users/kay/code/mobile-app" {
		t.Errorf("project = %q", s.Project)
	}
	testutil.Check(t, s.Events, []W{
		{Kind: event.Shell, Tool: "Shell", Command: "security find-identity -v -p codesigning && cat ios/fastlane/.env.default"},
		{Kind: event.Read, Tool: "Read", Path: "/Users/kay/code/mobile-app/ios/certs/dist.p12"},
		{Kind: event.Write, Tool: "StrReplace", Path: "/Users/kay/code/mobile-app/.cursor/hooks.json"},
		{Kind: event.Shell, Tool: "Shell", Command: "git stash drop && git push origin main -f"},
	})
	if s.Start.IsZero() || s.Events[0].Time.IsZero() {
		t.Error("expected mtime fallback timestamps")
	}
	child := testutil.Find(t, ss, "7b2e3f4a-5d6c-4b70-9889-706b5c4d3e2f")
	if child.Parent != s.ID || child.Project != "/Users/kay/code/mobile-app" {
		t.Fatalf("parent=%q project=%q", child.Parent, child.Project)
	}
	testutil.Check(t, child.Events, []W{
		{Kind: event.Shell, Tool: "Shell", Command: "cd /Users/kay/code/mobile-app && history -c"},
		{Kind: event.MCP, Tool: "mcp__fs__write_file", Path: "/Users/kay/.ssh/authorized_keys"},
	})
	for _, e := range child.Events {
		if e.SessionID != s.ID {
			t.Errorf("session = %q, want parent", e.SessionID)
		}
	}
}

func TestEncodeProject(t *testing.T) {
	cases := map[string]string{
		"/Users/kay/code/mobile-app": "Users-kay-code-mobile-app",
		"/home/k/my.site":            "home-k-my-site",
	}
	for in, want := range cases {
		if got := encodeProject(in); got != want {
			t.Errorf("encodeProject(%q) = %q, want %q", in, got, want)
		}
	}
}
