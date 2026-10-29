package cursor

import (
	"testing"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers/testutil"
)

type W = testutil.Want

func TestParse(t *testing.T) {
	files := Parser{}.Discover(testutil.Home(t))
	if len(files) != 1 {
		t.Fatalf("discovered %v", files)
	}
	s, err := Parser{}.Parse(files[0])
	if err != nil {
		t.Fatal(err)
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
