// Package testutil holds helpers shared by the parser tests.
package testutil

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kaygaaf/tattlr/internal/event"
)

// Home returns the absolute path of testdata/home at the repo root.
func Home(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "testdata", "home")
}

// Want describes one expected event.
type Want struct {
	Kind    event.Kind
	Tool    string
	Command string
	Path    string
	URL     string
}

// Check compares parsed events against the expected list in order.
func Check(t *testing.T, got []event.Event, want []Want) {
	t.Helper()
	if len(got) != len(want) {
		for _, e := range got {
			t.Logf("got %s %s cmd=%q path=%q url=%q", e.Kind, e.Tool, e.Command, e.Path, e.URL)
		}
		t.Fatalf("got %d events, want %d", len(got), len(want))
	}
	for i, w := range want {
		e := got[i]
		if e.Kind != w.Kind || e.Tool != w.Tool || e.Command != w.Command || e.Path != w.Path || e.URL != w.URL {
			t.Errorf("event %d:\n got  %s %s cmd=%q path=%q url=%q\n want %s %s cmd=%q path=%q url=%q",
				i, e.Kind, e.Tool, e.Command, e.Path, e.URL, w.Kind, w.Tool, w.Command, w.Path, w.URL)
		}
	}
}

// Find returns the session whose ID matches, or fails the test.
func Find(t *testing.T, ss []*event.Session, id string) *event.Session {
	t.Helper()
	for _, s := range ss {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("session %s not found", id)
	return nil
}
