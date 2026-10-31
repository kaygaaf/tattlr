package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateDirIgnoresXDGForFakeHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	home := t.TempDir()
	want := filepath.Join(home, ".local", "state", "tattlr")
	if got := StateDir(home); got != want {
		t.Fatalf("StateDir(fake home) = %q, want %q", got, want)
	}
}

func TestStateDirUsesXDGForRealHome(t *testing.T) {
	real, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir:", err)
	}
	xdg := t.TempDir()
	t.Setenv("XDG_STATE_HOME", xdg)
	if got, want := StateDir(real), filepath.Join(xdg, "tattlr"); got != want {
		t.Fatalf("StateDir(real home) = %q, want %q", got, want)
	}
	if got, want := AuditPath(real), filepath.Join(xdg, "tattlr", "audit.jsonl"); got != want {
		t.Fatalf("AuditPath(real home) = %q, want %q", got, want)
	}
}

func TestProtectedCoversOwnFiles(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin", "tattlr")
	got := Protected(home, bin)

	if !strings.HasSuffix(got[0], "/") || got[0] != Dir(home)+"/" {
		t.Errorf("first entry should be the config dir as a folder, got %q", got[0])
	}
	if got[1] != StateDir(home)+"/" {
		t.Errorf("second entry should be the state dir as a folder, got %q", got[1])
	}
	for _, f := range HookConfigs(home) {
		if !contains(got, f) {
			t.Errorf("hook config %q missing from protected list", f)
		}
	}
	if got[len(got)-1] != bin {
		t.Errorf("binary should be last, got %q", got[len(got)-1])
	}
	if n := len(Protected(home, "")); n != len(got)-1 {
		t.Errorf("empty bin should be left out: got %d entries, want %d", n, len(got)-1)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
