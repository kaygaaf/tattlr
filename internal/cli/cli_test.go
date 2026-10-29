package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func fixtures() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "testdata", "home")
}

func run(t *testing.T, home, stdin string, tty bool, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	env := Env{Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb, Home: home, Now: now, TTY: tty, InTTY: tty,
		Getenv: func(string) string { return "" }}
	code := Run(args, env)
	return code, out.String(), errb.String()
}

func TestScanCommand(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
		want []string
		not  []string
	}{
		{"default", []string{"scan"}, 0, []string{"RAP SHEET", "WORST MOMENTS"}, []string{"\x1b["}},
		{"no args", nil, 0, []string{"RAP SHEET"}, nil},
		{"agent filter", []string{"scan", "--agent", "gemini"}, 0, []string{"gemini-cli"}, []string{"claude-code"}},
		{"bad agent", []string{"scan", "--agent", "clippy"}, 2, nil, nil},
		{"bad since", []string{"scan", "--since", "yesterday-ish"}, 2, nil, nil},
		{"fail on critical", []string{"scan", "--fail-on", "critical"}, 1, []string{"RAP SHEET"}, nil},
		{"fail on but filtered clean", []string{"scan", "--fail-on", "high", "--project", "nope"}, 0, []string{"No agent activity"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errs := run(t, fixtures(), "", false, c.args...)
			if code != c.code {
				t.Fatalf("exit %d, want %d; stderr: %s", code, c.code, errs)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q", w)
				}
			}
			for _, n := range c.not {
				if strings.Contains(out, n) {
					t.Errorf("unexpected %q", n)
				}
			}
		})
	}
}

func TestScanJSONAndCard(t *testing.T) {
	card := filepath.Join(t.TempDir(), "card.svg")
	code, out, errs := run(t, fixtures(), "", false, "scan", "--json", "--card", card)
	if code != 0 {
		t.Fatal(errs)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	b, err := os.ReadFile(card)
	if err != nil || !bytes.HasPrefix(b, []byte("<svg")) {
		t.Fatalf("card: %v %q", err, b[:min(len(b), 40)])
	}
}

func TestTrapRoundTrip(t *testing.T) {
	home := t.TempDir()
	// No tty and no --yes: refuse.
	if code, _, _ := run(t, home, "", false, "trap"); code != 1 {
		t.Fatalf("want refusal without a terminal, got %d", code)
	}
	// Answer no.
	if code, out, _ := run(t, home, "n\n", true, "trap"); code != 0 || !strings.Contains(out, "nothing planted") {
		t.Fatalf("decline: %d %s", code, out)
	}
	if _, err := os.Stat(filepath.Join(home, ".aws", "credentials")); !os.IsNotExist(err) {
		t.Fatal("planted after saying no")
	}
	// Answer yes.
	if code, out, errs := run(t, home, "y\n", true, "trap"); code != 0 || !strings.Contains(out, "planted") {
		t.Fatalf("plant: %d %s %s", code, out, errs)
	}
	_, out, _ := run(t, home, "", false, "trap", "--list")
	if !strings.Contains(out, "aws-profile") || !strings.Contains(out, "decoy-env") {
		t.Fatalf("list: %s", out)
	}
	_, out, _ = run(t, home, "", false, "trap", "--yes")
	if !strings.Contains(out, "Nothing new") {
		t.Errorf("second plant: %s", out)
	}
	if code, _, errs := run(t, home, "", false, "trap", "--remove"); code != 0 {
		t.Fatal(errs)
	}
	_, out, _ = run(t, home, "", false, "trap", "--list")
	if !strings.Contains(out, "No canaries") {
		t.Errorf("after remove: %s", out)
	}
}

func TestParseSince(t *testing.T) {
	cases := []struct {
		in   string
		want time.Time
		err  bool
	}{
		{"24h", now.Add(-24 * time.Hour), false},
		{"7d", now.AddDate(0, 0, -7), false},
		{"2w", now.AddDate(0, 0, -14), false},
		{"3mo", now.AddDate(0, -3, 0), false},
		{"30m", now.Add(-30 * time.Minute), false},
		{"2026-10-01T00:00:00Z", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), false},
		{"soon", time.Time{}, true},
	}
	for _, c := range cases {
		got, err := ParseSince(c.in, now)
		if (err != nil) != c.err || !got.Equal(c.want) {
			t.Errorf("ParseSince(%q) = %v, %v", c.in, got, err)
		}
	}
	if d, err := ParseSince("2026-10-01", now); err != nil || d.Day() != 1 {
		t.Errorf("date: %v %v", d, err)
	}
}

func TestVersionAndRules(t *testing.T) {
	if _, out, _ := run(t, t.TempDir(), "", false, "version"); !strings.HasPrefix(out, "tattlr ") {
		t.Error(out)
	}
	_, out, _ := run(t, t.TempDir(), "", false, "rules")
	if !strings.Contains(out, "remote-code") || !strings.HasPrefix(out, "critical") {
		t.Error(out)
	}
	if code, _, _ := run(t, t.TempDir(), "", false, "bogus"); code != 2 {
		t.Error("unknown command should exit 2")
	}
}
