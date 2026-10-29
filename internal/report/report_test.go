package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kaygaaf/tattlr/internal/scan"
)

func result(t *testing.T) *scan.Result {
	_, f, _, _ := runtime.Caller(0)
	res, err := scan.Run(scan.Options{Home: filepath.Join(filepath.Dir(f), "..", "..", "testdata", "home")})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestText(t *testing.T) {
	res := result(t)
	cases := []struct {
		color bool
		esc   bool
	}{{false, false}, {true, true}}
	for _, c := range cases {
		var b bytes.Buffer
		Text(&b, res, TextOptions{Color: c.color, Loc: time.UTC})
		out := b.String()
		for _, want := range []string{"RAP SHEET", "TOP OFFENSES", "WORST MOMENTS", "claude-code", "Touched a tattlr canary"} {
			if !strings.Contains(out, want) {
				t.Errorf("missing %q in:\n%s", want, out)
			}
		}
		if strings.Contains(out, "\x1b[") != c.esc {
			t.Errorf("color=%v but escape codes present=%v", c.color, !c.esc)
		}
		if strings.Contains(out, "/Users/kay") {
			t.Error("home path not shortened")
		}
		if strings.Contains(out, "\u2014") {
			t.Error("em dash in output")
		}
	}
}

func TestTextEmpty(t *testing.T) {
	var b bytes.Buffer
	Text(&b, &scan.Result{Home: "/home/x"}, TextOptions{})
	if !strings.Contains(b.String(), "No agent activity") {
		t.Error(b.String())
	}
}

func TestJSON(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, result(t)); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"agents", "offenses", "moments", "findings", "tool_calls"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %s", k)
		}
	}
}

func TestCardIsValidSVG(t *testing.T) {
	var b bytes.Buffer
	if err := Card(&b, result(t), time.UTC); err != nil {
		t.Fatal(err)
	}
	d := xml.NewDecoder(&b)
	for {
		_, err := d.Token()
		if err != nil {
			if err.Error() != "EOF" {
				t.Fatalf("invalid SVG: %v", err)
			}
			break
		}
	}
}

func TestCardHasNoDetails(t *testing.T) {
	var b bytes.Buffer
	Card(&b, result(t), time.UTC)
	for _, bad := range []string{"/Users", "billing-api", "curl", ".aws"} {
		if strings.Contains(b.String(), bad) {
			t.Errorf("card leaks %q", bad)
		}
	}
}

func TestTilde(t *testing.T) {
	cases := map[string]string{
		"/Users/kay/code/x":         "~/code/x",
		"cat /home/bob/.ssh/id_rsa": "cat ~/.ssh/id_rsa",
		"/root":                     "~",
		"/usr/local/bin":            "/usr/local/bin",
	}
	for in, want := range cases {
		if got := tilde(in); got != want {
			t.Errorf("tilde(%q) = %q, want %q", in, got, want)
		}
	}
}
