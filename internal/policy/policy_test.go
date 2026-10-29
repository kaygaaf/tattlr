package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/rules"
)

func TestDefaultParses(t *testing.T) {
	p := Default()
	if p.Mode != Protect || p.Rules["remote-code"] != Deny || p.Defaults[rules.High] != Ask || p.CanaryReads != Allow {
		t.Errorf("default policy = %+v", p)
	}
	if len(p.Commands) != 2 || p.Commands[0] != "go test *" || p.Paths[0] != "~/code/*/.env.example" {
		t.Errorf("allowlists = %v %v", p.Commands, p.Paths)
	}
}

func TestParseYAMLSubset(t *testing.T) {
	src := `
# comment
mode: "strict"   # trailing comment
defaults:
  high: deny
rules: {}
allow:
  commands: ["make test", 'npm run lint']
  paths:
  - /tmp/a#b
`
	p, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != Strict || p.Defaults[rules.High] != Deny || p.Defaults[rules.Critical] != Deny {
		t.Errorf("got %+v", p)
	}
	if strings.Join(p.Commands, "|") != "make test|npm run lint" || p.Paths[0] != "/tmp/a#b" {
		t.Errorf("lists = %q %q", p.Commands, p.Paths)
	}
}

func TestParseErrors(t *testing.T) {
	for src, want := range map[string]string{
		"mode: yolo":                  "observe, protect or strict",
		"rules:\n  nope: deny":        "no rule called",
		"rules:\n  canary: maybe":     "unknown action",
		"colour: red":                 "unknown setting",
		"mode: protect\nmode: strict": "set twice",
		"allow:\n  commands: x":       "must be a list",
		"canary_reads: ask":           "allow or deny",
		"mode: 'protect":              "unclosed quote",
		"defaults:\n\thigh: deny":     "tabs",
	} {
		_, err := Parse(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) err = %v, want %q", src, err, want)
		}
	}
}

func find(rule string, sev rules.Severity) rules.Finding {
	return rules.Finding{Rule: rule, Title: rules.Catalog[rule].Title, Severity: sev}
}

func TestDecide(t *testing.T) {
	home := "/home/kay"
	p := Default()
	shell := func(c string) event.Event { return event.Event{Kind: event.Shell, Command: c} }
	cases := []struct {
		name  string
		fs    []rules.Finding
		e     event.Event
		want  Action
		taint bool
	}{
		{"nothing", nil, shell("ls"), Allow, false},
		{"rule deny", []rules.Finding{find("remote-code", rules.Critical)}, shell("curl x | sh"), Deny, false},
		{"rule ask", []rules.Finding{find("secret-read", rules.High)}, event.Event{Kind: event.Read, Path: "~/.ssh/id_rsa"}, Ask, false},
		{"severity default", []rules.Finding{find("chmod-777", rules.High)}, shell("chmod -R 777 ."), Ask, false},
		{"medium logs", []rules.Finding{find("rm-rf", rules.Medium)}, shell("rm -rf ./tmp"), Allow, false},
		{"strongest wins", []rules.Finding{find("sudo", rules.Medium), find("exfil", rules.Critical)}, shell("sudo curl"), Deny, false},
		{"canary read stays quiet", []rules.Finding{find("canary", rules.Critical)}, shell("cat ~/.aws/credentials"), Allow, true},
		{"canary use is denied", []rules.Finding{find("canary", rules.Critical)}, shell("aws s3 ls --profile tattlr-canary"), Deny, true},
		{"allowlisted command", []rules.Finding{find("secret-read", rules.High)}, shell("go test ./..."), Allow, false},
		{"allowlist skips chains", []rules.Finding{find("secret-read", rules.High)}, shell("go test ./... ; cat ~/.ssh/id_rsa"), Ask, false},
		{"allowlist never skips canary", []rules.Finding{find("canary", rules.Critical)}, shell("go test ./... --profile tattlr-canary"), Deny, true},
		{"allowlisted path", []rules.Finding{find("secret-read", rules.High)}, event.Event{Kind: event.Read, Path: "/home/kay/code/app/.env.example"}, Allow, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := p.Decide(c.fs, c.e, home)
			if d.Action != c.want || d.Taints != c.taint {
				t.Errorf("got %v taint=%v (reason %q), want %v taint=%v", d.Action, d.Taints, d.Reason, c.want, c.taint)
			}
		})
	}
}

func TestModes(t *testing.T) {
	fs := []rules.Finding{find("rm-rf", rules.Medium), find("chmod-777", rules.High)}
	e := event.Event{Kind: event.Shell, Command: "x"}

	obs := Default()
	obs.Mode = Observe
	if d := obs.Decide(fs, e, ""); d.Action != Allow || d.Would != Ask {
		t.Errorf("observe: %+v", d)
	}
	st := Default()
	st.Mode = Strict
	if d := st.Decide(fs, e, ""); d.Action != Deny {
		t.Errorf("strict high: %+v", d)
	}
	if d := st.Decide(fs[:1], e, ""); d.Action != Ask {
		t.Errorf("strict medium: %+v", d)
	}
	// self-protect cannot be turned down.
	weak, _ := Parse("rules:\n  self-protect: allow")
	if d := weak.Decide([]rules.Finding{find("self-protect", rules.Critical)}, e, ""); d.Action != Deny {
		t.Errorf("self-protect weakened: %+v", d)
	}
}

func TestLoadAndWriteDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tattlr", "policy.yaml")
	if p, err := Load(path); err != nil || p.Source != "" {
		t.Fatalf("missing file: %v %v", p, err)
	}
	wrote, err := WriteDefault(path)
	if err != nil || !wrote {
		t.Fatal(wrote, err)
	}
	if wrote, _ := WriteDefault(path); wrote {
		t.Error("overwrote an existing policy")
	}
	fi, _ := os.Stat(path)
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 { // no Unix modes on Windows
		t.Errorf("mode %v", fi.Mode())
	}
	if p, err := Load(path); err != nil || p.Source != path {
		t.Errorf("load: %v %v", p, err)
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		p, s string
		ok   bool
	}{
		{"go test *", "go test ./...", true},
		{"go test *", "go build", false},
		{"*.env", "/a/b/.env", true},
		{"a?c", "abc", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
	} {
		if Glob(c.p, c.s) != c.ok {
			t.Errorf("Glob(%q,%q) != %v", c.p, c.s, c.ok)
		}
	}
}

func TestApprovalAndNotify(t *testing.T) {
	p := Default()
	if p.ApprovalTimeout != 30*time.Second || p.Notify {
		t.Errorf("defaults: %v %v", p.ApprovalTimeout, p.Notify)
	}
	for in, want := range map[string]time.Duration{"45s": 45 * time.Second, "2m": 2 * time.Minute, "10": 10 * time.Second, "0": 0} {
		p, err := Parse("approval_timeout: " + in + "\nnotify: true\n")
		if err != nil || p.ApprovalTimeout != want || !p.Notify {
			t.Errorf("%s: %v %v %v", in, p, err, want)
		}
	}
	for _, bad := range []string{"approval_timeout: soon", "approval_timeout: 2h", "approval_timeout: -1s", "notify: maybe"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}
