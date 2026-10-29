package protect

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kaygaaf/tattlr/internal/config"
)

func opts(home string, agents ...string) (Options, *bytes.Buffer) {
	var out bytes.Buffer
	return Options{Home: home, Bin: testBin, Agents: agents, Yes: true, Out: &out,
		Now: func() time.Time { return time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC) }}, &out
}

func write(t *testing.T, p, s string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad JSON %v:\n%s", err, s)
	}
	return m
}

const claudeExisting = `{
  "model": "opus",
  "permissions": {"allow": ["Bash(npm test:*)"]},
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "~/bin/my-guard.sh"}]}
    ],
    "Stop": [{"hooks": [{"type": "command", "command": "say done"}]}]
  },
  "zeta": 1.50
}
`

func TestClaudeRoundTrip(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".claude", "settings.json")
	write(t, p, claudeExisting)
	o, out := opts(home, "claude")

	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	got := read(t, p)
	m := mustJSON(t, got)
	pre := m["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("PreToolUse has %d groups, want 2:\n%s", len(pre), got)
	}
	ours := pre[1].(map[string]any)
	h := ours["hooks"].([]any)[0].(map[string]any)
	if ours["matcher"] != "*" || h["command"] != testCmd+" hook claude" || h["type"] != "command" {
		t.Errorf("entry: %v", ours)
	}
	// Key order and the user's own hook survive.
	if strings.Index(got, `"model"`) > strings.Index(got, `"permissions"`) || !strings.Contains(got, "my-guard.sh") || !strings.Contains(got, "1.50") {
		t.Errorf("user content changed:\n%s", got)
	}
	if !strings.Contains(out.String(), "+++") || !strings.Contains(out.String(), "backed up") {
		t.Errorf("no diff or backup note:\n%s", out)
	}
	baks, _ := filepath.Glob(filepath.Join(config.BackupDir(home), "claude-settings.json.*.bak"))
	if len(baks) != 1 || read(t, baks[0]) != claudeExisting {
		t.Errorf("backups: %v", baks)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode changed to %v", fi.Mode().Perm())
	}
	if _, err := os.Stat(config.PolicyPath(home)); err != nil {
		t.Errorf("default policy not written: %v", err)
	}

	// Idempotent.
	out.Reset()
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	if read(t, p) != got || !strings.Contains(out.String(), "already installed") {
		t.Errorf("second install changed things:\n%s", out)
	}

	st := Status(home, o.Bin, o.Now())
	if len(st) != 1 || !st[0].Installed || !st[0].BinOK {
		t.Errorf("status: %+v", st)
	}

	if err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	after := read(t, p)
	if !sameJSONIgnoringLayout([]byte(after), []byte(claudeExisting)) {
		t.Errorf("uninstall did not restore the file:\n%s", after)
	}
	if strings.Contains(after, "tattlr") {
		t.Errorf("tattlr left behind:\n%s", after)
	}
}

func TestClaudeFreshFileIsDeletedOnUninstall(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	o, _ := opts(home)
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(home, ".claude", "settings.json")
	if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("settings.json not created 0600: %v", err)
	}
	if err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("created file was not removed")
	}
}

func TestStrictAddsFailClosed(t *testing.T) {
	home := t.TempDir()
	write(t, config.PolicyPath(home), "mode: strict\n")
	o, _ := opts(home, "claude", "cursor")
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, filepath.Join(home, ".claude", "settings.json")), `"onFailure": "block"`) {
		t.Error("claude: no onFailure block")
	}
	if strings.Count(read(t, filepath.Join(home, ".cursor", "hooks.json")), `"failClosed": true`) != len(cursorEvents) {
		t.Error("cursor: failClosed missing")
	}
}

func TestCursorRoundTrip(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".cursor", "hooks.json")
	orig := `{"version": 1, "hooks": {"afterFileEdit": [{"command": "./format.sh"}], "beforeShellExecution": [{"command": "./audit.sh"}]}}` + "\n"
	write(t, p, orig)
	o, _ := opts(home, "cursor")
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	m := mustJSON(t, read(t, p))
	hooks := m["hooks"].(map[string]any)
	for _, ev := range cursorEvents {
		list, _ := hooks[ev.name].([]any)
		last := list[len(list)-1].(map[string]any)
		if last["command"] != testCmd+" hook cursor" {
			t.Errorf("%s: %v", ev.name, list)
		}
		if ev.matcher != "" && last["matcher"] != ev.matcher {
			t.Errorf("%s matcher %v", ev.name, last["matcher"])
		}
	}
	if len(hooks["beforeShellExecution"].([]any)) != 2 {
		t.Error("user's beforeShellExecution hook lost")
	}
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	if len(mustJSON(t, read(t, p))["hooks"].(map[string]any)["beforeShellExecution"].([]any)) != 2 {
		t.Error("second install duplicated the hook")
	}
	if err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if !sameJSONIgnoringLayout([]byte(read(t, p)), []byte(orig)) {
		t.Errorf("not restored:\n%s", read(t, p))
	}
}

func TestCodexTOMLRoundTrip(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".codex", "config.toml")
	orig := "model = \"gpt-5-codex\"\n\n[projects.\"/home/kay/code/app\"]\ntrust_level = \"trusted\"\n"
	write(t, p, orig)
	o, out := opts(home, "codex")
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	got := read(t, p)
	for _, want := range []string{tomlBegin, "[[hooks.PreToolUse]]", "[[hooks.PreToolUse.hooks]]",
		"command = " + tomlQuote(testCmd+" hook codex"), tomlEnd} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if !strings.HasPrefix(got, orig) {
		t.Errorf("user config changed:\n%s", got)
	}
	if !strings.Contains(out.String(), "/hooks") {
		t.Error("no trust reminder")
	}
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	if read(t, p) != got {
		t.Error("second install changed config.toml")
	}
	if err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if read(t, p) != orig {
		t.Errorf("not restored:\n%q\nwant\n%q", read(t, p), orig)
	}
}

func TestCodexRefusesInlineHooks(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".codex", "config.toml"), "hooks = { PreToolUse = [] }\n")
	o, _ := opts(home, "codex")
	if err := Install(o); err == nil || !strings.Contains(err.Error(), "inline") {
		t.Errorf("want inline refusal, got %v", err)
	}
}

func TestCodexHooksJSON(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".codex", "hooks.json")
	write(t, p, `{"hooks": {}}`)
	o, _ := opts(home, "codex")
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	m := mustJSON(t, read(t, p))
	g := m["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)
	if g["matcher"] != ".*" {
		t.Errorf("codex matcher %v", g["matcher"])
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "config.toml")); err == nil {
		t.Error("touched config.toml although hooks.json exists")
	}
	if err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(read(t, p), "tattlr") {
		t.Error("left behind")
	}
}

func TestBrokenJSONIsRefused(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".claude", "settings.json")
	write(t, p, `{"model": "opus",}`)
	o, _ := opts(home, "claude")
	if err := Install(o); err == nil {
		t.Fatal("installed into broken JSON")
	}
	if read(t, p) != `{"model": "opus",}` {
		t.Error("broken file was touched")
	}
}

func TestConfirmPrompt(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	o, _ := opts(home)
	o.Yes = false
	if err := Install(o); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("non-TTY without --yes: %v", err)
	}
	o.IsTTY, o.In = true, strings.NewReader("n\n")
	if err := Install(o); err != ErrAborted {
		t.Errorf("answer n: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err == nil {
		t.Error("wrote after no")
	}
	o.In = strings.NewReader("y\n")
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
}

func TestSymlinkedConfigStaysALink(t *testing.T) {
	home := t.TempDir()
	real := filepath.Join(home, "dotfiles", "claude-settings.json")
	write(t, real, "{}\n")
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	link := filepath.Join(home, ".claude", "settings.json")
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}
	o, _ := opts(home, "claude")
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink replaced by a file")
	}
	if !strings.Contains(read(t, real), "hook claude") {
		t.Error("target not updated")
	}
}

func TestDiff(t *testing.T) {
	d := unifiedDiff("f", "a\nb\nc\n", "a\nb\nx\nc\n")
	if !strings.Contains(d, "+x\n") || !strings.Contains(d, "@@ -1,3 +1,4 @@") {
		t.Errorf("diff:\n%s", d)
	}
	if unifiedDiff("f", "a\n", "a\n") != "" {
		t.Error("diff of equal texts")
	}
}

func TestGeminiRoundTrip(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".gemini", "settings.json")
	orig := `{"general": {"vimMode": true}, "hooks": {"BeforeTool": [{"matcher": "write_file", "hooks": [{"type": "command", "command": "./lint.sh"}]}]}}` + "\n"
	write(t, p, orig)
	o, out := opts(home, "gemini")
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	m := mustJSON(t, read(t, p))
	groups := m["hooks"].(map[string]any)["BeforeTool"].([]any)
	if len(groups) != 2 {
		t.Fatalf("groups: %v", groups)
	}
	g := groups[1].(map[string]any)
	h := g["hooks"].([]any)[0].(map[string]any)
	if g["matcher"] != ".*" || h["command"] != testCmd+" hook gemini" || h["timeout"] != float64(10000) || h["name"] != "tattlr" {
		t.Errorf("entry: %v", g)
	}
	if !strings.Contains(out.String(), "fails open") {
		t.Errorf("missing note:\n%s", out)
	}
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	if n := len(mustJSON(t, read(t, p))["hooks"].(map[string]any)["BeforeTool"].([]any)); n != 2 {
		t.Errorf("second install: %d groups", n)
	}
	st := Status(home, testBin, time.Now())
	found := false
	for _, s := range st {
		if s.Agent == "gemini" && s.Installed {
			found = true
		}
	}
	if !found {
		t.Errorf("status: %+v", st)
	}
	if err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if !sameJSONIgnoringLayout([]byte(read(t, p)), []byte(orig)) {
		t.Errorf("not restored:\n%s", read(t, p))
	}
}

func TestGeminiFreshFileAndHooksOffWarning(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".gemini", "settings.json")
	o, _ := opts(home, "gemini")
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("settings.json we created was left behind")
	}
	write(t, p, `{"hooksConfig": {"enabled": false}}`)
	o, out := opts(home, "gemini")
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "hooksConfig.enabled is false") {
		t.Errorf("no warning:\n%s", out)
	}
}

func TestHookTimeoutCoversApprovalWait(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".config", "tattlr", "policy.yaml"), "approval_timeout: 45s\n")
	o, _ := opts(home, "claude", "codex", "cursor")
	if err := Install(o); err != nil {
		t.Fatal(err)
	}
	if s := read(t, filepath.Join(home, ".codex", "config.toml")); !strings.Contains(s, "timeout = 55\n") {
		t.Errorf("codex:\n%s", s)
	}
	if s := read(t, filepath.Join(home, ".cursor", "hooks.json")); !strings.Contains(s, `"timeout": 55`) {
		t.Errorf("cursor:\n%s", s)
	}
	if s := read(t, filepath.Join(home, ".claude", "settings.json")); !strings.Contains(s, `"timeout": 10`) {
		t.Errorf("claude has its own prompt and keeps 10s:\n%s", s)
	}
}

// config.toml as Codex 0.165.0 left it after trusting the hook in /hooks:
// it appended its tables inside our markers, because our block was last.
const codexAfterTrust = `model = "gpt-5"

# >>> tattlr protect >>>
[[hooks.PreToolUse]]
matcher = ".*"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/home/kay/.local/bin/tattlr hook codex"
timeout = 40

[hooks.state]

[hooks.state."/home/kay/.codex/config.toml:pre_tool_use:0:0"]
trusted_hash = "sha256:e9dfa3bf8f24bfc596c5cb3091054e51f33097bcebd97f8e50e01b199e153e97"

[projects."/home/kay/code/proj"]
trust_level = "trusted"
# <<< tattlr protect <<<
`

func TestTomlKeepsWhatCodexAppended(t *testing.T) {
	cmd := "/home/kay/.local/bin/tattlr hook codex"
	// Same hook again: nothing to do, so trust stays.
	out, _, err := tomlInstall(codexAfterTrust, cmd, 40)
	if err != nil || string(out) != codexAfterTrust {
		t.Fatalf("reinstall changed the file (err %v):\n%s", err, out)
	}
	// Uninstall must keep Codex's own tables.
	stripped := tomlStrip(codexAfterTrust)
	for _, want := range []string{`model = "gpt-5"`, `[hooks.state."/home/kay/.codex/config.toml:pre_tool_use:0:0"]`, `trusted_hash = "sha256:e9df`, `trust_level = "trusted"`} {
		if !strings.Contains(stripped, want) {
			t.Errorf("uninstall dropped %q:\n%s", want, stripped)
		}
	}
	for _, gone := range []string{"tattlr hook codex", tomlBegin, tomlEnd, "[[hooks.PreToolUse]]"} {
		if strings.Contains(stripped, gone) {
			t.Errorf("uninstall left %q:\n%s", gone, stripped)
		}
	}
	// A new binary path rewrites our tables in place and keeps the rest.
	out, _, err = tomlInstall(codexAfterTrust, "/opt/tattlr hook codex", 40)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `command = "/opt/tattlr hook codex"`) || strings.Contains(s, "/home/kay/.local/bin/tattlr") ||
		!strings.Contains(s, "trusted_hash") || !strings.Contains(s, `trust_level = "trusted"`) {
		t.Errorf("rewrite lost something:\n%s", s)
	}
	if strings.Index(s, "[[hooks.PreToolUse]]") > strings.Index(s, "[hooks.state]") {
		t.Errorf("block moved after the state tables:\n%s", s)
	}
	if again, _, _ := tomlInstall(s, "/opt/tattlr hook codex", 40); string(again) != s {
		t.Errorf("second rewrite not a no-op:\n%s", again)
	}
}

// testBin is an absolute binary path with a space in it, on whatever OS the
// tests run on. testCmd is how it shows up in hook commands.
var testBin, testCmd = func() (string, string) {
	if runtime.GOOS == "windows" {
		return `C:\opt\tattlr bin\tattlr.exe`, `"C:/opt/tattlr bin/tattlr.exe"`
	}
	return "/opt/tattlr bin/tattlr", `'/opt/tattlr bin/tattlr'`
}()

func tomlQuote(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"/home/kay/.local/bin/tattlr":                  "/home/kay/.local/bin/tattlr",
		"/opt/tattlr bin/tattlr":                       `'/opt/tattlr bin/tattlr'`,
		"/opt/it's/tattlr":                             `'/opt/it'\''s/tattlr'`,
		`C:\Users\kay\AppData\Local\tattlr\tattlr.exe`: "C:/Users/kay/AppData/Local/tattlr/tattlr.exe",
		`C:\Users\RUNNER~1\bin\tattlr.exe`:             "C:/Users/RUNNER~1/bin/tattlr.exe",
		`C:\Program Files\tattlr\tattlr.exe`:           `"C:/Program Files/tattlr/tattlr.exe"`,
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
