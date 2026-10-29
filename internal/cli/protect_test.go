package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectCommands(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".claude"), 0o755)
	bin := filepath.Join(home, "bin", "tattlr")

	if code, _, errs := run(t, home, "", false, "protect", "install", "--bin", bin); code != 1 || !strings.Contains(errs, "--yes") {
		t.Errorf("non-TTY install without --yes: %d %q", code, errs)
	}
	if code, out, _ := run(t, home, "n\n", true, "protect", "install", "--bin", bin); code != 1 || !strings.Contains(out, "nothing changed") {
		t.Errorf("answer no: %d\n%s", code, out)
	}
	code, out, errs := run(t, home, "", false, "protect", "install", "--bin", bin, "--yes")
	if code != 0 || !strings.Contains(out, "claude: hooked up") {
		t.Fatalf("install: %d\n%s\n%s", code, out, errs)
	}
	_, out, _ = run(t, home, "", false, "protect", "status")
	if !strings.Contains(out, "claude  hooked up") || !strings.Contains(out, "Self-test: ok") {
		t.Errorf("status:\n%s", out)
	}

	// The hook the config points at answers as Claude Code expects.
	payload := `{"hook_event_name":"PreToolUse","session_id":"s","cwd":"` + home + `","tool_name":"Bash","tool_input":{"command":"tattlr protect uninstall --yes"}}`
	code, out, _ = run(t, home, payload, false, "hook", "claude")
	if code != 0 || !strings.Contains(out, `"permissionDecision":"deny"`) {
		t.Errorf("hook: %d %s", code, out)
	}
	if code, _, _ := run(t, home, "{}", false, "hook"); code != 2 {
		t.Errorf("hook without agent: %d", code)
	}
	if code, _, _ := run(t, home, "", false, "protect", "install", "--agent", "gemini", "--bin", bin, "--yes"); code != 2 {
		t.Errorf("gemini should be refused: %d", code)
	}

	code, out, _ = run(t, home, "", false, "protect", "uninstall", "--yes")
	if code != 0 || !strings.Contains(out, "claude: removed") || strings.Contains(out, "codex") {
		t.Errorf("uninstall: %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Error("settings.json left behind")
	}
}
