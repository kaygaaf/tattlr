package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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
	payload := `{"hook_event_name":"PreToolUse","session_id":"s","cwd":` + jsonString(home) + `,"tool_name":"Bash","tool_input":{"command":"tattlr protect uninstall --yes"}}`
	code, out, _ = run(t, home, payload, false, "hook", "claude")
	if code != 0 || !strings.Contains(out, `"permissionDecision":"deny"`) {
		t.Errorf("hook: %d %s", code, out)
	}
	if code, _, _ := run(t, home, "{}", false, "hook"); code != 2 {
		t.Errorf("hook without agent: %d", code)
	}
	if code, out, _ := run(t, home, "", false, "protect", "install", "--agent", "gemini", "--bin", bin, "--yes"); code != 0 || !strings.Contains(out, "gemini") {
		t.Errorf("gemini install: %d\n%s", code, out)
	}

	code, out, _ = run(t, home, "", false, "protect", "uninstall", "--yes")
	if code != 0 || !strings.Contains(out, "claude: removed") || !strings.Contains(out, "gemini: removed") || strings.Contains(out, "codex") {
		t.Errorf("uninstall: %d\n%s", code, out)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Error("settings.json left behind")
	}
}

func TestProtectStatusListsHomeExtras(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		home := t.TempDir()
		code, out, errs := run(t, home, "", false, "protect", "status")
		if code != 0 {
			t.Fatalf("exit %d: %s\n%s", code, errs, out)
		}
		if !strings.Contains(out, "No extra session-start hooks") {
			t.Fatalf("missing empty note:\n%s", out)
		}
		if strings.Contains(out, "MCP server") || strings.Contains(out, "tattlr hook") {
			t.Fatalf("empty home listed a hook:\n%s", out)
		}
	})

	t.Run("only ours", func(t *testing.T) {
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
			t.Fatal(err)
		}
		ours := `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/usr/local/bin/tattlr hook claude"}]}
    ]
  }
}
`
		if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(ours), 0o644); err != nil {
			t.Fatal(err)
		}
		code, out, errs := run(t, home, "", false, "protect", "status")
		if code != 0 {
			t.Fatalf("exit %d: %s\n%s", code, errs, out)
		}
		if !strings.Contains(out, "claude  hooked up") || !strings.Contains(out, "No extra session-start hooks") {
			t.Fatalf("status:\n%s", out)
		}
		if strings.Contains(out, "tattlr hook") || strings.Contains(out, "MCP server") {
			t.Fatalf("flagged our hook:\n%s", out)
		}
	})

	t.Run("stranger", func(t *testing.T) {
		home := t.TempDir()
		if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
			t.Fatal(err)
		}
		settings := `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/usr/local/bin/tattlr hook claude"}]}
    ],
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "bash .hidden/setup.sh"}]}
    ]
  }
}
`
		mcp := `{
  "mcpServers": {
    "docs": {"url": "https://example.com/mcp"},
    "local": {"command": "/opt/bin/agent-mcp"}
  }
}
`
		if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(settings), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(mcp), 0o644); err != nil {
			t.Fatal(err)
		}
		code, out, errs := run(t, home, "", false, "protect", "status")
		if code != 0 {
			t.Fatalf("exit %d: %s\n%s", code, errs, out)
		}
		for _, want := range []string{
			"bash .hidden/setup.sh",
			"/opt/bin/agent-mcp",
			".claude/settings.json",
			".claude.json",
			"outside the PreToolUse hook",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("missing %q in:\n%s", want, out)
			}
		}
		if strings.Contains(out, "tattlr hook") || strings.Contains(out, "example.com") {
			t.Fatalf("flagged our hook or a URL server:\n%s", out)
		}
		if strings.Contains(out, `\`) {
			t.Fatalf("status path has a backslash:\n%s", out)
		}

		_, js, _ := run(t, home, "", false, "protect", "status", "--json")
		var doc struct {
			HomeHooks []struct {
				File   string `json:"file"`
				Detail string `json:"detail"`
			} `json:"home_hooks"`
		}
		if err := json.Unmarshal([]byte(js), &doc); err != nil {
			t.Fatalf("json: %v\n%s", err, js)
		}
		if len(doc.HomeHooks) != 2 {
			t.Fatalf("home_hooks: %+v\n%s", doc.HomeHooks, js)
		}
		blob := doc.HomeHooks[0].File + doc.HomeHooks[0].Detail + doc.HomeHooks[1].File + doc.HomeHooks[1].Detail
		for _, want := range []string{"bash .hidden/setup.sh", "/opt/bin/agent-mcp", ".claude/settings.json", ".claude.json"} {
			if !strings.Contains(blob, want) {
				t.Errorf("json missing %q in %s", want, blob)
			}
		}
		if strings.Contains(blob, "tattlr hook") || strings.Contains(blob, "example.com") || strings.Contains(blob, `\`) {
			t.Fatalf("json home_hooks: %s", blob)
		}
	})
}

func TestTempBin(t *testing.T) {
	if tempBin("/home/kay/.npm/_npx/1a2b/node_modules/tattlr-linux-x64/bin/tattlr") == "" {
		t.Error("npx cache path should warn")
	}
	if tempBin(filepath.Join(os.TempDir(), "x", "tattlr")) == "" {
		t.Error("temp dir path should warn")
	}
	if real, err := filepath.EvalSymlinks(os.TempDir()); err == nil {
		if tempBin(filepath.Join(real, "x", "tattlr")) == "" {
			t.Error("resolved temp dir path should warn")
		}
	}
	if runtime.GOOS != "windows" {
		t.Setenv("TMPDIR", "/tmp/fake-tmp/")
		if tempBin("/tmp/fake-tmp/x/tattlr") == "" {
			t.Error("TMPDIR with a trailing slash should still match")
		}
	}
	if got := tempBin("/home/kay/.local/bin/tattlr"); got != "" {
		t.Errorf("normal install warned: %s", got)
	}
}
