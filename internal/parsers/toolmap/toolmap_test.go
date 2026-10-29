package toolmap

import (
	"reflect"
	"testing"

	"github.com/kaygaaf/tattlr/internal/event"
)

func TestFill(t *testing.T) {
	tests := []struct {
		name      string
		tool      string
		args      map[string]any
		kind      event.Kind
		command   string
		path      string
		url       string
		escalated bool
	}{
		{"claude bash", "Bash", map[string]any{"command": "ls -la"}, event.Shell, "ls -la", "", "", false},
		{"claude bash no sandbox", "Bash", map[string]any{"command": "make", "dangerouslyDisableSandbox": true}, event.Shell, "make", "", "", true},
		{"claude read", "Read", map[string]any{"file_path": "/a/.env"}, event.Read, "", "/a/.env", "", false},
		{"claude edit", "Edit", map[string]any{"file_path": "/a/b.go", "old_string": "x", "new_string": "y"}, event.Write, "", "/a/b.go", "", false},
		{"claude webfetch", "WebFetch", map[string]any{"url": "https://x.dev", "prompt": "sum"}, event.Fetch, "", "", "https://x.dev", false},
		{"codex shell argv", "shell", map[string]any{"command": []any{"bash", "-lc", "rm -rf build"}}, event.Shell, "rm -rf build", "", "", false},
		{"codex escalated", "shell", map[string]any{"command": []any{"ls"}, "with_escalated_permissions": true}, event.Shell, "ls", "", "", true},
		{"codex exec_command", "exec_command", map[string]any{"cmd": "npm test", "sandbox_permissions": "require_escalated"}, event.Shell, "npm test", "", "", true},
		{"gemini read_file", "read_file", map[string]any{"absolute_path": "/k/.npmrc"}, event.Read, "", "/k/.npmrc", "", false},
		{"gemini many files", "read_many_files", map[string]any{"paths": []any{"a.go", "b.go"}}, event.Read, "", "a.go\nb.go", "", false},
		{"gemini search url in query", "google_web_search", map[string]any{"query": "see https://evil.test/x"}, event.Fetch, "", "", "https://evil.test/x", false},
		{"openclaw exec", "exec", map[string]any{"command": "whoami"}, event.Shell, "whoami", "", "", false},
		{"cursor strreplace", "StrReplace", map[string]any{"path": "/p/x.ts"}, event.Write, "", "/p/x.ts", "", false},
		{"mcp tool", "mcp__github__create_issue", map[string]any{"title": "t"}, event.MCP, "", "", "", false},
		{"unknown with command", "mystery", map[string]any{"command": "id"}, event.Shell, "id", "", "", false},
		{"unknown with url", "mystery", map[string]any{"url": "https://a.b"}, event.Fetch, "", "", "https://a.b", false},
		{"unknown nothing", "mystery", nil, event.Other, "", "", "", false},
		{"command ignored on reads", "Read", map[string]any{"file_path": "/x", "command": "rm -rf /"}, event.Read, "", "/x", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var e event.Event
			Fill(&e, tc.tool, tc.args)
			if e.Kind != tc.kind || e.Command != tc.command || e.Path != tc.path || e.URL != tc.url || e.Escalated != tc.escalated {
				t.Errorf("got kind=%q cmd=%q path=%q url=%q esc=%v", e.Kind, e.Command, e.Path, e.URL, e.Escalated)
			}
			if e.Tool != tc.tool {
				t.Errorf("tool = %q", e.Tool)
			}
		})
	}
}

func TestPatchFiles(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: a.txt\n+hi\n*** Update File: src/b.go\n*** Move to: src/c.go\n@@\n*** Delete File: old.md\n*** End Patch"
	want := []string{"a.txt", "src/b.go", "src/c.go", "old.md"}
	if got := PatchFiles(patch); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
