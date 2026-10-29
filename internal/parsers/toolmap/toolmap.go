// Package toolmap maps agent-specific tool names and arguments onto the
// normalized event kinds. Tool names barely collide across agents, so one
// table covers Claude Code, Codex, Gemini CLI, OpenClaw and Cursor.
package toolmap

import (
	"regexp"
	"strings"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers/jsonl"
)

var kinds = map[string]event.Kind{
	// Claude Code
	"bash": event.Shell, "read": event.Read, "write": event.Write, "edit": event.Write,
	"multiedit": event.Write, "notebookedit": event.Write, "notebookread": event.Read,
	"webfetch": event.Fetch, "websearch": event.Fetch, "grep": event.Search, "glob": event.Search, "ls": event.Search,
	// Codex
	"shell": event.Shell, "exec_command": event.Shell, "local_shell": event.Shell, "container.exec": event.Shell,
	"apply_patch": event.Write, "web_search": event.Fetch, "view_image": event.Read,
	// Gemini CLI
	"run_shell_command": event.Shell, "read_file": event.Read, "read_many_files": event.Read,
	"write_file": event.Write, "replace": event.Write, "web_fetch": event.Fetch,
	"google_web_search": event.Fetch, "list_directory": event.Search, "search_file_content": event.Search,
	"grep_search": event.Search,
	// OpenClaw
	"exec": event.Shell, "process": event.Shell, "browser": event.Fetch,
	// Cursor
	"strreplace": event.Write, "delete": event.Write, "run_terminal_cmd": event.Shell,
	"edit_file": event.Write, "search_replace": event.Write, "delete_file": event.Write,
	"codebase_search": event.Search,
}

var urlRe = regexp.MustCompile(`https?://[^\s"'<>)]+`)

// Fill sets Kind, Command, Path, URL and Args on e from a tool name and its
// decoded arguments.
func Fill(e *event.Event, name string, args map[string]any) {
	e.Tool = name
	key := strings.ToLower(name)
	kind, ok := kinds[key]
	switch {
	case ok:
	case strings.HasPrefix(key, "mcp__") || strings.Contains(key, "__") || strings.HasPrefix(key, "mcp_"):
		kind = event.MCP
	default:
		kind = guess(args)
	}
	e.Kind = kind

	if c := jsonl.FirstStr(args, "command", "cmd", "script"); c != "" {
		e.Command = c
	} else if argv := jsonl.Arr(args, "command"); argv != nil {
		e.Command = jsonl.ShellScript(argv)
	}
	if kind != event.Shell {
		e.Command = ""
	}
	e.Path = jsonl.FirstStr(args, "file_path", "absolute_path", "path", "notebook_path", "target_file", "filePath", "dir_path")
	if e.Path == "" {
		if ps := jsonl.Arr(args, "paths"); len(ps) > 0 {
			var parts []string
			for _, p := range ps {
				if s, ok := p.(string); ok {
					parts = append(parts, s)
				}
			}
			e.Path = strings.Join(parts, "\n")
		}
	}
	e.URL = jsonl.FirstStr(args, "url", "targetUrl")
	if e.URL == "" && kind == event.Fetch {
		if m := urlRe.FindString(jsonl.FirstStr(args, "prompt", "query", "q")); m != "" {
			e.URL = m
		}
	}
	if q := jsonl.FirstStr(args, "query"); e.URL == "" && q != "" {
		e.Args = "search: " + q
	}
	if e.Args == "" && kind != event.Shell && kind != event.Read {
		e.Args = jsonl.Truncate(jsonl.Compact(args), 2000)
	}
	if jsonl.Bool(args, "dangerouslyDisableSandbox") || jsonl.Bool(args, "with_escalated_permissions") ||
		jsonl.Str(args, "sandbox_permissions") == "require_escalated" {
		e.Escalated = true
	}
}

func guess(args map[string]any) event.Kind {
	switch {
	case args == nil:
		return event.Other
	case jsonl.FirstStr(args, "command", "cmd") != "" || jsonl.Arr(args, "command") != nil:
		return event.Shell
	case jsonl.FirstStr(args, "url") != "":
		return event.Fetch
	case jsonl.FirstStr(args, "content", "new_string", "old_string") != "":
		return event.Write
	case jsonl.FirstStr(args, "file_path", "path", "absolute_path") != "":
		return event.Read
	}
	return event.Other
}

// PatchFiles pulls the file paths out of an apply_patch body.
func PatchFiles(patch string) []string {
	var out []string
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		for _, p := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
			if strings.HasPrefix(line, p) {
				out = append(out, strings.TrimSpace(strings.TrimPrefix(line, p)))
			}
		}
	}
	return out
}
