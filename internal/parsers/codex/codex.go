// Package codex reads Codex CLI rollout files from
// ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl (and archived_sessions).
//
// Current rollouts wrap every line as {"timestamp", "type", "payload"} where
// type is session_meta, turn_context, response_item, event_msg and so on.
// Tool calls are response_item payloads of type function_call (shell,
// exec_command, apply_patch, MCP tools), custom_tool_call (apply_patch),
// local_shell_call, and web_search_call. Older rollouts skip the envelope and
// write the items directly after a first {id, timestamp, instructions} line.
package codex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers/jsonl"
	"github.com/kaygaaf/tattlr/internal/parsers/toolmap"
)

// Parser reads Codex rollouts.
type Parser struct{}

func (Parser) Agent() string { return event.AgentCodex }

func (Parser) Discover(home string) []string {
	base := filepath.Join(home, ".codex")
	if dir := os.Getenv("CODEX_HOME"); dir != "" {
		if h, _ := os.UserHomeDir(); h == home {
			base = dir
		}
	}
	keep := func(p string) bool {
		b := filepath.Base(p)
		return strings.HasPrefix(b, "rollout-") && (strings.HasSuffix(b, ".jsonl") || strings.HasSuffix(b, ".json"))
	}
	out := jsonl.Walk(filepath.Join(base, "sessions"), keep)
	return append(out, jsonl.Walk(filepath.Join(base, "archived_sessions"), keep)...)
}

func (Parser) Parse(path string) (*event.Session, error) {
	s := &event.Session{Agent: event.AgentCodex, Source: path}
	idx := map[string][]int{}
	cwd := ""
	err := jsonl.EachLine(path, func(m map[string]any) {
		ts := jsonl.Time(m["timestamp"])
		typ := jsonl.Str(m, "type")
		item := jsonl.Obj(m, "payload")
		if item == nil {
			// Old format: the line is the item itself.
			item = m
			if typ == "" && jsonl.Str(m, "id") != "" && s.ID == "" {
				s.ID = jsonl.Str(m, "id")
				s.Start = ts
				return
			}
		}
		switch typ {
		case "session_meta":
			if s.ID == "" {
				s.ID = jsonl.Str(item, "id")
			}
			if c := jsonl.Str(item, "cwd"); c != "" {
				cwd = c
				if s.Project == "" {
					s.Project = c
				}
			}
			if s.Start.IsZero() {
				s.Start = jsonl.Time(item["timestamp"])
			}
			return
		case "turn_context":
			if c := jsonl.Str(item, "cwd"); c != "" {
				cwd = c
			}
			return
		case "event_msg", "compacted":
			// event_msg duplicates the response items (exec_command_begin and
			// friends), so skip it to avoid double counting.
			return
		}
		if ts.IsZero() {
			ts = s.Start
		}
		base := event.Event{Agent: event.AgentCodex, Source: path, Time: ts, Project: cwd,
			CallID: jsonl.FirstStr(item, "call_id", "id")}
		add := func(e event.Event) {
			idx[e.CallID] = append(idx[e.CallID], len(s.Events))
			s.Events = append(s.Events, e)
		}
		switch jsonl.Str(item, "type") {
		case "function_call":
			name := jsonl.Str(item, "name")
			if ns := jsonl.Str(item, "namespace"); ns != "" && !strings.Contains(name, "__") {
				name = ns + "__" + name
			}
			var args map[string]any
			raw := jsonl.Str(item, "arguments")
			if json.Unmarshal([]byte(raw), &args) != nil {
				args = map[string]any{"input": raw}
			}
			if name == "apply_patch" {
				for _, e := range patchEvents(base, jsonl.FirstStr(args, "input", "patch"), cwd) {
					add(e)
				}
				return
			}
			e := base
			toolmap.Fill(&e, name, args)
			add(e)
		case "custom_tool_call":
			name := jsonl.Str(item, "name")
			input := jsonl.Str(item, "input")
			if name == "apply_patch" {
				for _, e := range patchEvents(base, input, cwd) {
					add(e)
				}
				return
			}
			e := base
			toolmap.Fill(&e, name, map[string]any{"input": input})
			add(e)
		case "local_shell_call":
			action := jsonl.Obj(item, "action")
			e := base
			toolmap.Fill(&e, "local_shell", map[string]any{"command": jsonl.Arr(action, "command")})
			if wd := jsonl.Str(action, "working_directory"); wd != "" && s.Project == "" {
				s.Project = wd
			}
			add(e)
		case "web_search_call":
			action := jsonl.Obj(item, "action")
			e := base
			args := map[string]any{"query": jsonl.Str(action, "query")}
			if u := jsonl.Str(action, "url"); u != "" {
				args["url"] = u
			}
			toolmap.Fill(&e, "web_search", args)
			add(e)
		case "function_call_output", "custom_tool_call_output":
			out := item["output"]
			if o, ok := out.(map[string]any); ok {
				out = o["content"]
			}
			for _, i := range idx[jsonl.Str(item, "call_id")] {
				s.Events[i].Output = jsonl.ContentText(out)
			}
		}
	})
	if s.ID == "" {
		s.ID = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	for i := range s.Events {
		s.Events[i].SessionID = s.ID
		if s.Events[i].Project == "" {
			s.Events[i].Project = s.Project
		}
	}
	return s, err
}

// patchEvents turns one apply_patch call into a write event per touched file.
// Relative paths are resolved against the session cwd.
func patchEvents(base event.Event, patch, cwd string) []event.Event {
	var out []event.Event
	for _, f := range toolmap.PatchFiles(patch) {
		if cwd != "" && !filepath.IsAbs(f) && !strings.HasPrefix(f, "~") {
			f = filepath.Join(cwd, f)
		}
		e := base
		toolmap.Fill(&e, "apply_patch", map[string]any{"path": f})
		e.Args = ""
		out = append(out, e)
	}
	return out
}
