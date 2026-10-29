// Package cursor reads Cursor agent transcripts from
// ~/.cursor/projects/<encoded-path>/agent-transcripts/<id>/<id>.jsonl
// (and the flat agent-transcripts/<id>.jsonl layout).
//
// Lines are {role, message:{content:[...]}} with Anthropic-style blocks:
// tool_use {id, name, input} and tool_result {tool_use_id, content}. The
// transcripts carry no per-line timestamps, so tattlr uses the file mtime.
//
// Cursor also keeps chats in SQLite (~/.cursor/chats/<hash>/<id>/store.db and
// the IDE's state.vscdb). tattlr does not read those yet.
package cursor

import (
	"path/filepath"
	"strings"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers/jsonl"
	"github.com/kaygaaf/tattlr/internal/parsers/toolmap"
)

// Parser reads Cursor transcripts.
type Parser struct{}

func (Parser) Agent() string { return event.AgentCursor }

func (Parser) Discover(home string) []string {
	return jsonl.Walk(filepath.Join(home, ".cursor", "projects"), func(p string) bool {
		return strings.HasSuffix(p, ".jsonl") && strings.Contains(filepath.ToSlash(p), "/agent-transcripts/")
	})
}

func (Parser) Parse(path string) (*event.Session, error) {
	s := &event.Session{Agent: event.AgentCursor, Source: path, Start: jsonl.ModTime(path)}
	s.ID = strings.TrimSuffix(filepath.Base(path), ".jsonl")
	s.Project = projectFromPath(path)
	idx := map[string]int{}
	err := jsonl.EachLine(path, func(m map[string]any) {
		ts := jsonl.Time(m["timestamp"])
		if ts.IsZero() {
			ts = s.Start
		}
		for _, b := range jsonl.Arr(jsonl.Obj(m, "message"), "content") {
			blk, _ := b.(map[string]any)
			switch jsonl.Str(blk, "type") {
			case "tool_use":
				e := event.Event{Agent: event.AgentCursor, SessionID: s.ID, Project: s.Project, Source: path,
					Time: ts, CallID: jsonl.Str(blk, "id")}
				toolmap.Fill(&e, jsonl.Str(blk, "name"), jsonl.Obj(blk, "input"))
				idx[e.CallID] = len(s.Events)
				s.Events = append(s.Events, e)
			case "tool_result":
				if i, ok := idx[jsonl.Str(blk, "tool_use_id")]; ok {
					s.Events[i].Output = jsonl.ContentText(blk["content"])
				}
			}
		}
	})
	if p := projectFromEvents(s.Project, path, s.Events); p != "" {
		s.Project = p
		for i := range s.Events {
			s.Events[i].Project = p
		}
	}
	return s, err
}

// encodeProject mirrors how Cursor names project folders: drop the leading
// slash and turn every non-alphanumeric character into a dash.
func encodeProject(dir string) string {
	var b strings.Builder
	for _, r := range strings.TrimPrefix(filepath.ToSlash(dir), "/") {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

// projectFromEvents fixes the lossy folder name by finding an absolute path
// the agent touched whose parent folder encodes to the same name.
func projectFromEvents(guess, path string, evs []event.Event) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	enc := ""
	for i, p := range parts {
		if p == "agent-transcripts" && i > 0 {
			enc = parts[i-1]
		}
	}
	if enc == "" {
		return ""
	}
	for _, e := range evs {
		for _, cand := range append([]string{e.Path}, strings.Fields(e.Command)...) {
			if !strings.HasPrefix(cand, "/") {
				continue
			}
			dir := cand
			for dir != "/" && dir != "." && dir != "" {
				if encodeProject(dir) == enc {
					return dir
				}
				dir = filepath.Dir(dir)
			}
		}
	}
	return ""
}

// projectFromPath pulls the project folder out of
// .../projects/<encoded>/agent-transcripts/... Cursor encodes "/a/b" as "a-b",
// which is lossy, so this is a best guess.
func projectFromPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i, p := range parts {
		if p == "agent-transcripts" && i > 0 {
			enc := parts[i-1]
			if strings.Contains(enc, "-") {
				return "/" + strings.ReplaceAll(enc, "-", "/")
			}
			return enc
		}
	}
	return ""
}
