// Package claude reads Claude Code session logs from
// ~/.claude/projects/<encoded-cwd>/<session-id>.jsonl.
//
// Each line is an object with type "user", "assistant", "summary" and so on.
// Assistant lines carry message.content[] blocks; tool calls are blocks of
// type "tool_use" with name and input. Tool results come back as
// "tool_result" blocks in the next user line, keyed by tool_use_id.
package claude

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers/jsonl"
	"github.com/kaygaaf/tattlr/internal/parsers/toolmap"
)

// Parser reads Claude Code logs.
type Parser struct{}

func (Parser) Agent() string { return event.AgentClaude }

func (Parser) Discover(home string) []string {
	roots := []string{filepath.Join(home, ".claude", "projects")}
	if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" && home == userHome() {
		roots = append(roots, filepath.Join(dir, "projects"))
	}
	var out []string
	for _, r := range roots {
		out = append(out, jsonl.Walk(r, func(p string) bool { return strings.HasSuffix(p, ".jsonl") })...)
	}
	return out
}

func userHome() string { h, _ := os.UserHomeDir(); return h }

func (Parser) Parse(path string) (*event.Session, error) {
	s := &event.Session{Agent: event.AgentClaude, Source: path}
	idx := map[string]int{}
	err := jsonl.EachLine(path, func(m map[string]any) {
		if s.ID == "" {
			s.ID = jsonl.Str(m, "sessionId")
		}
		if cwd := jsonl.Str(m, "cwd"); cwd != "" && s.Project == "" {
			s.Project = cwd
		}
		ts := jsonl.Time(m["timestamp"])
		if s.Start.IsZero() && !ts.IsZero() {
			s.Start = ts
		}
		msg := jsonl.Obj(m, "message")
		blocks := jsonl.Arr(msg, "content")
		for _, b := range blocks {
			blk, _ := b.(map[string]any)
			switch jsonl.Str(blk, "type") {
			case "tool_use", "server_tool_use":
				e := event.Event{
					Agent: event.AgentClaude, SessionID: s.ID, Source: path, Time: ts,
					CallID: jsonl.Str(blk, "id"), Project: jsonl.Str(m, "cwd"),
				}
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
	if s.ID == "" {
		s.ID = strings.TrimSuffix(filepath.Base(path), ".jsonl")
	}
	if s.Project == "" {
		s.Project = decodeProjectDir(filepath.Base(filepath.Dir(path)))
	}
	for i := range s.Events {
		if s.Events[i].Project == "" {
			s.Events[i].Project = s.Project
		}
		s.Events[i].SessionID = s.ID
	}
	return s, err
}

// decodeProjectDir turns "-Users-kay-code-api" back into "/Users/kay/code/api".
// The encoding is lossy (dashes and dots both become "-"), so this is a guess.
func decodeProjectDir(name string) string {
	if strings.HasPrefix(name, "-") {
		return strings.ReplaceAll(name, "-", "/")
	}
	return name
}
