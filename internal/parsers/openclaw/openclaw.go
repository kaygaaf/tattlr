// Package openclaw reads OpenClaw session transcripts from
// ~/.openclaw/agents/<agent>/sessions/*.jsonl, including the archived
// *.jsonl.reset.<ts> and *.jsonl.deleted.<ts> copies.
//
// The first line is a header {type:"session", version, id, timestamp, cwd}.
// Then {type:"message", id, parentId, timestamp, message:{role, content}}.
// Assistant content holds {type:"toolCall", id, name, arguments} blocks, and
// results come back as role "toolResult" messages with toolCallId.
//
// Newer OpenClaw builds (2026.10 and later) keep live transcripts in a
// per-agent SQLite database, agents/<agent>/agent/openclaw-agent.sqlite, one
// row per line in transcript_events. The rows hold the same JSON objects, so
// each session there shows up as "<db>#<session id>" and goes through the
// same line handler. See sqlite.go.
package openclaw

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers/jsonl"
	"github.com/kaygaaf/tattlr/internal/parsers/toolmap"
)

// Parser reads OpenClaw transcripts.
type Parser struct{}

func (Parser) Agent() string { return event.AgentOpenClaw }

func (Parser) Discover(home string) []string {
	base := filepath.Join(home, ".openclaw")
	if dir := os.Getenv("OPENCLAW_STATE_DIR"); dir != "" {
		if h, _ := os.UserHomeDir(); h == home {
			base = dir
		}
	}
	root := filepath.Join(base, "agents")
	var dbs []string
	files := jsonl.Walk(root, func(p string) bool {
		if filepath.Base(p) == dbName && filepath.Base(filepath.Dir(p)) == "agent" {
			dbs = append(dbs, p)
			return false
		}
		if filepath.Base(filepath.Dir(p)) != "sessions" {
			return false
		}
		b := filepath.Base(p)
		if strings.HasSuffix(b, ".zst") || strings.Contains(b, ".checkpoint.") || strings.Contains(b, ".trajectory.") {
			return false
		}
		return strings.HasSuffix(b, ".jsonl") || strings.Contains(b, ".jsonl.reset.") || strings.Contains(b, ".jsonl.deleted.")
	})
	for _, db := range dbs {
		files = append(files, dbSessions(db)...)
	}
	return files
}

func (Parser) Parse(path string) (*event.Session, error) {
	s := &event.Session{Agent: event.AgentOpenClaw, Source: path}
	idx := map[string]int{}
	each := jsonl.EachLine
	db, sid, inDB := splitDBPath(path)
	if inDB {
		each = func(_ string, fn func(map[string]any)) error { return dbEvents(db, sid, fn) }
	}
	err := each(path, func(m map[string]any) {
		ts := jsonl.Time(m["timestamp"])
		switch jsonl.Str(m, "type") {
		case "session":
			s.ID = jsonl.Str(m, "id")
			s.Project = jsonl.Str(m, "cwd")
			s.Start = ts
			return
		case "message":
		default:
			return
		}
		msg := jsonl.Obj(m, "message")
		if ts.IsZero() {
			ts = jsonl.Time(msg["timestamp"])
		}
		switch jsonl.Str(msg, "role") {
		case "assistant":
			for _, b := range jsonl.Arr(msg, "content") {
				blk, _ := b.(map[string]any)
				t := strings.ToLower(jsonl.Str(blk, "type"))
				if t != "toolcall" && t != "tool_use" {
					continue
				}
				args := jsonl.Obj(blk, "arguments")
				if args == nil {
					args = jsonl.Obj(blk, "input")
				}
				e := event.Event{Agent: event.AgentOpenClaw, Source: path, Time: ts, CallID: jsonl.Str(blk, "id")}
				toolmap.Fill(&e, jsonl.Str(blk, "name"), args)
				idx[e.CallID] = len(s.Events)
				s.Events = append(s.Events, e)
			}
		case "toolResult":
			if i, ok := idx[jsonl.Str(msg, "toolCallId")]; ok {
				s.Events[i].Output = jsonl.ContentText(msg["content"])
			}
		}
	})
	if s.ID == "" {
		s.ID = strings.SplitN(filepath.Base(path), ".", 2)[0]
		if inDB {
			s.ID = sid
		}
	}
	if s.Project == "" {
		// agents/<agent>/sessions/<file> or agents/<agent>/agent/<db>:
		// use the agent name.
		dir := path
		if inDB {
			dir = db
		}
		s.Project = "openclaw:" + filepath.Base(filepath.Dir(filepath.Dir(dir)))
	}
	for i := range s.Events {
		s.Events[i].SessionID = s.ID
		s.Events[i].Project = s.Project
	}
	return s, err
}
