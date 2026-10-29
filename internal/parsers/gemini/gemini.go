// Package gemini reads Gemini CLI chat recordings from
// ~/.gemini/tmp/<project>/chats/.
//
// Current versions write session-<date>-<id>.jsonl: a first metadata line
// {sessionId, projectHash, startTime, ...}, then one line per message
// {id, timestamp, type: "user"|"gemini", content, toolCalls: [...]}, plus
// control lines like {"$set": {...}} and {"$rewindTo": id}. A message can be
// written more than once as it updates, so the last copy of each id wins.
// Older versions wrote a single session-*.json object with a messages array.
// Tool calls look like {id, name, args, result, status, timestamp}.
package gemini

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers/jsonl"
	"github.com/kaygaaf/tattlr/internal/parsers/toolmap"
)

// Parser reads Gemini CLI logs.
type Parser struct{}

func (Parser) Agent() string { return event.AgentGemini }

func (Parser) Discover(home string) []string {
	return jsonl.Walk(filepath.Join(home, ".gemini", "tmp"), func(p string) bool {
		b := filepath.Base(p)
		return strings.Contains(filepath.ToSlash(p), "/chats/") &&
			(strings.HasSuffix(b, ".jsonl") || strings.HasSuffix(b, ".json"))
	})
}

func (Parser) Parse(path string) (*event.Session, error) {
	s := &event.Session{Agent: event.AgentGemini, Source: path}
	var order []string
	msgs := map[string]map[string]any{}
	addMsg := func(m map[string]any) {
		id := jsonl.Str(m, "id")
		if id == "" {
			id = jsonl.Str(m, "timestamp") + jsonl.Compact(m["content"])
		}
		if _, seen := msgs[id]; !seen {
			order = append(order, id)
		}
		msgs[id] = m
	}
	meta := func(m map[string]any) {
		if v := jsonl.Str(m, "sessionId"); v != "" && s.ID == "" {
			s.ID = v
		}
		if t := jsonl.Time(m["startTime"]); !t.IsZero() && s.Start.IsZero() {
			s.Start = t
		}
		if dirs := jsonl.Arr(m, "directories"); len(dirs) > 0 && s.Project == "" {
			s.Project, _ = dirs[0].(string)
		}
	}

	var err error
	if strings.HasSuffix(path, ".json") {
		var raw []byte
		raw, err = os.ReadFile(path)
		var obj map[string]any
		if err == nil && json.Unmarshal(raw, &obj) == nil {
			meta(obj)
			for _, m := range jsonl.Arr(obj, "messages") {
				if mm, ok := m.(map[string]any); ok {
					addMsg(mm)
				}
			}
		}
	} else {
		err = jsonl.EachLine(path, func(m map[string]any) {
			switch {
			case m["$set"] != nil:
				meta(jsonl.Obj(m, "$set"))
			case m["$rewindTo"] != nil:
				target := jsonl.Str(m, "$rewindTo")
				for i, id := range order {
					if id == target {
						for _, gone := range order[i:] {
							delete(msgs, gone)
						}
						order = order[:i]
						break
					}
				}
			case m["$patch"] != nil:
				// Bulk edits to stored messages; rare, ignored for now.
			case jsonl.Str(m, "type") != "" && (m["content"] != nil || m["toolCalls"] != nil):
				addMsg(m)
			default:
				meta(m)
			}
		})
	}
	if s.ID == "" {
		s.ID = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	if s.Project == "" {
		// ~/.gemini/tmp/<project-or-hash>/chats/<file>. Newer versions name
		// the folder after the project and keep its full path in .project_root.
		dir := filepath.Dir(filepath.Dir(path))
		if filepath.Base(filepath.Dir(path)) != "chats" {
			dir = filepath.Dir(dir)
		}
		s.Project = filepath.Base(dir)
		if b, err := os.ReadFile(filepath.Join(dir, ".project_root")); err == nil {
			if root := strings.TrimSpace(string(b)); filepath.IsAbs(root) {
				s.Project = root
			}
		}
	}
	for _, id := range order {
		m := msgs[id]
		mts := jsonl.Time(m["timestamp"])
		for _, c := range jsonl.Arr(m, "toolCalls") {
			call, _ := c.(map[string]any)
			if call == nil {
				continue
			}
			ts := jsonl.Time(call["timestamp"])
			if ts.IsZero() {
				ts = mts
			}
			e := event.Event{Agent: event.AgentGemini, SessionID: s.ID, Project: s.Project, Source: path,
				Time: ts, CallID: jsonl.Str(call, "id")}
			toolmap.Fill(&e, jsonl.Str(call, "name"), jsonl.Obj(call, "args"))
			e.Output = jsonl.ContentText(call["result"])
			s.Events = append(s.Events, e)
		}
	}
	return s, err
}
