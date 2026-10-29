// Package claude reads Claude Code session logs.
//
// Where they live:
//   - $CLAUDE_CONFIG_DIR/projects, a comma separated list that replaces the
//     defaults when set (Anthropic documents one dir; ccusage takes a list)
//   - ~/.config/claude/projects (or $XDG_CONFIG_HOME/claude/projects), which
//     ccusage and older installs use
//   - ~/.claude/projects, the documented default
//
// Inside, each project gets a folder named after its cwd with every
// non-alphanumeric character turned into "-" (long names get cut to 200
// characters plus a hash, and CLAUDE_CODE_PROJECT_DIR_NAME can pick any
// name), holding <session-id>.jsonl. Next to it:
//   - <session-id>/subagents/agent-<id>.jsonl, subagent transcripts
//   - <session-id>/subagents/workflows/<run>/agent-<id>.jsonl, workflow agents
//   - agent-<id>.jsonl in the project folder, the older subagent layout
//   - <session-id>.orphaned-<ts>-<x>.jsonl and <session-id>.jsonl.superseded-<ts>,
//     older copies Claude Code set aside instead of deleting
//   - <session-id>/tool-results/<tool_use_id>.txt|.json, big tool outputs
//
// Subagent and workflow lines carry the parent sessionId, so they merge into
// the parent session.
//
// Each line has a "type". Only "user" and "assistant" lines matter here;
// "summary", "system", "progress", "attachment", "file-history-snapshot",
// "queue-operation", "ai-title" and friends are skipped. Assistant lines are
// written one content block per line while the reply streams, so the same
// message.id shows up on several lines and a tool_use block can repeat; we
// dedupe on the tool_use id. Tool results come back as "tool_result" blocks
// in a later user line keyed by tool_use_id, with a structured copy in the
// line's "toolUseResult" field. An output that was too big starts with
// "<persisted-output>" and names the tool-results file holding the rest.
//
// Resuming with --fork-session, /branch, and resumed or replayed sessions can
// copy earlier lines into a new file under a new sessionId, same tool_use ids.
// Parser.UniqueCallIDs tells scan to count each tool_use id once.
package claude

import (
	"encoding/json"
	"io"
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

// UniqueCallIDs reports that a tool_use id names one call across every
// file, so copies in forked, resumed or set-aside transcripts count once.
func (Parser) UniqueCallIDs() bool { return true }

// Roots lists the Claude config dirs to read for this home, in lookup order.
// Environment overrides only apply when home is the real user home, so
// scans of a test home stay hermetic.
func Roots(home string) []string {
	real := home == userHome()
	if env := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); env != "" && real {
		var out []string
		for _, p := range strings.Split(env, ",") {
			p = expand(strings.TrimSpace(p), home)
			if p == "" {
				continue
			}
			if filepath.Base(p) == "projects" {
				p = filepath.Dir(p)
			}
			out = append(out, p)
		}
		return dedupe(out)
	}
	xdg := filepath.Join(home, ".config")
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" && real {
		xdg = x
	}
	return dedupe([]string{filepath.Join(xdg, "claude"), filepath.Join(home, ".claude")})
}

func expand(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

func dedupe(ps []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ps {
		c := filepath.Clean(p)
		if r, err := filepath.EvalSymlinks(c); err == nil {
			c = r
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, p)
		}
	}
	return out
}

func (Parser) Discover(home string) []string {
	var out []string
	for _, r := range Roots(home) {
		out = append(out, jsonl.Walk(filepath.Join(r, "projects"), isTranscript)...)
	}
	return out
}

// isTranscript keeps session, subagent, workflow and set-aside transcripts,
// and skips spilled tool output and MCP task state.
func isTranscript(p string) bool {
	slash := filepath.ToSlash(p)
	if strings.Contains(slash, "/tool-results/") || strings.Contains(slash, "/mcp-tasks/") {
		return false
	}
	base := filepath.Base(p)
	return strings.HasSuffix(base, ".jsonl") || strings.Contains(base, ".jsonl.superseded-")
}

func userHome() string { h, _ := os.UserHomeDir(); return h }

func (Parser) Parse(path string) (*event.Session, error) {
	s := &event.Session{Agent: event.AgentClaude, Source: path}
	idx := map[string]int{}
	err := jsonl.EachLine(path, func(m map[string]any) {
		typ := jsonl.Str(m, "type")
		if typ != "user" && typ != "assistant" {
			return
		}
		if s.ID == "" {
			s.ID = jsonl.Str(m, "sessionId")
		}
		cwd := jsonl.Str(m, "cwd")
		if cwd != "" && s.Project == "" {
			s.Project = cwd
		}
		ts := jsonl.Time(m["timestamp"])
		if s.Start.IsZero() && !ts.IsZero() {
			s.Start = ts
		}
		msg := jsonl.Obj(m, "message")
		for _, b := range jsonl.Arr(msg, "content") {
			blk, _ := b.(map[string]any)
			switch jsonl.Str(blk, "type") {
			case "tool_use", "server_tool_use":
				if typ != "assistant" {
					continue
				}
				id := jsonl.Str(blk, "id")
				if _, dup := idx[id]; dup && id != "" {
					continue
				}
				e := event.Event{
					Agent: event.AgentClaude, SessionID: s.ID, Source: path, Time: ts,
					CallID: id, Project: cwd,
				}
				toolmap.Fill(&e, jsonl.Str(blk, "name"), jsonl.Obj(blk, "input"))
				if id != "" {
					idx[id] = len(s.Events)
				}
				s.Events = append(s.Events, e)
			case "tool_result":
				i, ok := idx[jsonl.Str(blk, "tool_use_id")]
				if !ok {
					continue
				}
				out := strings.TrimRight(jsonl.ContentText(blk["content"]), "\n")
				if out == "" {
					out = resultText(m["toolUseResult"])
				}
				if full, ok := persisted(path, s.ID, out); ok {
					out = full
				}
				s.Events[i].Output = out
			}
		}
	})
	if s.ID == "" {
		s.ID = strings.TrimSuffix(filepath.Base(path), ".jsonl")
	}
	if s.Project == "" {
		s.Project = decodeProjectDir(projectDirName(path))
	}
	for i := range s.Events {
		if s.Events[i].Project == "" {
			s.Events[i].Project = s.Project
		}
		s.Events[i].SessionID = s.ID
	}
	return s, err
}

// resultText pulls readable text out of a structured toolUseResult: Bash
// gives stdout/stderr, Read gives file.content, others are plain strings.
func resultText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any:
		var parts []string
		for _, k := range []string{"stdout", "stderr", "content"} {
			if s := jsonl.Str(t, k); s != "" {
				parts = append(parts, s)
			}
		}
		if f := jsonl.Obj(t, "file"); f != nil {
			if s := jsonl.Str(f, "content"); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// projectDirName finds the encoded project folder for a log path: the
// folder right under "projects", however deep the subagent or workflow
// transcript sits.
func projectDirName(path string) string {
	dir := filepath.Dir(path)
	for d := dir; ; {
		parent := filepath.Dir(d)
		if filepath.Base(parent) == "projects" {
			return filepath.Base(d)
		}
		if parent == d {
			break
		}
		d = parent
	}
	return filepath.Base(dir)
}

// projectDir is the full path of that folder, or "" when the log is not
// under a projects dir.
func projectDir(path string) string {
	for d := filepath.Dir(path); ; {
		parent := filepath.Dir(d)
		if filepath.Base(parent) == "projects" {
			return d
		}
		if parent == d {
			return ""
		}
		d = parent
	}
}

const (
	persistedTag  = "<persisted-output>"
	persistedFrom = "Full output saved to: "
	persistedMax  = 4 << 20
)

// persisted swaps a "<persisted-output>" preview for the full output Claude
// Code spilled to <project>/<session>/tool-results/. Only the file name is
// taken from the log; the folder is rebuilt from the log's own location, so
// a crafted line can't point us at some other file.
func persisted(logPath, sessionID, out string) (string, bool) {
	if !strings.HasPrefix(strings.TrimSpace(out), persistedTag) {
		return "", false
	}
	i := strings.Index(out, persistedFrom)
	if i < 0 {
		return "", false
	}
	ref := out[i+len(persistedFrom):]
	if j := strings.IndexAny(ref, "\r\n"); j >= 0 {
		ref = ref[:j]
	}
	name := filepath.Base(filepath.FromSlash(strings.ReplaceAll(strings.TrimSpace(ref), "\\", "/")))
	if name == "." || name == "/" || strings.ContainsAny(name, "/\\") || strings.HasPrefix(name, ".") {
		return "", false
	}
	pd := projectDir(logPath)
	if pd == "" || sessionID == "" || strings.ContainsAny(sessionID, "/\\") {
		return "", false
	}
	f, err := os.Open(filepath.Join(pd, sessionID, "tool-results", name))
	if err != nil {
		return "", false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, persistedMax))
	if err != nil || len(b) == 0 {
		return "", false
	}
	if strings.HasSuffix(name, ".json") {
		var v any
		if json.Unmarshal(b, &v) == nil {
			if t := jsonl.ContentText(v); t != "" {
				return strings.TrimRight(t, "\n"), true
			}
		}
	}
	return strings.TrimRight(string(b), "\n"), true
}

// decodeProjectDir turns "-Users-kay-code-api" back into "/Users/kay/code/api".
// Claude Code replaces every non-alphanumeric character with "-", so dots,
// dashes and spaces all come back as slashes. Only used when no line in the
// log carries a cwd.
func decodeProjectDir(name string) string {
	if strings.HasPrefix(name, "-") {
		return strings.ReplaceAll(name, "-", "/")
	}
	return name
}
