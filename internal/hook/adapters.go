package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers/jsonl"
	"github.com/kaygaaf/tattlr/internal/parsers/toolmap"
	"github.com/kaygaaf/tattlr/internal/policy"
	"github.com/kaygaaf/tattlr/internal/redact"
)

// adapter turns one agent's payload into a call and writes the answer.
type adapter struct {
	parse func([]byte) (call, error)
	// write prints the answer and returns the exit code.
	write func(io.Writer, call, policy.Decision, string) int
}

var adapters = map[string]adapter{
	"claude":   {parseClaude, writeClaude},
	"codex":    {parseCodex, writeCodex},
	"cursor":   {parseCursor, writeCursor},
	"gemini":   {parseGemini, writeGemini},
	"openclaw": {parseOpenClaw, writeOpenClaw},
}

func decode(raw []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("bad JSON: %w", err)
	}
	if m == nil {
		return nil, errors.New("empty request")
	}
	return m, nil
}

// one builds a single event from a tool name and its arguments.
func one(agent, session, cwd, tool string, args map[string]any) event.Event {
	e := event.Event{Agent: agent, SessionID: session, Project: cwd}
	toolmap.Fill(&e, tool, args)
	e.Path = absAll(e.Path, cwd)
	return e
}

func absAll(p, cwd string) string {
	if p == "" {
		return ""
	}
	parts := strings.Split(p, "\n")
	for i := range parts {
		parts[i] = abs(parts[i], cwd)
	}
	return strings.Join(parts, "\n")
}

// ---------------- Claude Code ----------------
//
// PreToolUse input: session_id, transcript_path, cwd, permission_mode,
// hook_event_name, tool_name, tool_input, tool_use_id.
// Answer: hookSpecificOutput.permissionDecision deny|ask with a reason, exit
// 0. Allow prints nothing, so Claude's own permission rules still apply
// (printing "allow" would skip them).

func parseClaude(raw []byte) (call, error) {
	m, err := decode(raw)
	if err != nil {
		return call{}, err
	}
	c := call{agent: event.AgentClaude, hookEvent: jsonl.Str(m, "hook_event_name"), session: jsonl.Str(m, "session_id"),
		cwd: jsonl.Str(m, "cwd"), tool: jsonl.Str(m, "tool_name")}
	if c.hookEvent != "" && c.hookEvent != "PreToolUse" {
		c.skip = true
		return c, nil
	}
	if c.tool == "" {
		return c, errors.New("no tool_name")
	}
	args := jsonl.Obj(m, "tool_input")
	c.events = []event.Event{one(c.agent, c.session, c.cwd, c.tool, args)}
	// Write content can carry config text (disableAllHooks and friends).
	if s := jsonl.FirstStr(args, "content", "new_string"); s != "" && c.events[0].Kind == event.Write {
		c.events[0].Args = jsonl.Truncate(s, 4000)
	}
	return c, nil
}

func writeClaude(w io.Writer, _ call, d policy.Decision, reason string) int {
	if d.Action == policy.Allow {
		return 0
	}
	out := map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       d.Action.String(),
		"permissionDecisionReason": reason,
	}}
	if d.Action == policy.Deny {
		out["systemMessage"] = "tattlr blocked a tool call: " + firstSentence(d.Reason)
	}
	writeJSON(w, out)
	return 0
}

// ---------------- Codex ----------------
//
// PreToolUse input: session_id, turn_id, transcript_path, cwd,
// hook_event_name, model, permission_mode, tool_name, tool_use_id,
// tool_input. Bash and apply_patch put the command or patch in
// tool_input.command; MCP tools are mcp__server__tool with their own args.
// Answer: hookSpecificOutput.permissionDecision "deny" with a reason. Codex
// does not support "ask" yet (it would fail the hook and let the call
// run), so ask becomes deny with a note.

func parseCodex(raw []byte) (call, error) {
	m, err := decode(raw)
	if err != nil {
		return call{}, err
	}
	c := call{agent: event.AgentCodex, hookEvent: jsonl.Str(m, "hook_event_name"), session: jsonl.Str(m, "session_id"),
		cwd: jsonl.Str(m, "cwd"), tool: jsonl.Str(m, "tool_name")}
	if c.hookEvent != "" && c.hookEvent != "PreToolUse" {
		c.skip = true
		return c, nil
	}
	if c.tool == "" {
		return c, errors.New("no tool_name")
	}
	args := jsonl.Obj(m, "tool_input")
	if strings.EqualFold(c.tool, "apply_patch") {
		patch := jsonl.FirstStr(args, "command", "patch", "input")
		for _, f := range toolmap.PatchFiles(patch) {
			e := one(c.agent, c.session, c.cwd, "apply_patch", map[string]any{"path": f})
			e.Args = jsonl.Truncate(patch, 4000)
			c.events = append(c.events, e)
		}
		if len(c.events) == 0 {
			e := one(c.agent, c.session, c.cwd, "apply_patch", nil)
			e.Args = jsonl.Truncate(patch, 4000)
			c.events = append(c.events, e)
		}
		return c, nil
	}
	if args == nil {
		// Some tools send the command as a bare string.
		if s := jsonl.Str(m, "tool_input"); s != "" {
			args = map[string]any{"command": s}
		}
	}
	c.events = []event.Event{one(c.agent, c.session, c.cwd, c.tool, args)}
	return c, nil
}

func writeCodex(w io.Writer, _ call, d policy.Decision, reason string) int {
	if d.Action == policy.Allow {
		return 0
	}
	if d.Action == policy.Ask {
		reason = strings.TrimSuffix(reason, " tattlr wants a human to OK this.") +
			" tattlr wants a human to OK this, and Codex hooks cannot ask, so it is blocked for now." +
			" Ask the user to run it themselves or allow it in ~/.config/tattlr/policy.yaml."
	}
	writeJSON(w, map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":            "PreToolUse",
		"permissionDecision":       "deny",
		"permissionDecisionReason": reason,
	}})
	return 0
}

// ---------------- Cursor ----------------
//
// beforeShellExecution: {command, cwd, sandbox}
// beforeMCPExecution: {tool_name, tool_input (a JSON string), mcp_server_name, url | command}
// beforeReadFile: {file_path, content}
// preToolUse: {tool_name (Shell, Read, Write, Delete, MCP:x), tool_input, cwd}
// All carry conversation_id, workspace_roots and hook_event_name.
// Answer: {"permission": "allow|deny|ask", "user_message", "agent_message"}
// on every call; anything that is not valid JSON blocks the action. ask is
// only enforced on the shell and MCP hooks, so elsewhere it becomes deny.

func parseCursor(raw []byte) (call, error) {
	m, err := decode(raw)
	if err != nil {
		return call{}, err
	}
	c := call{agent: event.AgentCursor, hookEvent: jsonl.Str(m, "hook_event_name"),
		session: jsonl.FirstStr(m, "conversation_id", "session_id"), cwd: jsonl.Str(m, "cwd")}
	if c.cwd == "" {
		if roots := jsonl.Arr(m, "workspace_roots"); len(roots) > 0 {
			c.cwd, _ = roots[0].(string)
		}
	}
	switch c.hookEvent {
	case "beforeShellExecution":
		c.tool = "Shell"
		cmd := jsonl.Str(m, "command")
		c.events = []event.Event{one(c.agent, c.session, c.cwd, "shell", map[string]any{"command": cmd})}
		c.events[0].Tool = "Shell"
	case "beforeMCPExecution":
		c.tool = jsonl.Str(m, "tool_name")
		srv := jsonl.Str(m, "mcp_server_name")
		var args map[string]any
		if s := jsonl.Str(m, "tool_input"); s != "" {
			if json.Unmarshal([]byte(s), &args) != nil {
				args = map[string]any{"input": s}
			}
		} else {
			args = jsonl.Obj(m, "tool_input")
		}
		e := event.Event{Agent: c.agent, SessionID: c.session, Project: c.cwd}
		toolmap.Fill(&e, "mcp__"+srv+"__"+c.tool, args)
		e.Kind = event.MCP
		if u := jsonl.Str(m, "url"); u != "" && e.URL == "" {
			e.URL = u
		}
		c.events = []event.Event{e}
	case "beforeReadFile":
		c.tool = "Read"
		e := one(c.agent, c.session, c.cwd, "read", map[string]any{"file_path": jsonl.Str(m, "file_path")})
		// The content is only used to spot canary markers; it is never logged.
		e.Output = jsonl.Truncate(jsonl.Str(m, "content"), 1<<20)
		c.events = []event.Event{e}
	case "preToolUse":
		c.tool = jsonl.Str(m, "tool_name")
		args := jsonl.Obj(m, "tool_input")
		name := c.tool
		if strings.HasPrefix(name, "MCP:") {
			name = "mcp__cursor__" + strings.TrimPrefix(name, "MCP:")
		}
		e := one(c.agent, c.session, c.cwd, name, args)
		e.Tool = c.tool
		if s := jsonl.FirstStr(args, "contents", "content", "new_string", "code_edit"); s != "" && e.Kind == event.Write {
			e.Args = jsonl.Truncate(s, 4000)
		}
		c.events = []event.Event{e}
	default:
		c.skip = true
	}
	return c, nil
}

func writeCursor(w io.Writer, c call, d policy.Decision, reason string) int {
	a := d.Action
	native := c.hookEvent == "beforeShellExecution" || c.hookEvent == "beforeMCPExecution"
	if a == policy.Ask && !native {
		a = policy.Deny
		reason = strings.TrimSuffix(reason, " tattlr wants a human to OK this.") +
			" tattlr wants a human to OK this, and this Cursor hook cannot ask, so it is blocked." +
			" Ask the user to do it or allow it in ~/.config/tattlr/policy.yaml."
	}
	out := map[string]any{"permission": a.String()}
	if a != policy.Allow {
		out["user_message"] = "tattlr: " + firstSentence(d.Reason)
		out["agent_message"] = reason
	}
	writeJSON(w, out)
	return 0
}

// ---------------- Gemini CLI ----------------
//
// BeforeTool input (hooks/types.ts, docs/hooks/reference): session_id,
// transcript_path, cwd, hook_event_name, timestamp, tool_name, tool_input,
// mcp_context {server_name, tool_name, ...} for MCP tools,
// original_request_name. Built-in tools are run_shell_command, read_file,
// write_file, replace, read_many_files, glob, grep_search, web_fetch and so
// on; MCP tools are mcp_<server>_<tool>.
// Answer on stdout, exit 0: {"decision": "deny", "reason"} blocks the call
// and sends the reason to the model. {"decision": "ask"} makes the
// scheduler show its confirmation prompt (scheduler.ts forces ASK_USER).
// Allow prints {} so Gemini doesn't fall back to parsing stderr.

func parseGemini(raw []byte) (call, error) {
	m, err := decode(raw)
	if err != nil {
		return call{}, err
	}
	c := call{agent: event.AgentGemini, hookEvent: jsonl.Str(m, "hook_event_name"), session: jsonl.Str(m, "session_id"),
		cwd: jsonl.Str(m, "cwd"), tool: jsonl.Str(m, "tool_name")}
	if c.hookEvent != "" && c.hookEvent != "BeforeTool" {
		c.skip = true
		return c, nil
	}
	if c.tool == "" {
		return c, errors.New("no tool_name")
	}
	args := jsonl.Obj(m, "tool_input")
	name := c.tool
	mcp := jsonl.Obj(m, "mcp_context")
	if mcp != nil {
		name = "mcp__" + jsonl.Str(mcp, "server_name") + "__" + jsonl.FirstStr(mcp, "tool_name")
	}
	e := one(c.agent, c.session, c.cwd, name, args)
	e.Tool = c.tool
	if mcp != nil {
		e.Kind = event.MCP
		if u := jsonl.Str(mcp, "url"); u != "" && e.URL == "" {
			e.URL = u
		}
	}
	if s := jsonl.FirstStr(args, "content", "new_string"); s != "" && e.Kind == event.Write {
		e.Args = jsonl.Truncate(s, 4000)
	}
	c.events = []event.Event{e}
	return c, nil
}

func writeGemini(w io.Writer, _ call, d policy.Decision, reason string) int {
	switch d.Action {
	case policy.Allow:
		writeJSON(w, map[string]any{})
	case policy.Ask:
		writeJSON(w, map[string]any{"decision": "ask", "reason": reason,
			"systemMessage": "tattlr wants you to OK this: " + firstSentence(d.Reason)})
	default:
		writeJSON(w, map[string]any{"decision": "deny", "reason": reason,
			"systemMessage": "tattlr blocked a tool call: " + firstSentence(d.Reason)})
	}
	return 0
}

// ---------------- OpenClaw ----------------
//
// The plugin in integrations/openclaw sends
// {tool_name, params, session_id, agent_id, cwd} from its before_tool_call
// handler and maps our {"action","reason","title","severity"} answer onto
// {block, blockReason} or {requireApproval}.

func parseOpenClaw(raw []byte) (call, error) {
	m, err := decode(raw)
	if err != nil {
		return call{}, err
	}
	c := call{agent: event.AgentOpenClaw, hookEvent: "before_tool_call", session: jsonl.FirstStr(m, "session_id", "sessionId"),
		cwd: jsonl.Str(m, "cwd"), tool: jsonl.FirstStr(m, "tool_name", "toolName")}
	if c.tool == "" {
		return c, errors.New("no tool_name")
	}
	args := jsonl.Obj(m, "params")
	if strings.EqualFold(c.tool, "apply_patch") {
		// The host's derived_paths come first; parse the patch if they are missing.
		patch := jsonl.FirstStr(args, "input", "patch", "command")
		files := toolmap.PatchFiles(patch)
		if ds, ok := m["derived_paths"].([]any); ok && len(ds) > 0 {
			files = files[:0]
			for _, d := range ds {
				if s, ok := d.(string); ok && s != "" {
					files = append(files, s)
				}
			}
		}
		for _, f := range files {
			e := one(c.agent, c.session, c.cwd, "apply_patch", map[string]any{"path": f})
			e.Args = jsonl.Truncate(patch, 4000)
			c.events = append(c.events, e)
		}
		if len(c.events) == 0 {
			e := one(c.agent, c.session, c.cwd, "apply_patch", nil)
			e.Args = jsonl.Truncate(patch, 4000)
			c.events = append(c.events, e)
		}
		return c, nil
	}
	c.events = []event.Event{one(c.agent, c.session, c.cwd, c.tool, args)}
	if s := jsonl.FirstStr(args, "content", "newText", "new_string"); s != "" && c.events[0].Kind == event.Write {
		c.events[0].Args = jsonl.Truncate(s, 4000)
	}
	return c, nil
}

func writeOpenClaw(w io.Writer, _ call, d policy.Decision, reason string) int {
	out := map[string]any{"action": d.Action.String()}
	if d.Action != policy.Allow {
		out["reason"] = reason
		out["title"] = trimTo("tattlr: "+firstSentence(d.Reason), 80)
		out["severity"] = map[bool]string{true: "critical", false: "warning"}[d.Action == policy.Deny]
	}
	writeJSON(w, out)
	return 0
}

// ---------------- helpers ----------------

func writeJSON(w io.Writer, v any) {
	b, _ := json.Marshal(v)
	_, _ = w.Write(append(b, '\n'))
}

func firstSentence(s string) string {
	if i := strings.Index(s, "; "); i > 0 {
		return redact.Line(s[:i], 200)
	}
	return redact.Line(s, 200)
}

func trimTo(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
