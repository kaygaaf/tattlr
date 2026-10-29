// Package event holds the normalized tool call type every parser produces.
package event

import "time"

// Kind is the normalized category of a tool call.
type Kind string

const (
	Shell  Kind = "shell"
	Read   Kind = "read"
	Write  Kind = "write"
	Search Kind = "search"
	Fetch  Kind = "fetch"
	MCP    Kind = "mcp"
	Other  Kind = "other"
)

// Event is one tool call made by an agent, normalized across log formats.
type Event struct {
	Agent     string    `json:"agent"`
	SessionID string    `json:"session_id"`
	Project   string    `json:"project"`
	Source    string    `json:"source"`
	Time      time.Time `json:"time"`
	CallID    string    `json:"-"`
	Tool      string    `json:"tool"`
	Kind      Kind      `json:"kind"`
	Command   string    `json:"command,omitempty"`
	Path      string    `json:"path,omitempty"`
	URL       string    `json:"url,omitempty"`
	Args      string    `json:"args,omitempty"`
	Output    string    `json:"-"`
	// Escalated is set when the call asked to run outside the agent sandbox.
	Escalated bool `json:"escalated,omitempty"`
}

// Session groups the events parsed from one log file.
type Session struct {
	Agent   string
	ID      string
	Project string
	Source  string
	Start   time.Time
	Events  []Event
}

// Agent names used across the codebase.
const (
	AgentClaude   = "claude-code"
	AgentCodex    = "codex"
	AgentGemini   = "gemini-cli"
	AgentOpenClaw = "openclaw"
	AgentCursor   = "cursor"
)

// AllAgents lists every agent tattlr knows how to read.
var AllAgents = []string{AgentClaude, AgentCodex, AgentGemini, AgentOpenClaw, AgentCursor}
