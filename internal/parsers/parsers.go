// Package parsers wires up every agent log parser.
package parsers

import (
	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers/claude"
	"github.com/kaygaaf/tattlr/internal/parsers/codex"
	"github.com/kaygaaf/tattlr/internal/parsers/cursor"
	"github.com/kaygaaf/tattlr/internal/parsers/gemini"
	"github.com/kaygaaf/tattlr/internal/parsers/openclaw"
)

// Parser finds and reads one agent's session logs.
type Parser interface {
	// Agent is the agent name, like "claude-code".
	Agent() string
	// Discover returns candidate log files under the given home directory.
	Discover(home string) []string
	// Parse reads one log file.
	Parse(path string) (*event.Session, error)
}

// All returns every parser.
func All() []Parser {
	return []Parser{claude.Parser{}, codex.Parser{}, gemini.Parser{}, openclaw.Parser{}, cursor.Parser{}}
}
