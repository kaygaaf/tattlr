package protect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kaygaaf/tattlr/internal/audit"
	"github.com/kaygaaf/tattlr/internal/config"
)

// AgentStatus describes one agent's hook wiring.
type AgentStatus struct {
	Agent     string   `json:"agent"`
	Config    string   `json:"config"`
	Exists    bool     `json:"config_exists"`
	Installed bool     `json:"installed"`
	Commands  []string `json:"commands,omitempty"`
	BinOK     bool     `json:"binary_ok"`
	Calls24h  int      `json:"calls_24h"`
	Blocked24 int      `json:"blocked_24h"`
	Problems  []string `json:"problems,omitempty"`
	// Inactive is why the hook is in the config but the agent will not run it.
	Inactive string `json:"inactive,omitempty"`
	// Trust is Codex's own verdict on the tattlr hook, when it could be read.
	Trust    string `json:"codex_trust,omitempty"`
	TrustVia string `json:"codex_trust_source,omitempty"`
}

var cmdRe = regexp.MustCompile(`"command"\s*:\s*"((?:[^"\\]|\\.)*)"|command\s*=\s*"((?:[^"\\]|\\.)*)"`)

// Status reports the wiring for each agent that has a config or an install.
func Status(home, bin string, now time.Time) []AgentStatus {
	st, _ := LoadState(home)
	recent, _ := audit.Tail(config.AuditPath(home), 4<<20)
	var out []AgentStatus
	for _, a := range hookAgents {
		s := AgentStatus{Agent: a, Config: configPath(home, a)}
		if st != nil {
			if as, ok := st.Agents[a]; ok && as.Path != "" {
				s.Config = as.Path
			}
		}
		b, err := os.ReadFile(s.Config)
		s.Exists = err == nil
		for _, m := range cmdRe.FindAllStringSubmatch(string(b), -1) {
			c := m[1] + m[2]
			c = strings.ReplaceAll(c, `\\`, `\`)
			c = strings.ReplaceAll(c, `\"`, `"`)
			if isOurs(c, a) {
				s.Commands = append(s.Commands, c)
			}
		}
		s.Installed = len(s.Commands) > 0
		s.BinOK = s.Installed
		for _, c := range s.Commands {
			if c != Command(bin, a) {
				p := hookBin(c)
				if fi, err := os.Stat(p); err != nil || fi.IsDir() {
					s.BinOK = false
					s.Problems = append(s.Problems, "hook points at "+p+", which does not exist; rerun tattlr protect install")
				} else if p != bin {
					s.Problems = append(s.Problems, "hook points at "+p+", not this tattlr ("+bin+")")
				}
			}
		}
		if a == "claude" && s.Exists && regexp.MustCompile(`"disableAllHooks"\s*:\s*true`).Match(b) {
			s.Problems = append(s.Problems, "disableAllHooks is true, so no hooks run")
		}
		if a == "codex" {
			toml, _ := os.ReadFile(configPathTOML(home))
			if tomlHooksOff.Match(toml) {
				s.Problems = append(s.Problems, "hooks are switched off in ~/.codex/config.toml")
			}
			if s.Installed {
				s.Trust, s.TrustVia = codexTrust(home, s.Config)
				if n := CodexTrustNote(s.Trust); n != "" {
					s.Problems = append(s.Problems, n)
				}
			}
		}
		if a == "gemini" && s.Installed {
			if why := geminiInactive(b, s.Commands); why != "" {
				s.Inactive = why
				s.Problems = append(s.Problems, why)
			}
		}
		for _, e := range recent {
			if e.Agent == agentEventName(a) && now.Sub(e.Time) < 24*time.Hour {
				s.Calls24h++
				if e.Decision == "deny" || e.Decision == "ask" {
					s.Blocked24++
				}
			}
		}
		if !s.Exists && !s.Installed {
			continue
		}
		out = append(out, s)
	}
	return out
}

func configPathTOML(home string) string { return filepath.Join(home, ".codex", "config.toml") }

// hookBin pulls the binary out of a hook command line.
func hookBin(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, "'") {
		if i := strings.Index(cmd[1:], "'"); i >= 0 {
			return cmd[1 : i+1]
		}
	}
	if i := strings.IndexByte(cmd, ' '); i > 0 {
		return cmd[:i]
	}
	return cmd
}

func agentEventName(a string) string {
	switch a {
	case "claude":
		return "claude-code"
	}
	return a
}

// geminiInactive reports why Gemini CLI 0.70 will not run a hook that is
// present in settings. hooksConfig.enabled false skips every hook. A name in
// hooksConfig.disabled skips that hook; Gemini matches the hook's name, or
// the command when the name is empty.
func geminiInactive(raw []byte, commands []string) string {
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil {
		return ""
	}
	hcRaw, ok := root["hooksConfig"]
	if !ok {
		return ""
	}
	var hc struct {
		Enabled  *bool    `json:"enabled"`
		Disabled []string `json:"disabled"`
	}
	if json.Unmarshal(hcRaw, &hc) != nil {
		return ""
	}
	if hc.Enabled != nil && !*hc.Enabled {
		return "Gemini skips this hook because hooksConfig.enabled is false"
	}
	for _, name := range hc.Disabled {
		if name == "tattlr" || containsStr(commands, name) {
			return "Gemini skips this hook because it is listed in hooksConfig.disabled"
		}
	}
	return ""
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
