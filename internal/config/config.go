// Package config knows where tattlr keeps its files.
package config

import (
	"os"
	"path/filepath"
)

// Dir is ~/.config/tattlr: policy, traps, install state and backups.
func Dir(home string) string { return filepath.Join(home, ".config", "tattlr") }

// PolicyPath is the live protection policy.
func PolicyPath(home string) string { return filepath.Join(Dir(home), "policy.yaml") }

// StatePath records what `tattlr protect install` changed.
func StatePath(home string) string { return filepath.Join(Dir(home), "protect.json") }

// BackupDir holds copies of agent configs taken before each edit.
func BackupDir(home string) string { return filepath.Join(Dir(home), "backups") }

// StateDir is where the audit log lives: $XDG_STATE_HOME/tattlr for the
// real home, ~/.local/state/tattlr otherwise (tests use a fake home and must
// not pick up the real environment).
func StateDir(home string) string {
	if x := os.Getenv("XDG_STATE_HOME"); x != "" && isRealHome(home) {
		return filepath.Join(x, "tattlr")
	}
	return filepath.Join(home, ".local", "state", "tattlr")
}

// AuditPath is the JSONL log of every hook decision.
func AuditPath(home string) string { return filepath.Join(StateDir(home), "audit.jsonl") }

func isRealHome(home string) bool {
	h, err := os.UserHomeDir()
	return err == nil && filepath.Clean(h) == filepath.Clean(home)
}

// HookConfigs are the agent config files protect install may edit.
func HookConfigs(home string) []string {
	return []string{
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".claude", "settings.local.json"),
		filepath.Join(home, ".codex", "config.toml"),
		filepath.Join(home, ".codex", "hooks.json"),
		filepath.Join(home, ".cursor", "hooks.json"),
		filepath.Join(home, ".gemini", "settings.json"),
	}
}

// Protected lists what agents may not edit while protection is on. A
// trailing slash means a whole folder.
func Protected(home, bin string) []string {
	out := []string{Dir(home) + "/", StateDir(home) + "/"}
	out = append(out, HookConfigs(home)...)
	if bin != "" {
		out = append(out, bin)
	}
	return out
}
