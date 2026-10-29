package protect

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Recent Codex releases (checked on 0.165.0) only run a hook from config.toml after the user
// trusts it in the /hooks screen. Until then `codex exec` skips it without a
// word, so a hooked-up config can still mean no protection.

// CodexTrust values.
const (
	TrustUnknown   = ""
	TrustTrusted   = "trusted"
	TrustUntrusted = "untrusted"
	TrustModified  = "modified"
	TrustManaged   = "managed"
)

// codexBin finds the codex binary. Tests swap it out.
var codexBin = func() string {
	p, err := exec.LookPath("codex")
	if err != nil {
		return ""
	}
	return p
}

// CodexTrustNote is what to tell the user for a trust status.
func CodexTrustNote(status string) string {
	switch status {
	case TrustUntrusted:
		return "Codex has not trusted this hook yet, so it does not run (codex exec skips it silently). Start codex, type /hooks and trust the tattlr hook"
	case TrustModified:
		return "the hook changed since you trusted it, so Codex skips it. Start codex, type /hooks and trust it again"
	}
	return ""
}

// codexTrust asks the local codex binary which tattlr hooks it trusts. It
// falls back to looking for a trust record in config.toml.
func codexTrust(home, cfg string) (status, how string) {
	if bin := codexBin(); bin != "" {
		if s, ok := askCodex(bin, home, filepath.Dir(cfg)); ok {
			return s, "codex hooks/list"
		}
	}
	b, err := os.ReadFile(cfg)
	if err != nil {
		return TrustUnknown, ""
	}
	return trustFromTOML(string(b), cfg), "config.toml"
}

// trustFromTOML can only tell "no record" from "some record": checking that
// the record matches needs Codex's own hash.
func trustFromTOML(toml, cfg string) string {
	prefix := `[hooks.state."` + cfg + `:pre_tool_use:`
	for _, blk := range strings.Split(toml, "\n[")[1:] {
		blk = "[" + blk
		if strings.HasPrefix(blk, prefix) && strings.Contains(blk, "trusted_hash") {
			return TrustUnknown
		}
	}
	return TrustUntrusted
}

// askCodex runs `codex app-server` over stdio for one hooks/list call. It needs
// no login and reads nothing but the local config.
func askCodex(bin, home, codexHome string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "app-server")
	cmd.Env = append(os.Environ(), "CODEX_HOME="+codexHome)
	cmd.Dir = home
	in, err := cmd.StdinPipe()
	if err != nil {
		return "", false
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", false
	}
	if err := cmd.Start(); err != nil {
		return "", false
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"tattlr","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"hooks/list","params":{"cwds":[` + jsonString(home) + `]}}`,
	}
	go func() {
		for _, m := range msgs {
			if _, err := in.Write([]byte(m + "\n")); err != nil {
				return
			}
		}
	}()
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		if s, ok := parseHooksList(sc.Bytes()); ok {
			return s, true
		}
	}
	return "", false
}

// parseHooksList picks the worst trust status among tattlr's hooks in a
// hooks/list response line.
func parseHooksList(line []byte) (string, bool) {
	var r struct {
		ID     int `json:"id"`
		Result *struct {
			Data []struct {
				Hooks []struct {
					Command     string `json:"command"`
					Enabled     bool   `json:"enabled"`
					TrustStatus string `json:"trustStatus"`
				} `json:"hooks"`
			} `json:"data"`
		} `json:"result"`
	}
	if json.Unmarshal(line, &r) != nil || r.ID != 2 || r.Result == nil {
		return "", false
	}
	rank := map[string]int{TrustUntrusted: 3, TrustModified: 2, TrustTrusted: 1, TrustManaged: 1}
	best := TrustUnknown
	for _, d := range r.Result.Data {
		for _, h := range d.Hooks {
			if !isOurs(h.Command, "codex") {
				continue
			}
			if rank[h.TrustStatus] > rank[best] {
				best = h.TrustStatus
			}
		}
	}
	return best, true
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
