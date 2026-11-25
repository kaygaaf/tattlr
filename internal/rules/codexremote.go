package rules

import (
	"regexp"
	"strings"
)

// pairingRe matches the text Codex 0.171.0 prints when it shows a device
// pairing code: "Pairing code: <code>", the JSON field manualPairingCode,
// and the pair link. A mention of remote control in prose does not match.
var pairingRe = regexp.MustCompile(`(?i)pairing code\s*:|manualPairingCode|manual_pairing_code|chatgpt\.com/codex/pair`)

// checkCodexRemote flags Codex commands that run on another machine, or that
// turn remote control on and print a pairing code. A local `codex app-server`
// stdio call is the hook trust check, so it stays quiet. Stop and
// disable-remote-control turn the feature off, so those stay quiet too.
//
// Flag names are from Codex 0.171.0 (openai/codex rust-v0.171.0):
// `codex exec --remote ADDR`, `codex --remote ADDR`,
// `codex remote-control` / `start` / `pair`, and
// `codex app-server --remote-control` or `daemon enable-remote-control`.
func checkCodexRemote(cmd string, segs []segment, add func(string, string, Severity)) {
	for _, s := range segs {
		if !isCodexBin(s) {
			continue
		}
		if detail, ok := codexRemoteDetail(s.Args); ok {
			add(RuleCodexRemote, detail, 0)
			return
		}
	}
	if pairingRe.MatchString(cmd) {
		add(RuleCodexRemote, "pairing code", 0)
	}
}

func isCodexBin(s segment) bool {
	if len(s.Args) == 0 {
		return false
	}
	p := strings.ReplaceAll(s.Args[0], string(rune(0x5c)), "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	p = strings.TrimSuffix(p, ".exe")
	return p == "codex"
}

func codexRemoteDetail(args []string) (string, bool) {
	rest := args[1:]
	if addr, ok := longFlagValue(rest, "--remote"); ok {
		if addr == "" {
			addr = "remote app server"
		}
		return "codex --remote " + addr, true
	}
	if env, ok := longFlagValue(rest, "--remote-auth-token-env"); ok {
		if env == "" {
			return "codex --remote-auth-token-env", true
		}
		return "codex --remote-auth-token-env " + env, true
	}
	if hasExactFlag(rest, "--remote-control") {
		return "codex app-server --remote-control", true
	}
	if codexHelp(rest) {
		return "", false
	}
	pos := positional(rest)
	for i, p := range pos {
		switch p {
		case "remote-control":
			sub := ""
			if i+1 < len(pos) {
				sub = pos[i+1]
			}
			switch sub {
			case "", "start":
				if sub == "" {
					return "codex remote-control", true
				}
				return "codex remote-control start", true
			case "pair":
				return "codex remote-control pair", true
			}
		case "enable-remote-control":
			return "codex app-server daemon enable-remote-control", true
		}
	}
	return "", false
}

func longFlagValue(args []string, name string) (string, bool) {
	for i, a := range args {
		if a == "--" {
			return "", false
		}
		if a == name {
			if i+1 < len(args) && args[i+1] != "--" && !strings.HasPrefix(args[i+1], "-") {
				return args[i+1], true
			}
			return "", true
		}
		if strings.HasPrefix(a, name+"=") {
			return strings.TrimPrefix(a, name+"="), true
		}
	}
	return "", false
}

func hasExactFlag(args []string, name string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == name {
			return true
		}
	}
	return false
}

func codexHelp(args []string) bool {
	pos := positional(args)
	if len(pos) > 0 && pos[0] == "help" {
		return true
	}
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--help" || a == "-h" {
			return true
		}
	}
	return false
}
