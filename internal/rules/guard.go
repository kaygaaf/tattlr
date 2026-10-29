package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/kaygaaf/tattlr/internal/event"
)

// Rules used by live protection. self-protect fires from Check; tainted
// egress needs session history, so the hook adds it.
const (
	RuleSelfProtect   = "self-protect"
	RuleTaintedEgress = "tainted-egress"
)

func init() {
	Catalog[RuleSelfProtect] = Info{RuleSelfProtect, "Tried to switch off tattlr", "tampering", Critical}
	Catalog[RuleTaintedEgress] = Info{RuleTaintedEgress, "Went online after touching a canary", "network", Critical}
}

var (
	killTattlrRe = regexp.MustCompile(`\b(pkill|killall|kill)\b[^;&|\n]*tattlr|\btattlr\s+(protect\s+(uninstall|off)|trap\b[^;&|\n]*--remove)|\bchmod\s+[^;&|\n]*-x[^;&|\n]*tattlr`)
	hooksOffRe   = regexp.MustCompile(`(?m)\bdisableAllHooks\b|(?:^|[^A-Za-z_]|\\n)(codex_)?hooks\s*=\s*false` +
		// Gemini CLI: hooksConfig.enabled false, the old enableHooks
		// switch, or tattlr listed in hooksConfig.disabled.
		`|"?hooksConfig"?\s*:\s*\{[^}]*"?enabled"?\s*:\s*false|hooksConfig\.enabled\s*=\s*false|"?enableHooks"?\s*:\s*false|"?disabled"?\s*:\s*\[[^\]]*tattlr`)
)

// readOnlyProgs never change a file on their own. A command made only of
// these (and no redirects) can look at protected files.
var readOnlyProgs = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "more": true, "grep": true, "egrep": true,
	"fgrep": true, "rg": true, "ls": true, "wc": true, "file": true, "stat": true, "diff": true, "jq": true,
	"bat": true, "strings": true, "md5sum": true, "sha256sum": true, "shasum": true, "readlink": true,
	"realpath": true, "test": true, "[": true, "echo": true, "printf": true, "which": true, "type": true,
	"tattlr": true, "cmp": true, "du": true, "find": true, "git": true, "pwd": true, "cd": true, "true": true,
}

// ReadOnlyCommand reports whether a shell command only reads: every
// program is a known reader, nothing is redirected into a file, and no
// in-place or exec flags are used.
func ReadOnlyCommand(cmd string) bool {
	segs := splitShell(cmd)
	if len(segs) == 0 {
		return false
	}
	for _, s := range segs {
		if len(s.Out) > 0 {
			for _, o := range s.Out {
				if o != "/dev/null" && !strings.HasPrefix(o, "&") {
					return false
				}
			}
		}
		p := prog(s)
		if !readOnlyProgs[p] {
			return false
		}
		switch p {
		case "find":
			for _, a := range s.Args {
				if a == "-delete" || a == "-exec" || a == "-execdir" || a == "-ok" || a == "-fprint" {
					return false
				}
			}
		case "git":
			if len(s.Args) < 2 {
				return false
			}
			pos := positional(s.Args[1:])
			if len(pos) == 0 {
				return false
			}
			switch pos[0] {
			case "status", "log", "diff", "show", "blame", "ls-files", "rev-parse", "branch":
			default:
				return false
			}
		case "tattlr":
			if len(s.Args) > 1 && !tattlrReadOnly(s.Args[1:]) {
				return false
			}
		}
	}
	return true
}

// IsEgress reports whether a call can send data off the machine.
func IsEgress(e event.Event) bool {
	switch e.Kind {
	case event.Fetch:
		return true
	case event.MCP:
		return urlRe.MatchString(e.Args)
	case event.Shell:
		segs := splitShell(e.Command)
		if hasNetworkProgram(segs) {
			return true
		}
		l := strings.ToLower(e.Command)
		for _, w := range []string{"requests.post", "requests.get", "urllib", "http.client", "fetch(", "axios",
			"socket.", "/dev/tcp/", "invoke-webrequest", "iwr ", "irm ", "net.http", "dig ", "nslookup ", "gh api",
			"gh gist", "aws s3 cp", "gsutil cp", "rclone ", "git push", "npm publish"} {
			if strings.Contains(l, w) {
				return true
			}
		}
	}
	return false
}

// protectedHit reports which protected path a token points at, or "".
func (en *Engine) protectedHit(tok string) string {
	if tok == "" {
		return ""
	}
	if en.Cwd != "" && !strings.HasPrefix(tok, "/") && !strings.HasPrefix(tok, "~") && !strings.HasPrefix(tok, "$") {
		tok = path.Join(strings.ReplaceAll(en.Cwd, "\\", "/"), tok)
	}
	t := normPath(path.Clean(normPath(tok, en.Home)), en.Home)
	for _, p := range en.Protected {
		dir := strings.HasSuffix(p, "/")
		n := normPath(strings.TrimSuffix(p, "/"), en.Home)
		if n == "" {
			continue
		}
		if t == n || dir && strings.HasPrefix(t, n+"/") {
			return n
		}
	}
	return ""
}

// checkSelfProtect fires when a call tries to edit or kill tattlr's own
// guard rails: its policy and state, the hook configs it installed, or the
// binary the hooks run.
func (en *Engine) checkSelfProtect(e event.Event, add func(string, string, Severity)) {
	text := e.Command + "\n" + e.Args
	if killTattlrRe.MatchString(e.Command) {
		add(RuleSelfProtect, "stop or remove tattlr", 0)
		return
	}
	readOnly := e.Kind == event.Shell && ReadOnlyCommand(e.Command)
	if e.Kind != event.Read && e.Kind != event.Search && !readOnly && hooksOffRe.MatchString(text) {
		add(RuleSelfProtect, "turn hooks off", 0)
		return
	}
	if len(en.Protected) == 0 {
		return
	}
	switch e.Kind {
	case event.Write:
		for _, p := range splitPaths(e.Path) {
			if hit := en.protectedHit(p); hit != "" {
				add(RuleSelfProtect, hit, 0)
				return
			}
		}
	case event.Shell:
		if readOnly {
			return
		}
		for _, w := range words(e.Command) {
			if hit := en.protectedHit(w); hit != "" {
				add(RuleSelfProtect, hit, 0)
				return
			}
		}
	case event.MCP:
		l := strings.ToLower(e.Tool)
		if !strings.Contains(l, "write") && !strings.Contains(l, "edit") && !strings.Contains(l, "delete") &&
			!strings.Contains(l, "move") && !strings.Contains(l, "exec") && !strings.Contains(l, "run") &&
			!strings.Contains(l, "shell") && !strings.Contains(l, "patch") {
			return
		}
		for _, w := range words(e.Args) {
			if hit := en.protectedHit(strings.Trim(w, `\:`)); hit != "" {
				add(RuleSelfProtect, hit, 0)
				return
			}
		}
	}
}

// Evidence is the redacted one-line summary of an event, as used in
// findings and the audit log.
func Evidence(e event.Event) string { return evidence(e) }

func tattlrReadOnly(args []string) bool {
	switch args[0] {
	case "scan", "rules", "version", "help", "--help", "-h":
		return true
	case "protect":
		return len(args) > 1 && args[1] == "status"
	}
	return false
}
