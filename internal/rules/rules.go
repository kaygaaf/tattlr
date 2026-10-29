// Package rules decides which tool calls deserve a mention on the rap sheet.
package rules

import (
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/redact"
)

// Severity orders findings. Higher is worse.
type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	}
	return "unknown"
}

// MarshalText makes severities read as words in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity turns "high" into High. Unknown strings give 0.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "low":
		return Low
	case "medium", "med":
		return Medium
	case "high":
		return High
	case "critical", "crit":
		return Critical
	}
	return 0
}

// Weight is how many points a severity adds to an agent's score.
func (s Severity) Weight() int {
	switch s {
	case Critical:
		return 25
	case High:
		return 8
	case Medium:
		return 3
	case Low:
		return 1
	}
	return 0
}

// Rule IDs. These are stable and show up in --json output.
const (
	RuleCanary        = "canary"
	RuleSecretRead    = "secret-read"
	RuleSecretWrite   = "secret-write"
	RuleKeychain      = "keychain"
	RuleEnvDump       = "env-dump"
	RuleRmRf          = "rm-rf"
	RuleForcePush     = "git-force-push"
	RuleResetHard     = "git-reset-hard"
	RuleGitClean      = "git-clean"
	RuleGitDiscard    = "git-discard"
	RuleNoVerify      = "git-no-verify"
	RuleChmod777      = "chmod-777"
	RuleDiskWipe      = "disk-wipe"
	RuleSQLDrop       = "sql-drop"
	RuleRemoteCode    = "remote-code"
	RuleRunDownloaded = "run-downloaded"
	RuleUpload        = "upload"
	RuleExfil         = "exfil"
	RuleDropSite      = "drop-site"
	RuleSecretInURL   = "secret-in-url"
	RuleSudo          = "sudo"
	RuleShellProfile  = "shell-profile"
	RuleAgentConfig   = "agent-config"
	RulePersistence   = "persistence"
	RuleSandboxEscape = "sandbox-escape"
	RuleYoloSpawn     = "yolo-spawn"
)

// Info describes one rule for humans.
type Info struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
}

// Catalog lists every rule with its default severity.
var Catalog = map[string]Info{
	RuleCanary:        {RuleCanary, "Touched a tattlr canary", "canary", Critical},
	RuleSecretRead:    {RuleSecretRead, "Read a secret file", "secrets", High},
	RuleSecretWrite:   {RuleSecretWrite, "Wrote to a secret file", "secrets", Medium},
	RuleKeychain:      {RuleKeychain, "Pulled a credential from a keychain or CLI", "secrets", High},
	RuleEnvDump:       {RuleEnvDump, "Dumped environment variables", "secrets", Medium},
	RuleRmRf:          {RuleRmRf, "Ran rm -rf", "destructive", Medium},
	RuleForcePush:     {RuleForcePush, "Force pushed", "destructive", High},
	RuleResetHard:     {RuleResetHard, "Ran git reset --hard", "destructive", High},
	RuleGitClean:      {RuleGitClean, "Ran git clean", "destructive", Medium},
	RuleGitDiscard:    {RuleGitDiscard, "Threw away uncommitted changes", "destructive", Medium},
	RuleNoVerify:      {RuleNoVerify, "Skipped git hooks with --no-verify", "destructive", Low},
	RuleChmod777:      {RuleChmod777, "Made files world-writable", "destructive", High},
	RuleDiskWipe:      {RuleDiskWipe, "Wrote straight to a disk device", "destructive", Critical},
	RuleSQLDrop:       {RuleSQLDrop, "Dropped or truncated a database table", "destructive", High},
	RuleRemoteCode:    {RuleRemoteCode, "Piped a remote script into a shell", "remote-code", Critical},
	RuleRunDownloaded: {RuleRunDownloaded, "Downloaded a script and ran it", "remote-code", High},
	RuleUpload:        {RuleUpload, "Uploaded a local file", "network", High},
	RuleExfil:         {RuleExfil, "Sent secrets over the network", "network", Critical},
	RuleDropSite:      {RuleDropSite, "Talked to a paste or webhook drop site", "network", High},
	RuleSecretInURL:   {RuleSecretInURL, "Put a secret in a URL", "network", High},
	RuleSudo:          {RuleSudo, "Used sudo", "privilege", Medium},
	RuleShellProfile:  {RuleShellProfile, "Edited a shell startup file", "tampering", High},
	RuleAgentConfig:   {RuleAgentConfig, "Edited its own config or hooks", "tampering", High},
	RulePersistence:   {RulePersistence, "Set up something that runs later", "tampering", Medium},
	RuleSandboxEscape: {RuleSandboxEscape, "Asked to run outside the sandbox", "privilege", Medium},
	RuleYoloSpawn:     {RuleYoloSpawn, "Started another agent with approvals off", "privilege", Medium},
}

// Finding is one rule hit on one event.
type Finding struct {
	Rule     string      `json:"rule"`
	Title    string      `json:"title"`
	Category string      `json:"category"`
	Severity Severity    `json:"severity"`
	Detail   string      `json:"detail,omitempty"`
	Evidence string      `json:"evidence"`
	Event    event.Event `json:"event"`
}

// Canary is a planted fake secret that scan should watch for.
type Canary struct {
	Path    string    `json:"path"`
	Markers []string  `json:"markers"`
	Planted time.Time `json:"planted"`
}

// Engine runs every rule against events.
type Engine struct {
	Home     string
	Canaries []Canary
	// Protected lists files tattlr guards from edits: its own config,
	// installed hook configs and its binary. A trailing "/" means the whole
	// folder.
	Protected []string
	// Cwd resolves relative paths when known (live hooks know it).
	Cwd string
}

// Check returns the findings for one event, at most one per rule.
func (en *Engine) Check(e event.Event) []Finding {
	var out []Finding
	seen := map[string]bool{}
	add := func(rule, detail string, sev Severity) {
		if seen[rule] {
			return
		}
		seen[rule] = true
		info := Catalog[rule]
		if sev == 0 {
			sev = info.Severity
		}
		out = append(out, Finding{
			Rule: rule, Title: info.Title, Category: info.Category, Severity: sev,
			Detail: detail, Evidence: evidence(e), Event: scrub(e),
		})
	}

	en.checkCanary(e, add)
	en.checkSelfProtect(e, add)
	if e.Escalated {
		add(RuleSandboxEscape, "", 0)
	}
	switch e.Kind {
	case event.Shell:
		en.checkShell(e.Command, add)
	case event.Read, event.Search:
		for _, p := range splitPaths(e.Path) {
			if k := secretKind(p, en.Home); k != "" {
				add(RuleSecretRead, k, 0)
			}
		}
	case event.Write:
		for _, p := range splitPaths(e.Path) {
			en.checkWriteTarget(p, add)
		}
	case event.Fetch, event.MCP:
		en.checkURL(e.URL, add)
		for _, u := range urlRe.FindAllString(e.Args, -1) {
			en.checkURL(u, add)
		}
		if e.Kind == event.MCP {
			// MCP tools that run shell commands or read files.
			for _, w := range words(e.Args) {
				if k := secretKind(w, en.Home); k != "" && looksLikePath(w) {
					add(RuleSecretRead, k+" via MCP", 0)
				}
			}
		}
	}
	return out
}

func splitPaths(p string) []string {
	if p == "" {
		return nil
	}
	// Multi-file reads are joined with newlines. Single paths may contain
	// spaces ("Application Support"), so never split on those.
	var out []string
	for _, l := range strings.Split(p, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func looksLikePath(w string) bool {
	return strings.Contains(w, "/") || strings.HasPrefix(w, ".")
}

func (en *Engine) checkWriteTarget(p string, add func(string, string, Severity)) {
	if isShellProfile(p, en.Home) {
		add(RuleShellProfile, path.Base(normPath(p, en.Home)), 0)
	}
	if c := agentConfig(p, en.Home); c != "" {
		add(RuleAgentConfig, c, 0)
	}
	if t := persistenceTarget(p, en.Home); t != "" {
		add(RulePersistence, t, 0)
	}
	if k := secretKind(p, en.Home); k != "" {
		add(RuleSecretWrite, k, 0)
	}
}

func (en *Engine) checkCanary(e event.Event, add func(string, string, Severity)) {
	if len(en.Canaries) == 0 {
		return
	}
	hay := []string{e.Path, e.Command, e.URL, e.Args, e.Output}
	live := func(c Canary) bool {
		return e.Time.IsZero() || c.Planted.IsZero() || !e.Time.Before(c.Planted)
	}
	// A direct hit on a canary file wins over a marker match, so the detail
	// names the right canary.
	for _, c := range en.Canaries {
		cp := normPath(c.Path, en.Home)
		if !live(c) || cp == "" {
			continue
		}
		for _, h := range hay[:4] {
			for _, w := range words(h) {
				if normPath(w, en.Home) == cp {
					add(RuleCanary, cp, 0)
					return
				}
			}
		}
	}
	for _, c := range en.Canaries {
		if !live(c) {
			continue
		}
		for _, h := range hay {
			for _, m := range c.Markers {
				if m != "" && h != "" && strings.Contains(h, m) {
					add(RuleCanary, normPath(c.Path, en.Home), 0)
					return
				}
			}
		}
	}
}

var (
	urlRe          = regexp.MustCompile(`https?://[^\s"'<>)]+`)
	remotePipeRe   = regexp.MustCompile(`(?i)\b(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod|fetch)\b[^|;&\n]*\|\s*(sudo\s+(-\S+\s+)*)?(env\s+\S+=\S+\s+)*(ba|z|da|k|fi|c|tc)?sh\b|\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(python[0-9.]*|node|perl|ruby|php|iex|invoke-expression)\b`)
	procSubRe      = regexp.MustCompile(`\b(ba|z)?sh\s+(-s\s+)?<\(\s*(curl|wget)\b`)
	evalCurlRe     = regexp.MustCompile(`\b(eval|(ba|z)?sh\s+-c|source|\.)\s+["']?\$\(\s*(curl|wget)\b`)
	iexRe          = regexp.MustCompile(`(?i)\b(iex|invoke-expression)\b.*\b(iwr|irm|invoke-webrequest|invoke-restmethod|downloadstring)\b`)
	sqlDropRe      = regexp.MustCompile(`(?i)\b(drop\s+(table|database|schema)|truncate\s+table)\b`)
	diskDevRe      = regexp.MustCompile(`^/dev/(sd[a-z]|nvme\d|disk\d|rdisk\d|hd[a-z]|mmcblk\d|vd[a-z]|xvd[a-z])`)
	keychainRe     = regexp.MustCompile(`\bsecurity\s+(find-generic-password|find-internet-password|dump-keychain|export)\b|\bsecret-tool\s+lookup\b|\bpass\s+show\b|\bop\s+(read|item\s+get)\b|\bgh\s+auth\s+token\b|\bgcloud\s+auth\s+(print-access-token|print-identity-token|application-default\s+print-access-token)\b|\baws\s+configure\s+(get|export-credentials)\b|\baws\s+sts\s+get-session-token\b|\baz\s+account\s+get-access-token\b|\bkeyring\s+get\b|\bcmdkey\s+/list\b|\bvault\s+(kv\s+get|read)\b`)
	yoloRe         = regexp.MustCompile(`\b(claude\b[^|;&\n]*--dangerously-skip-permissions|codex\b[^|;&\n]*(--yolo|--dangerously-bypass-approvals-and-sandbox|--full-auto)|gemini\b[^|;&\n]*(--yolo|-y\b|--approval-mode[= ]yolo)|cursor-agent\b[^|;&\n]*(--force|-f\b|--yolo))`)
	sudoRe         = regexp.MustCompile(`(^|[\s;&|(])(sudo|doas|pkexec)\s|\bsu\s+(-\s+|-c\s|root\b)`)
	networkProgram = map[string]bool{"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true, "scp": true,
		"rsync": true, "sftp": true, "ftp": true, "http": true, "https": true, "xh": true, "telnet": true, "socat": true, "ssh": true}
)

// Hosts that only make sense as a place to drop data.
var dropHosts = []string{"pastebin.com", "paste.ee", "hastebin.com", "ghostbin", "transfer.sh", "0x0.st", "file.io",
	"termbin.com", "webhook.site", "requestbin", "pipedream.net", "ngrok.io", "ngrok-free.app", "ngrok.app",
	"interact.sh", "oast.fun", "oast.pro", "oast.live", "burpcollaborator.net", "canarytokens.com",
	"discord.com/api/webhooks", "discordapp.com/api/webhooks", "hooks.slack.com", "api.telegram.org/bot",
	"beeceptor.com", "requestcatcher.com", "dnslog.cn", "temp.sh", "bashupload.com", "litterbox.catbox.moe", "catbox.moe"}

func dropHost(s string) string {
	l := strings.ToLower(s)
	for _, h := range dropHosts {
		if strings.Contains(l, h) {
			return h
		}
	}
	return ""
}

func (en *Engine) checkURL(u string, add func(string, string, Severity)) {
	if u == "" {
		return
	}
	if h := dropHost(u); h != "" {
		add(RuleDropSite, h, 0)
	}
	if pu, err := url.Parse(u); err == nil {
		if pu.User != nil {
			if _, ok := pu.User.Password(); ok {
				add(RuleSecretInURL, "password in URL", 0)
			}
		}
		if q := pu.RawQuery; q != "" && redact.String(q) != q {
			add(RuleSecretInURL, "token in query string", 0)
		}
	}
}

func (en *Engine) checkShell(cmd string, add func(string, string, Severity)) {
	if strings.TrimSpace(cmd) == "" {
		return
	}
	segs := splitShell(cmd)

	// Remote code.
	if remotePipeRe.MatchString(cmd) || procSubRe.MatchString(cmd) || evalCurlRe.MatchString(cmd) || iexRe.MatchString(cmd) {
		add(RuleRemoteCode, "", 0)
	}
	if sudoRe.MatchString(cmd) {
		add(RuleSudo, "", 0)
	}
	if keychainRe.MatchString(cmd) {
		add(RuleKeychain, "", 0)
	}
	if yoloRe.MatchString(cmd) {
		add(RuleYoloSpawn, "", 0)
	}
	if sqlDropRe.MatchString(cmd) {
		add(RuleSQLDrop, "", 0)
	}
	if h := dropHost(cmd); h != "" && hasNetworkProgram(segs) {
		add(RuleDropSite, h, 0)
	}
	for _, u := range urlRe.FindAllString(cmd, -1) {
		if pu, err := url.Parse(u); err == nil && pu.RawQuery != "" && redact.String(pu.RawQuery) != pu.RawQuery {
			add(RuleSecretInURL, "token in query string", 0)
		}
	}

	// Secrets mentioned anywhere in the command.
	secret := ""
	for _, w := range words(cmd) {
		if k := secretKind(w, en.Home); k != "" && !isSafeSecretMention(w) {
			secret = k
			break
		}
	}

	downloaded := map[string]bool{}
	envDumped := false
	sentSecret := false
	for i, s := range segs {
		p := prog(s)
		args := s.Args
		if len(args) == 0 {
			p = ""
		}
		switch p {
		case "rm":
			if hasFlag(args[1:], 'r', "--recursive") || hasFlag(args[1:], 'R') {
				if hasFlag(args[1:], 'f', "--force") {
					sev := Medium
					detail := strings.Join(positional(args[1:]), " ")
					for _, t := range positional(args[1:]) {
						if dangerousTarget(t) {
							sev = Critical
						}
					}
					add(RuleRmRf, detail, sev)
				}
			}
		case "git":
			en.checkGit(args, add)
		case "chmod":
			for _, a := range args[1:] {
				if a == "777" || a == "0777" || a == "a+rwx" || a == "o+w" || a == "a+w" || a == "ugo+rwx" {
					sev := High
					if !hasFlag(args[1:], 'R', "--recursive") {
						sev = Medium
					}
					add(RuleChmod777, strings.Join(positional(args[1:]), " "), sev)
				}
			}
		case "dd":
			for _, a := range args[1:] {
				if strings.HasPrefix(a, "of=") && diskDevRe.MatchString(strings.TrimPrefix(a, "of=")) {
					add(RuleDiskWipe, a, 0)
				}
			}
		case "mkfs", "wipefs", "fdisk", "sfdisk", "parted", "shred":
			add(RuleDiskWipe, p, 0)
		case "diskutil":
			if len(args) > 1 && (strings.HasPrefix(args[1], "erase") || args[1] == "zeroDisk" || args[1] == "secureErase") {
				add(RuleDiskWipe, "diskutil "+args[1], 0)
			}
		case "env", "printenv":
			if len(positional(args[1:])) == 0 {
				envDumped = true
				add(RuleEnvDump, "", 0)
			}
		case "export", "set", "declare":
			if len(args) == 1 || (len(args) == 2 && (args[1] == "-p" || args[1] == "-x")) {
				envDumped = true
				add(RuleEnvDump, "", 0)
			}
		case "crontab":
			if !hasFlag(args[1:], 'l') {
				add(RulePersistence, "crontab", 0)
			}
		case "launchctl":
			if len(args) > 1 && (args[1] == "load" || args[1] == "bootstrap" || args[1] == "submit") {
				add(RulePersistence, "launchctl "+args[1], 0)
			}
		case "systemctl":
			if len(args) > 1 && (args[1] == "enable" || contains(args, "enable")) {
				add(RulePersistence, "systemctl enable", 0)
			}
		case "curl", "wget", "http", "https", "xh":
			if isUpload(p, args) {
				add(RuleUpload, "", 0)
			}
			if f := downloadTarget(p, args); f != "" {
				downloaded[f] = true
			}
			if (envDumped || sentSecret) && i > 0 && segs[i-1].PipeNext {
				add(RuleExfil, "piped into "+p, 0)
			}
			if secret != "" {
				add(RuleExfil, secret+" sent with "+p, 0)
			}
		case "nc", "ncat", "netcat", "socat", "telnet":
			if len(s.In) > 0 || (i > 0 && segs[i-1].PipeNext) {
				add(RuleUpload, p, 0)
			}
			if secret != "" {
				add(RuleExfil, secret+" sent with "+p, 0)
			}
		case "scp", "rsync", "sftp":
			if secret != "" && hasRemote(args[1:]) {
				add(RuleExfil, secret+" copied with "+p, 0)
			}
		case "sh", "bash", "zsh", "source", ".":
			if len(args) > 1 && downloaded[strings.TrimPrefix(args[len(args)-1], "./")] {
				add(RuleRunDownloaded, args[len(args)-1], 0)
			}
		case "python", "python3", "node", "perl", "ruby":
			if len(args) > 1 && downloaded[strings.TrimPrefix(args[1], "./")] {
				add(RuleRunDownloaded, args[1], 0)
			}
		default:
			if strings.HasPrefix(p, "mkfs") {
				add(RuleDiskWipe, p, 0)
			}
			if len(args) > 0 && strings.HasPrefix(args[0], "./") && downloaded[strings.TrimPrefix(args[0], "./")] {
				add(RuleRunDownloaded, args[0], 0)
			}
		}
		if secret != "" && s.PipeNext {
			sentSecret = true
		}

		// Writes done from the shell: redirects, tee, sed -i, cp, mv, ln, install.
		for _, t := range s.Out {
			en.checkWriteTarget(t, add)
			if diskDevRe.MatchString(t) {
				add(RuleDiskWipe, t, 0)
			}
		}
		if t := shellWriteTargets(p, args); len(t) > 0 {
			for _, x := range t {
				en.checkWriteTarget(x, add)
			}
		}
	}

	if secret != "" {
		add(RuleSecretRead, secret, 0)
	}
}

func isSafeSecretMention(w string) bool {
	// Things like "--exclude=.env" or "*.pem" globs in .gitignore edits are not reads.
	return strings.ContainsAny(w, "*?") || strings.HasPrefix(w, "!")
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func hasNetworkProgram(segs []segment) bool {
	for _, s := range segs {
		if networkProgram[prog(s)] {
			return true
		}
	}
	return false
}

func hasRemote(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if i := strings.Index(a, ":"); i > 0 && !strings.Contains(a[:i], "/") {
			return true
		}
	}
	return false
}

func dangerousTarget(t string) bool {
	t = strings.TrimRight(t, "/")
	switch t {
	case "", "~", "$HOME", "${HOME}", "/*", "~/*", "*", ".", "..", "./*", "../*", "/usr", "/etc", "/var", "/bin",
		"/System", "/Users", "/home", "/opt", "/Library", "/boot", "/lib", "$HOME/*", "C:", "C:\\":
		return true
	}
	return strings.HasPrefix(t, "/") && strings.Count(t, "/") == 1 || homeRe.MatchString(t+"/") && strings.Count(t, "/") <= 2
}

func (en *Engine) checkGit(args []string, add func(string, string, Severity)) {
	sub := ""
	rest := []string{}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if sub == "" {
			if a == "-C" || a == "-c" {
				i++
				continue
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
			sub = a
			continue
		}
		rest = append(rest, a)
	}
	switch sub {
	case "push":
		if contains(rest, "--force-with-lease") || anyPrefix(rest, "--force-with-lease=") || contains(rest, "--force-if-includes") {
			add(RuleForcePush, "--force-with-lease", Medium)
		} else if hasFlag(rest, 'f', "--force") || anyPrefix(rest, "+") {
			add(RuleForcePush, "", 0)
		}
		if contains(rest, "--delete") || contains(rest, "-d") || anyPrefix(rest, ":") {
			add(RuleForcePush, "deleted a remote branch", Medium)
		}
		if contains(rest, "--no-verify") {
			add(RuleNoVerify, "", 0)
		}
	case "reset":
		if contains(rest, "--hard") {
			add(RuleResetHard, strings.Join(positional(rest), " "), 0)
		}
	case "clean":
		if hasFlag(rest, 'f', "--force") {
			sev := Medium
			if hasFlag(rest, 'x') {
				sev = High
			}
			add(RuleGitClean, "", sev)
		}
	case "checkout", "restore":
		p := positional(rest)
		if (contains(rest, "--") || sub == "restore") && (contains(p, ".") || contains(p, ":/")) {
			add(RuleGitDiscard, sub+" .", 0)
		}
	case "stash":
		if len(rest) > 0 && (rest[0] == "clear" || rest[0] == "drop") {
			add(RuleGitDiscard, "stash "+rest[0], 0)
		}
	case "branch":
		if contains(rest, "-D") {
			add(RuleGitDiscard, "branch -D", Low)
		}
	case "commit", "merge", "rebase", "am":
		if contains(rest, "--no-verify") || (sub == "commit" && contains(rest, "-n")) {
			add(RuleNoVerify, "", 0)
		}
	case "filter-branch", "filter-repo":
		add(RuleForcePush, "rewrote history with "+sub, Medium)
	}
}

func anyPrefix(xs []string, p string) bool {
	for _, x := range xs {
		if strings.HasPrefix(x, p) {
			return true
		}
	}
	return false
}

func isUpload(p string, args []string) bool {
	switch p {
	case "curl":
		for i, a := range args {
			next := ""
			if i+1 < len(args) {
				next = args[i+1]
			}
			switch {
			case a == "-T" || a == "--upload-file":
				return true
			case (a == "-d" || a == "--data" || a == "--data-binary" || a == "--data-raw" || a == "--data-urlencode" || a == "-F" || a == "--form") &&
				(strings.HasPrefix(next, "@") || strings.Contains(next, "=@") || strings.Contains(next, "=<")):
				return true
			case strings.HasPrefix(a, "--data-binary=@") || strings.HasPrefix(a, "-d@") || strings.HasPrefix(a, "--data=@"):
				return true
			}
		}
	case "wget":
		for _, a := range args {
			if strings.HasPrefix(a, "--post-file") || strings.HasPrefix(a, "--body-file") {
				return true
			}
		}
	case "http", "https", "xh":
		for _, a := range args {
			if strings.Contains(a, "@") && strings.Contains(a, "=@") || strings.HasPrefix(a, "@") {
				return true
			}
		}
	}
	return false
}

func downloadTarget(p string, args []string) string {
	for i, a := range args {
		if i+1 >= len(args) {
			break
		}
		if (p == "curl" && (a == "-o" || a == "--output")) || (p == "wget" && (a == "-O" || a == "--output-document")) {
			if args[i+1] != "-" {
				return strings.TrimPrefix(args[i+1], "./")
			}
		}
	}
	if p == "curl" && (contains(args, "-O") || contains(args, "--remote-name")) {
		for _, a := range args {
			if strings.HasPrefix(a, "http") {
				return path.Base(a)
			}
		}
	}
	if p == "wget" && !contains(args, "-O") && !contains(args, "-qO-") {
		for _, a := range args {
			if strings.HasPrefix(a, "http") {
				return path.Base(a)
			}
		}
	}
	return ""
}

// shellWriteTargets returns the files a command writes, for the commands
// where that is easy to tell.
func shellWriteTargets(p string, args []string) []string {
	if len(args) < 2 {
		return nil
	}
	pos := positional(args[1:])
	switch p {
	case "tee":
		return pos
	case "sed", "perl":
		if hasFlag(args[1:], 'i', "--in-place") || anyPrefix(args[1:], "-i") || anyPrefix(args[1:], "-pi") {
			if len(pos) > 1 {
				return pos[1:]
			}
		}
	case "cp", "mv", "ln", "install", "rsync":
		if len(pos) >= 2 {
			return pos[len(pos)-1:]
		}
	case "touch", "truncate":
		return pos
	}
	return nil
}

// scrub returns a copy of e with secrets masked and output dropped.
func scrub(e event.Event) event.Event {
	e.Command = redact.String(e.Command)
	e.Path = redact.String(e.Path)
	e.URL = redact.String(e.URL)
	e.Args = redact.Line(e.Args, 500)
	e.Output = ""
	return e
}

// evidence is the one-line, redacted thing worth showing for an event.
func evidence(e event.Event) string {
	switch {
	case e.Command != "":
		return redact.Line(e.Command, 300)
	case e.URL != "":
		return redact.Line(e.Tool+" "+e.URL, 300)
	case e.Path != "":
		return redact.Line(e.Tool+" "+e.Path, 300)
	default:
		return redact.Line(e.Tool+" "+e.Args, 300)
	}
}
