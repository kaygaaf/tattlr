// Package repo reads a checkout and points out setup that runs before you
// have a chance to look: a session-start hook, a task that runs when the
// folder opens, an MCP server whose command is a local program, or an
// instruction file that tells an agent not to read a script and just run it.
// It only reads files. It does not run anything in the repo.
package repo

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/kaygaaf/tattlr/internal/rules"
)

// Rule IDs.
const (
	RuleSessionHook = "repo-session-hook"
	RuleFolderOpen  = "repo-folder-open"
	RuleLocalMCP    = "repo-local-mcp"
	RuleInstruction = "repo-hidden-instruction"
)

// Catalog lists the checkout checks, for SARIF and the README.
var Catalog = map[string]rules.Info{
	RuleSessionHook: {ID: RuleSessionHook, Title: "Session-start hook in this checkout", Category: "repo", Severity: rules.High},
	RuleFolderOpen:  {ID: RuleFolderOpen, Title: "Task runs when the folder opens", Category: "repo", Severity: rules.High},
	RuleLocalMCP:    {ID: RuleLocalMCP, Title: "MCP server runs a local program", Category: "repo", Severity: rules.High},
	RuleInstruction: {ID: RuleInstruction, Title: "Instruction file tells the agent to run something without looking", Category: "repo", Severity: rules.High},
}

// Finding is one problem in one file.
type Finding struct {
	Rule     string         `json:"rule"`
	Title    string         `json:"title"`
	Severity rules.Severity `json:"severity"`
	File     string         `json:"file"`
	Line     int            `json:"line"`
	Detail   string         `json:"detail"`
}

// Result is what Check found.
type Result struct {
	Files    []string  `json:"files"`
	Findings []Finding `json:"findings"`
	Warnings []string  `json:"warnings,omitempty"`
}

// Files we look for at the root of a checkout. A missing one is fine.
var knownFiles = []string{
	".claude/settings.json",
	".claude/settings.local.json",
	".claude/mcp.json",
	".cursor/hooks.json",
	".cursor/mcp.json",
	".gemini/settings.json",
	".gemini/mcp.json",
	".codex/hooks.json",
	".codex/config.toml",
	".codex/mcp.json",
	".mcp.json",
	"mcp.json",
	".vscode/mcp.json",
	".vscode/tasks.json",
	"CLAUDE.md",
	"AGENTS.md",
	".cursorrules",
	".github/copilot-instructions.md",
}

// Check looks at path, a checkout or one file. It does not run anything it finds.
func Check(path string) (*Result, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	res := &Result{Files: []string{}, Findings: []Finding{}}
	var files []string
	if !fi.IsDir() {
		files = []string{path}
	} else {
		for _, rel := range knownFiles {
			p := filepath.Join(path, filepath.FromSlash(rel))
			if _, err := os.Stat(p); err == nil {
				files = append(files, p)
			}
		}
		files = append(files, ruleFiles(filepath.Join(path, ".cursor", "rules"))...)
	}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			res.Warnings = append(res.Warnings, err.Error())
			continue
		}
		if len(src) > 1<<20 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s is over 1MB, skipped", f))
			continue
		}
		fs, err := CheckFile(f, src)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %v", f, err))
			continue
		}
		res.Files = append(res.Files, f)
		res.Findings = append(res.Findings, fs...)
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return res, nil
}

// CheckFile checks one file. name is used to decide what kind of file it is.
func CheckFile(name string, src []byte) ([]Finding, error) {
	switch {
	case isInstructionFile(name):
		return checkInstruction(name, src), nil
	case strings.HasSuffix(strings.ToLower(name), ".toml"):
		return checkTOML(name, src), nil
	case strings.HasSuffix(strings.ToLower(name), ".json"):
		return checkJSON(name, src)
	}
	return nil, nil
}

func ruleFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			sub, err := os.ReadDir(p)
			if err != nil {
				continue
			}
			for _, s := range sub {
				if s.IsDir() {
					continue
				}
				sp := filepath.Join(p, s.Name())
				if isInstructionFile(sp) {
					out = append(out, sp)
				}
			}
			continue
		}
		if isInstructionFile(p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func isInstructionFile(path string) bool {
	base := filepath.Base(path)
	switch base {
	case "CLAUDE.md", "AGENTS.md", ".cursorrules", "copilot-instructions.md":
		return true
	}
	return strings.Contains(filepath.ToSlash(path), "/.cursor/rules/")
}

func checkJSON(name string, src []byte) ([]Finding, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil
	}
	root := doc.Content[0]
	var out []Finding
	out = append(out, sessionHooks(name, get(root, "hooks"))...)
	out = append(out, mcpFrom(name, root)...)
	if strings.EqualFold(filepath.Base(name), "tasks.json") {
		out = append(out, folderTasks(name, root)...)
	}
	return out, nil
}

func sessionHooks(file string, hooks *yaml.Node) []Finding {
	if hooks == nil || hooks.Kind != yaml.MappingNode {
		return nil
	}
	var out []Finding
	for i := 0; i+1 < len(hooks.Content); i += 2 {
		event := hooks.Content[i].Value
		if !isSessionEvent(event) {
			continue
		}
		for _, cmd := range hookCommands(hooks.Content[i+1]) {
			if cmd.value == "" || ours(cmd.value) {
				continue
			}
			out = append(out, finding(RuleSessionHook, file, cmd.line,
				fmt.Sprintf("%s hook runs %q when the folder is trusted, before any PreToolUse hook", event, trunc(cmd.value))))
		}
	}
	return out
}

func isSessionEvent(name string) bool {
	n := strings.ToLower(name)
	n = strings.ReplaceAll(n, "-", "")
	n = strings.ReplaceAll(n, "_", "")
	return n == "sessionstart" || n == "folderopen"
}

type cmdHit struct {
	value string
	line  int
}

func hookCommands(n *yaml.Node) []cmdHit {
	if n == nil {
		return nil
	}
	var out []cmdHit
	switch n.Kind {
	case yaml.SequenceNode:
		for _, c := range n.Content {
			out = append(out, hookCommands(c)...)
		}
	case yaml.MappingNode:
		if c := get(n, "command"); c != nil && c.Kind == yaml.ScalarNode && c.Value != "" {
			// A group that only wraps other hooks has no command of its own.
			// Claude puts the command on the inner hook, Cursor on the entry.
			if get(n, "hooks") == nil {
				out = append(out, cmdHit{c.Value, lineOf(c)})
			}
		}
		if h := get(n, "hooks"); h != nil {
			out = append(out, hookCommands(h)...)
		}
	}
	return out
}

func mcpFrom(name string, root *yaml.Node) []Finding {
	var out []Finding
	for _, key := range []string{"mcpServers", "mcp_servers"} {
		out = append(out, mcpServers(name, get(root, key))...)
	}
	if isMCPFile(name) {
		out = append(out, mcpServers(name, get(root, "servers"))...)
	}
	return out
}

func isMCPFile(name string) bool {
	b := strings.ToLower(filepath.Base(name))
	return b == "mcp.json" || b == ".mcp.json"
}

func mcpServers(file string, servers *yaml.Node) []Finding {
	if servers == nil || servers.Kind != yaml.MappingNode {
		return nil
	}
	var out []Finding
	for i := 0; i+1 < len(servers.Content); i += 2 {
		srvName := servers.Content[i].Value
		spec := servers.Content[i+1]
		cmdNode := get(spec, "command")
		cmd := scalar(cmdNode)
		args := stringList(get(spec, "args"))
		if !isLocalMCP(cmd, args) {
			continue
		}
		line := lineOf(spec)
		if cmdNode != nil {
			line = lineOf(cmdNode)
		}
		shown := cmd
		if len(args) > 0 {
			shown += " " + strings.Join(args, " ")
		}
		out = append(out, finding(RuleLocalMCP, file, line,
			fmt.Sprintf("MCP server %q runs %q, a program in this checkout", srvName, trunc(shown))))
	}
	return out
}

func isLocalMCP(command string, args []string) bool {
	if looksLikeLocalProgram(command) {
		return true
	}
	if !isInterpreter(command) {
		return false
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if looksLikeLocalProgram(a) || looksLikeScript(a) {
			return true
		}
	}
	return false
}

func isInterpreter(command string) bool {
	switch strings.ToLower(filepath.Base(command)) {
	case "bash", "sh", "zsh", "python", "python3", "node", "perl", "ruby", "pwsh", "powershell":
		return true
	}
	return false
}

// looksLikeLocalProgram is a path or a script name, not an npx package.
func looksLikeLocalProgram(s string) bool {
	s = strings.Trim(s, `"'`)
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "@") {
		return false
	}
	if strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") || strings.HasPrefix(s, ".\\") {
		return true
	}
	if strings.Contains(s, "/") || strings.Contains(s, `\`) {
		return true
	}
	return looksLikeScript(s)
}

func looksLikeScript(s string) bool {
	switch strings.ToLower(filepath.Ext(strings.Trim(s, `"'`))) {
	case ".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".rb", ".pl", ".ps1", ".bat", ".cmd":
		return true
	}
	return false
}

func folderTasks(file string, root *yaml.Node) []Finding {
	tasks := get(root, "tasks")
	if tasks == nil || tasks.Kind != yaml.SequenceNode {
		return nil
	}
	var out []Finding
	for _, task := range tasks.Content {
		runOn := scalar(get(get(task, "runOptions"), "runOn"))
		if !strings.EqualFold(runOn, "folderOpen") {
			runOn = scalar(get(task, "runOn"))
		}
		if !strings.EqualFold(runOn, "folderOpen") {
			continue
		}
		cmd := scalar(get(task, "command"))
		label := scalar(get(task, "label"))
		if label == "" {
			label = cmd
		}
		line := lineOf(task)
		if c := get(task, "command"); c != nil && c.Line > 0 {
			line = c.Line
		}
		shown := cmd
		if shown == "" {
			shown = label
		}
		out = append(out, finding(RuleFolderOpen, file, line,
			fmt.Sprintf("task %q runs %q when the folder opens", label, trunc(shown))))
	}
	return out
}

var (
	dontRead  = regexp.MustCompile(`(?i)(\b(do not|don't|dont|never)\s+(read|open|inspect|examine)\s+(it|this|the file|the script|that file|that script|\S+\.(sh|py|js|mjs|bash))\b|\bnot to read\b)`)
	hideOut   = regexp.MustCompile(`(?i)\b(hide|suppress|conceal)\s+(the\s+)?(output|stdout|stderr|logs)\b|\b(do not|don't|dont)\s+(show|print|display)\s+(the\s+)?(output|result|command)\b`)
	noAsk     = regexp.MustCompile(`(?i)\b(without asking|without confirmation|without prompting|no questions asked|don't ask|do not ask|dont ask)\b|\bjust run (it|this|the script|the file|the command)\b|\brun (it|this|the script) (now|immediately|without)\b`)
	sealed    = regexp.MustCompile(`(?i)\bsealed\b`)
	scriptish = regexp.MustCompile(`(?i)(\.sh\b|\bscript\b|\bsetup\b)`)
)

func checkInstruction(file string, src []byte) []Finding {
	text := string(src)
	type hit struct {
		name string
		at   int
	}
	var hits []hit
	add := func(name string, re *regexp.Regexp) {
		loc := re.FindStringIndex(text)
		if loc == nil {
			return
		}
		hits = append(hits, hit{name, loc[0]})
	}
	add("not to read a file", dontRead)
	add("to hide the output", hideOut)
	add("to run something without asking", noAsk)
	if loc := sealed.FindStringIndex(text); loc != nil {
		start := loc[0] - 120
		if start < 0 {
			start = 0
		}
		end := loc[1] + 120
		if end > len(text) {
			end = len(text)
		}
		if scriptish.MatchString(text[start:end]) {
			hits = append(hits, hit{"that a script is sealed", loc[0]})
		}
	}
	if len(hits) == 0 {
		return nil
	}
	first := hits[0].at
	names := make([]string, len(hits))
	for i, h := range hits {
		names[i] = h.name
		if h.at < first {
			first = h.at
		}
	}
	line := bytes.Count(src[:first], []byte("\n")) + 1
	return []Finding{finding(RuleInstruction, file, line, "tells the agent "+humanJoin(names))}
}

func humanJoin(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + ", and " + parts[len(parts)-1]
}

var (
	tomlHeader  = regexp.MustCompile(`^\s*\[\[?([^\]\s]+)\]\]?\s*$`)
	tomlCommand = regexp.MustCompile(`^\s*command\s*=\s*(.+?)\s*$`)
	tomlQuoted  = regexp.MustCompile(`"([^"]*)"|'([^']*)'`)
	oursRe      = regexp.MustCompile(`(?i)\bhook\s+(claude|codex|cursor|gemini|openclaw)\b`)
)

func checkTOML(file string, src []byte) []Finding {
	lines := strings.Split(string(src), "\n")
	var out []Finding
	section := ""
	var body []tomlLine
	flush := func() {
		if section == "" {
			return
		}
		out = append(out, tomlSection(file, section, body)...)
	}
	for i, line := range lines {
		if m := tomlHeader.FindStringSubmatch(line); m != nil {
			flush()
			section = m[1]
			body = nil
			continue
		}
		if section != "" {
			body = append(body, tomlLine{n: i + 1, text: line})
		}
	}
	flush()
	return out
}

type tomlLine struct {
	n    int
	text string
}

func tomlSection(file, section string, body []tomlLine) []Finding {
	sec := strings.ToLower(section)
	switch {
	case isSessionEvent(strings.TrimPrefix(strings.TrimPrefix(sec, "hooks."), "hooks.")):
		// hooks.SessionStart or hooks.SessionStart.hooks
		return tomlHookCommands(file, section, body)
	case strings.HasPrefix(sec, "hooks.") && isSessionEvent(sectionTail(sec)):
		return tomlHookCommands(file, section, body)
	case strings.HasPrefix(sec, "mcp_servers."):
		return tomlMCP(file, strings.TrimPrefix(section, section[:len("mcp_servers.")]), body)
	}
	return nil
}

// sectionTail returns the event name from hooks.SessionStart or hooks.SessionStart.hooks.
func sectionTail(sec string) string {
	sec = strings.TrimPrefix(sec, "hooks.")
	sec = strings.TrimSuffix(sec, ".hooks")
	return sec
}

func tomlHookCommands(file, section string, body []tomlLine) []Finding {
	event := section
	if i := strings.LastIndex(section, "."); i >= 0 {
		event = section[i+1:]
	}
	if strings.EqualFold(event, "hooks") {
		// hooks.SessionStart.hooks: the event is the middle part.
		parts := strings.Split(section, ".")
		if len(parts) >= 2 {
			event = parts[len(parts)-2]
		}
	}
	var out []Finding
	for _, ln := range body {
		m := tomlCommand.FindStringSubmatch(ln.text)
		if m == nil {
			continue
		}
		cmd := unquote(m[1])
		if cmd == "" || ours(cmd) {
			continue
		}
		out = append(out, finding(RuleSessionHook, file, ln.n,
			fmt.Sprintf("%s hook runs %q when the folder is trusted, before any PreToolUse hook", event, trunc(cmd))))
	}
	return out
}

func tomlMCP(file, name string, body []tomlLine) []Finding {
	var cmd string
	var cmdLine int
	var args []string
	for _, ln := range body {
		if m := tomlCommand.FindStringSubmatch(ln.text); m != nil && cmd == "" {
			cmd = unquote(m[1])
			cmdLine = ln.n
		}
		if strings.Contains(strings.ToLower(ln.text), "args") {
			for _, q := range tomlQuoted.FindAllStringSubmatch(ln.text, -1) {
				s := q[1] + q[2]
				if s != "" {
					args = append(args, s)
				}
			}
		}
	}
	if !isLocalMCP(cmd, args) {
		return nil
	}
	shown := cmd
	if len(args) > 0 {
		shown += " " + strings.Join(args, " ")
	}
	if cmdLine == 0 {
		cmdLine = 1
	}
	return []Finding{finding(RuleLocalMCP, file, cmdLine,
		fmt.Sprintf("MCP server %q runs %q, a program in this checkout", name, trunc(shown)))}
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func ours(cmd string) bool {
	return strings.Contains(strings.ToLower(cmd), "tattlr") && oursRe.MatchString(cmd)
}

func finding(rule, file string, line int, detail string) Finding {
	info := Catalog[rule]
	if line < 1 {
		line = 1
	}
	return Finding{Rule: rule, Title: info.Title, Severity: info.Severity, File: file, Line: line, Detail: detail}
}

func trunc(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}

func get(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func stringList(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.ScalarNode && n.Value != "" {
		return []string{n.Value}
	}
	if n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, c := range n.Content {
		if c.Kind == yaml.ScalarNode && c.Value != "" {
			out = append(out, c.Value)
		}
	}
	return out
}

func lineOf(n *yaml.Node) int {
	if n == nil || n.Line < 1 {
		return 1
	}
	return n.Line
}
