// Package workflows reads GitHub Actions workflow files and points out the
// ones where people outside the repo can steer a coding agent: an agent step
// that runs on issues or comments, with text from those events in its
// prompt, open to any user, or holding write access and secrets.
package workflows

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
	RulePrompt  = "workflow-untrusted-prompt"
	RuleOpen    = "workflow-agent-open"
	RuleWrite   = "workflow-agent-write"
	RuleSandbox = "workflow-agent-sandbox-off"
	RuleTrigger = "workflow-agent-trigger"
)

// Catalog lists the workflow checks, for SARIF and the README.
var Catalog = map[string]rules.Info{
	RulePrompt:  {ID: RulePrompt, Title: "Text that outsiders write goes into the agent's prompt", Category: "workflow", Severity: rules.High},
	RuleOpen:    {ID: RuleOpen, Title: "Agent runs for anyone, not just people with write access", Category: "workflow", Severity: rules.High},
	RuleWrite:   {ID: RuleWrite, Title: "Agent that outsiders can reach has write access or extra secrets", Category: "workflow", Severity: rules.High},
	RuleSandbox: {ID: RuleSandbox, Title: "Agent that outsiders can reach runs without its sandbox or prompts", Category: "workflow", Severity: rules.High},
	RuleTrigger: {ID: RuleTrigger, Title: "Agent runs on events anyone can create", Category: "workflow", Severity: rules.Low},
}

// Finding is one problem in one agent step.
type Finding struct {
	Rule     string         `json:"rule"`
	Title    string         `json:"title"`
	Severity rules.Severity `json:"severity"`
	File     string         `json:"file"`
	Line     int            `json:"line"`
	Job      string         `json:"job"`
	Step     string         `json:"step,omitempty"`
	Detail   string         `json:"detail"`
}

// Result is what Check found.
type Result struct {
	Files    []string  `json:"files"`
	Findings []Finding `json:"findings"`
	Warnings []string  `json:"warnings,omitempty"`
}

// Check looks at path, which can be a repo (it reads .github/workflows), a
// folder of workflow files or a single file.
func Check(path string) (*Result, error) {
	files, err := findFiles(path)
	if err != nil {
		return nil, err
	}
	res := &Result{Files: []string{}, Findings: []Finding{}}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			res.Warnings = append(res.Warnings, err.Error())
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

func findFiles(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return []string{path}, nil
	}
	dir := path
	if d := filepath.Join(path, ".github", "workflows"); isDir(d) {
		dir = d
	}
	var out []string
	for _, pat := range []string{"*.yml", "*.yaml"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		out = append(out, m...)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("no workflow files in %s (looked for .github/workflows/*.yml)", path)
	}
	return out, nil
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// Triggers where the event text, and often the run itself, comes from
// whoever opened the issue, comment, PR or discussion.
var outsiderTriggers = map[string]bool{
	"issues": true, "issue_comment": true, "pull_request_target": true,
	"pull_request_review": true, "pull_request_review_comment": true,
	"discussion": true, "discussion_comment": true,
}

var agentActions = []string{
	"anthropics/claude-code-action",
	"anthropics/claude-code-base-action",
	"openai/codex-action",
	"google-github-actions/run-gemini-cli",
	"google-gemini/gemini-cli-action",
}

var agentCLI = regexp.MustCompile(`(?m)(^|[\s;&|(])(` +
	`claude(\s[^\n;&|]*)?\s(-p|--print)\b|` +
	`codex(\s[^\n;&|]*)?\sexec\b|` +
	`gemini(\s[^\n;&|]*)?\s(-p|--prompt)\b|` +
	`cursor-agent(\s[^\n;&|]*)?\s(-p|--print)\b)`)

// Event fields that hold text the author of the issue, comment or PR picked.
var outsiderText = regexp.MustCompile(`github\.event\.(` +
	`issue\.(title|body)|comment\.body|review\.body|review_comment\.body|` +
	`pull_request\.(title|body|head\.ref|head\.label)|discussion\.(title|body)|` +
	`head_commit\.message|commits)|github\.head_ref|toJSON\(\s*github\.event`)

var expr = regexp.MustCompile(`\$\{\{(.*?)\}\}`)

var secretRef = regexp.MustCompile(`secrets\.([A-Za-z0-9_]+)|toJSON\(\s*secrets\s*\)`)

// Secrets an agent step needs to run at all. Anything else handed to the
// agent is something a prompt injection can walk off with.
var agentSecrets = regexp.MustCompile(`^(GITHUB_TOKEN|\w*(ANTHROPIC|OPENAI|CODEX|GEMINI|GOOGLE|CLAUDE|AZURE|OPENROUTER)\w*_(API_KEY|OAUTH_TOKEN))$`)

var sandboxOff = regexp.MustCompile(`--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|` +
	`danger-full-access|--full-auto|--yolo|--approval-mode[= ]yolo|bypassPermissions`)

// Inputs that turn off the actor check in the agent actions.
var openInputs = []string{"allow-users", "allowed_non_write_users", "allowed_bots", "allow-bots"}

// Permissions that let a hijacked agent change code, releases or packages.
var writeScopes = []string{"actions", "contents", "deployments", "id-token", "packages", "pages"}

// A job or step "if" that checks who is asking.
var actorGate = regexp.MustCompile(`author_association|github\.actor|github\.triggering_actor|sender\.login`)

type workflow struct {
	triggers []string
	perms    *yaml.Node
	env      *yaml.Node
}

// CheckFile checks one workflow file.
func CheckFile(name string, src []byte) ([]Finding, error) {
	var doc yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(src)).Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil
	}
	root := doc.Content[0]
	wf := workflow{perms: get(root, "permissions"), env: get(root, "env")}
	wf.triggers = triggers(get(root, "on"))
	var outside []string
	for _, t := range wf.triggers {
		if outsiderTriggers[t] {
			outside = append(outside, t)
		}
	}
	if len(outside) == 0 {
		return nil, nil
	}
	jobs := get(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil, nil
	}
	var out []Finding
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		out = append(out, checkJob(name, jobs.Content[i].Value, jobs.Content[i+1], wf, outside)...)
	}
	return out, nil
}

func checkJob(file, jobID string, job *yaml.Node, wf workflow, outside []string) []Finding {
	steps := get(job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return nil
	}
	perms := get(job, "permissions")
	if perms == nil {
		perms = wf.perms
	}
	writes := writePerms(perms)
	jobGated := actorGate.MatchString(scalar(get(job, "if")))

	// env vars that carry outsider text, so "$ISSUE_BODY" in a prompt counts
	tainted := map[string]bool{}
	taintEnv(wf.env, tainted)
	taintEnv(get(job, "env"), tainted)

	var out []Finding
	for i, step := range steps.Content {
		if step.Kind != yaml.MappingNode {
			continue
		}
		uses := scalar(get(step, "uses"))
		run := get(step, "run")
		isAction := false
		for _, a := range agentActions {
			if uses == a || strings.HasPrefix(uses, a+"@") {
				isAction = true
			}
		}
		isCLI := run != nil && agentCLI.MatchString(run.Value)
		if !isAction && !isCLI {
			continue
		}
		stepName := scalar(get(step, "name"))
		if stepName == "" {
			stepName = uses
		}
		if stepName == "" {
			stepName = fmt.Sprintf("step %d", i+1)
		}
		f := Finding{File: file, Line: step.Line, Job: jobID, Step: stepName}
		add := func(rule string, sev rules.Severity, line int, detail string) {
			g := f
			g.Rule, g.Title, g.Severity, g.Detail = rule, Catalog[rule].Title, sev, detail
			if line > 0 {
				g.Line = line
			}
			out = append(out, g)
		}

		stepTainted := map[string]bool{}
		for k := range tainted {
			stepTainted[k] = true
		}
		taintEnv(get(step, "env"), stepTainted)

		// What the agent gets to read: the step inputs and the script.
		with := get(step, "with")
		promptHit, promptLine := "", 0
		for _, n := range scalars(with, run) {
			if hit := outsiderExpr(n.Value); hit != "" {
				promptHit, promptLine = hit, lineOf(n, hit)
				break
			}
			if v := usesTainted(n.Value, stepTainted); v != "" {
				promptHit, promptLine = v, lineOf(n, v[1:])
				break
			}
		}

		openBy, openLine := "", 0
		if isAction {
			for _, k := range openInputs {
				if v := get(with, k); v != nil && strings.TrimSpace(v.Value) == "*" {
					openBy, openLine = k+` is "*"`, v.Line
				}
			}
		} else if !jobGated && !actorGate.MatchString(scalar(get(step, "if"))) {
			openBy, openLine = "nothing checks who started the run", step.Line
		}

		var extra []string
		for _, n := range scalars(with, get(step, "env"), get(job, "env"), wf.env, run) {
			for _, m := range secretRef.FindAllStringSubmatch(n.Value, -1) {
				if m[1] == "" {
					extra = appendNew(extra, "all secrets")
				} else if !agentSecrets.MatchString(m[1]) {
					extra = appendNew(extra, m[1])
				}
			}
		}

		sandbox := ""
		for _, n := range scalars(with, run) {
			if m := sandboxOff.FindString(n.Value); m != "" {
				sandbox = m
				break
			}
		}
		if v := get(with, "sandbox"); sandbox == "" && v != nil && (v.Value == "workspace-write" || v.Value == "danger-full-access") {
			sandbox = "sandbox: " + v.Value
		}

		trig := strings.Join(outside, ", ")
		reach := promptHit != "" || openBy != ""
		if promptHit != "" {
			sev := rules.High
			detail := fmt.Sprintf("%s ends up in what the agent reads on %s, so whoever writes it can give the agent instructions", promptHit, trig)
			if openBy != "" {
				sev = rules.Critical
				detail += ", and " + openBy
			}
			add(RulePrompt, sev, promptLine, detail)
		}
		if openBy != "" {
			add(RuleOpen, rules.High, openLine, fmt.Sprintf("on %s, %s", trig, openBy))
		}
		if reach && (len(writes) > 0 || len(extra) > 0) {
			sev := rules.High
			if promptHit != "" && openBy != "" {
				sev = rules.Critical
			}
			var parts []string
			if len(writes) > 0 {
				parts = append(parts, "permissions "+strings.Join(writes, ", "))
			}
			if len(extra) > 0 {
				parts = append(parts, "secrets "+strings.Join(extra, ", "))
			}
			add(RuleWrite, sev, 0, "the job has "+strings.Join(parts, " and ")+", which a steered agent can use")
		}
		if reach && sandbox != "" {
			add(RuleSandbox, rules.High, 0, sandbox+" lets a steered agent run anything without asking")
		}
		if !reach {
			add(RuleTrigger, rules.Low, 0, fmt.Sprintf("runs on %s; the action only answers people with write access, keep it that way", trig))
		}
	}
	return out
}

func outsiderExpr(s string) string {
	for _, m := range expr.FindAllStringSubmatch(s, -1) {
		if hit := outsiderText.FindString(m[1]); hit != "" {
			return hit
		}
	}
	return ""
}

func taintEnv(env *yaml.Node, into map[string]bool) {
	if env == nil || env.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(env.Content); i += 2 {
		k, v := env.Content[i].Value, env.Content[i+1]
		if outsiderExpr(v.Value) != "" || usesTainted(v.Value, into) != "" {
			into[k] = true
		}
	}
}

// usesTainted reports an env var with outsider text that s refers to.
func usesTainted(s string, tainted map[string]bool) string {
	keys := make([]string, 0, len(tainted))
	for k := range tainted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		q := regexp.QuoteMeta(k)
		if regexp.MustCompile(`(env\.|\$\{?)` + q + `\b`).MatchString(s) {
			return "$" + k
		}
	}
	return ""
}

// lineOf is the line of the first match of sub in a scalar, counting into
// "|" blocks so the finding points at the right line of a long prompt.
func lineOf(n *yaml.Node, sub string) int {
	i := strings.Index(n.Value, sub)
	if n.Style != yaml.LiteralStyle || i < 0 {
		return n.Line
	}
	return n.Line + 1 + strings.Count(n.Value[:i], "\n")
}

func triggers(on *yaml.Node) []string {
	if on == nil {
		return nil
	}
	var out []string
	switch on.Kind {
	case yaml.ScalarNode:
		out = append(out, on.Value)
	case yaml.SequenceNode:
		for _, n := range on.Content {
			out = append(out, n.Value)
		}
	case yaml.MappingNode:
		for i := 0; i < len(on.Content); i += 2 {
			out = append(out, on.Content[i].Value)
		}
	}
	return out
}

func writePerms(p *yaml.Node) []string {
	if p == nil {
		return nil
	}
	if p.Kind == yaml.ScalarNode {
		if p.Value == "write-all" {
			return []string{"write-all"}
		}
		return nil
	}
	var out []string
	for _, s := range writeScopes {
		if v := get(p, s); v != nil && v.Value == "write" {
			out = append(out, s+": write")
		}
	}
	return out
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

// scalars returns every scalar value under the given nodes, keys excluded.
func scalars(nodes ...*yaml.Node) []*yaml.Node {
	var out []*yaml.Node
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		switch n.Kind {
		case yaml.ScalarNode:
			out = append(out, n)
		case yaml.MappingNode:
			for i := 1; i < len(n.Content); i += 2 {
				walk(n.Content[i])
			}
		case yaml.SequenceNode, yaml.DocumentNode:
			for _, c := range n.Content {
				walk(c)
			}
		case yaml.AliasNode:
			walk(n.Alias)
		}
	}
	for _, n := range nodes {
		walk(n)
	}
	return out
}

func appendNew(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}
