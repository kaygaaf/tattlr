package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kaygaaf/tattlr/internal/rules"
	"github.com/kaygaaf/tattlr/internal/workflows"
)

const workflowsURL = "https://github.com/kaygaaf/tattlr#check-your-github-workflows"

// WorkflowsJSON writes the workflow findings as JSON.
func WorkflowsJSON(w io.Writer, r *workflows.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func counts(r *workflows.Result) string {
	by := map[rules.Severity]int{}
	for _, f := range r.Findings {
		by[f.Severity]++
	}
	var parts []string
	for _, s := range []rules.Severity{rules.Critical, rules.High, rules.Medium, rules.Low} {
		if by[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", by[s], s))
		}
	}
	return strings.Join(parts, ", ")
}

func where(f workflows.Finding) string {
	s := fmt.Sprintf("job %s", f.Job)
	if f.Step != "" {
		s += fmt.Sprintf(", step %q", f.Step)
	}
	return s
}

// WorkflowsText writes the workflow findings for a terminal.
func WorkflowsText(w io.Writer, r *workflows.Result, color bool) {
	p := painter{color}
	dim := func(s string) string { return p.c("2", s) }
	fmt.Fprintln(w)
	fmt.Fprintf(w, " %s  %s  %s\n", p.c("1;38;5;231;48;5;160", " TATTLR "), p.c("1", "WORKFLOWS"), dim(plural(len(r.Files), "file")+" checked"))
	fmt.Fprintln(w)
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, " No agent steps that outsiders can steer. Nice.")
		fmt.Fprintln(w)
		return
	}
	for _, f := range r.Findings {
		fmt.Fprintf(w, " %s %s  %s\n", p.sev(f.Severity, sevLabel[f.Severity]), p.c("1", fmt.Sprintf("%s:%d", f.File, f.Line)), dim(where(f)))
		fmt.Fprintf(w, "      %s\n", f.Title)
		fmt.Fprintf(w, "      %s\n", dim(f.Detail))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, " %s. %s\n", counts(r), dim("More: "+workflowsURL))
	fmt.Fprintln(w)
}

// WorkflowsMarkdown writes the workflow findings for a job summary or PR
// comment.
func WorkflowsMarkdown(w io.Writer, r *workflows.Result) {
	fmt.Fprintln(w, "## tattlr workflows")
	fmt.Fprintln(w)
	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "Checked %s. No agent steps that outsiders can steer.\n", plural(len(r.Files), "workflow file"))
		return
	}
	fmt.Fprintf(w, "Checked %s: %s.\n\n", plural(len(r.Files), "workflow file"), counts(r))
	fmt.Fprintln(w, "| | Where | Job / step | What |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "| %s %s | `%s:%d` | %s | **%s.** %s |\n", sevEmoji[f.Severity.String()], f.Severity,
			mdCode(filepath.ToSlash(f.File)), f.Line, mdText(where(f)), mdText(f.Title), mdText(f.Detail))
	}
}

// WorkflowsSARIF writes the workflow findings as SARIF 2.1.0 so they show
// up in code scanning next to the workflow line.
func WorkflowsSARIF(w io.Writer, r *workflows.Result, o SARIFOptions) error {
	ids := make([]string, 0, len(workflows.Catalog))
	for id := range workflows.Catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	index := map[string]int{}
	run := sarifRun{
		Tool:    sarifTool{Driver: sarifDriver{Name: "tattlr", Version: o.Version, InformationURI: "https://github.com/kaygaaf/tattlr"}},
		Results: []sarifResult{},
	}
	for i, id := range ids {
		index[id] = i
		info := workflows.Catalog[id]
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID: id, Name: ruleName(id), ShortDescription: sarifText{info.Title}, HelpURI: workflowsURL,
			DefaultConfiguration: sarifConfig{sarifLevel(info.Severity)},
			Properties: map[string]any{
				"tags":              []string{"security", "ai-agent", "github-actions"},
				"security-severity": securitySeverity(info.Severity),
				"precision":         "medium",
			},
		})
	}
	root := o.SrcRoot
	if root != "" {
		root = filepath.Clean(root)
		run.OriginalURIBaseIDs = map[string]sarifArtifactLoc{"SRCROOT": {URI: fileURI(root) + "/"}}
	}
	for _, f := range r.Findings {
		loc := workflowLoc(f.File, root)
		sum := sha256.Sum256([]byte(strings.Join([]string{f.Rule, loc.URI, f.Job, f.Step}, "\x00")))
		run.Results = append(run.Results, sarifResult{
			RuleID: f.Rule, RuleIndex: index[f.Rule], Level: sarifLevel(f.Severity),
			Message:             sarifText{fmt.Sprintf("%s: %s (%s)", f.Title, f.Detail, where(f))},
			Locations:           []sarifLocation{{sarifPhysical{ArtifactLocation: loc, Region: &sarifRegion{StartLine: f.Line}}}},
			PartialFingerprints: map[string]string{"tattlrWorkflow/v1": hex.EncodeToString(sum[:16])},
			Properties:          map[string]any{"job": f.Job, "step": f.Step, "severity": f.Severity.String()},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0", Runs: []sarifRun{run}})
}

func workflowLoc(file, root string) sarifArtifactLoc {
	abs, err := filepath.Abs(file)
	if err != nil {
		abs = file
	}
	if root != "" {
		if rel, err := filepath.Rel(root, abs); err == nil && !strings.HasPrefix(rel, "..") {
			return sarifArtifactLoc{URI: filepath.ToSlash(rel), URIBaseID: "SRCROOT"}
		}
	}
	return sarifArtifactLoc{URI: fileURI(abs)}
}
