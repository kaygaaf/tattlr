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

	"github.com/kaygaaf/tattlr/internal/repo"
	"github.com/kaygaaf/tattlr/internal/rules"
)

const repoURL = "https://github.com/kaygaaf/tattlr#check-a-checkout-before-you-trust-it"

// RepoJSON writes the checkout findings as JSON.
func RepoJSON(w io.Writer, r *repo.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func repoCounts(r *repo.Result) string {
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

// RepoText writes the checkout findings for a terminal.
func RepoText(w io.Writer, r *repo.Result, color bool) {
	p := painter{color}
	dim := func(s string) string { return p.c("2", s) }
	fmt.Fprintln(w)
	fmt.Fprintf(w, " %s  %s  %s\n", p.c("1;38;5;231;48;5;160", " TATTLR "), p.c("1", "REPO"), dim(plural(len(r.Files), "file")+" checked"))
	fmt.Fprintln(w)
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, " Nothing in this checkout asks an agent to run a hidden setup.")
		fmt.Fprintln(w)
		return
	}
	for _, f := range r.Findings {
		fmt.Fprintf(w, " %s %s\n", p.sev(f.Severity, sevLabel[f.Severity]), p.c("1", fmt.Sprintf("%s:%d", f.File, f.Line)))
		fmt.Fprintf(w, "      %s\n", f.Title)
		fmt.Fprintf(w, "      %s\n", dim(f.Detail))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, " %s. %s\n", repoCounts(r), dim("More: "+repoURL))
	fmt.Fprintln(w)
}

// RepoMarkdown writes the checkout findings for a job summary or PR comment.
func RepoMarkdown(w io.Writer, r *repo.Result) {
	fmt.Fprintln(w, "## tattlr repo")
	fmt.Fprintln(w)
	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "Checked %s. Nothing in this checkout asks an agent to run a hidden setup.\n", plural(len(r.Files), "file"))
		return
	}
	fmt.Fprintf(w, "Checked %s: %s. This only reads the checkout. It does not run anything in it.\n\n", plural(len(r.Files), "file"), repoCounts(r))
	fmt.Fprintln(w, "| | Where | What |")
	fmt.Fprintln(w, "|---|---|---|")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "| %s %s | `%s:%d` | **%s.** %s |\n", sevEmoji[f.Severity.String()], f.Severity,
			mdCode(filepath.ToSlash(f.File)), f.Line, mdText(f.Title), mdText(f.Detail))
	}
}

// RepoSARIF writes the checkout findings as SARIF 2.1.0 so they show up in
// code scanning next to the file.
func RepoSARIF(w io.Writer, r *repo.Result, o SARIFOptions) error {
	ids := make([]string, 0, len(repo.Catalog))
	for id := range repo.Catalog {
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
		info := repo.Catalog[id]
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID: id, Name: ruleName(id), ShortDescription: sarifText{info.Title}, HelpURI: repoURL,
			DefaultConfiguration: sarifConfig{sarifLevel(info.Severity)},
			Properties: map[string]any{
				"tags":              []string{"security", "ai-agent", "supply-chain"},
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
		sum := sha256.Sum256([]byte(strings.Join([]string{f.Rule, loc.URI, f.Detail}, "\x00")))
		run.Results = append(run.Results, sarifResult{
			RuleID: f.Rule, RuleIndex: index[f.Rule], Level: sarifLevel(f.Severity),
			Message:             sarifText{fmt.Sprintf("%s: %s", f.Title, f.Detail)},
			Locations:           []sarifLocation{{sarifPhysical{ArtifactLocation: loc, Region: &sarifRegion{StartLine: f.Line}}}},
			PartialFingerprints: map[string]string{"tattlrRepo/v1": hex.EncodeToString(sum[:16])},
			Properties:          map[string]any{"severity": f.Severity.String()},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0", Runs: []sarifRun{run}})
}
