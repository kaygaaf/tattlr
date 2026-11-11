package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/kaygaaf/tattlr/internal/rules"
	"github.com/kaygaaf/tattlr/internal/scan"
)

// SARIFOptions controls the SARIF output.
type SARIFOptions struct {
	// Version goes into tool.driver.version.
	Version string
	// SrcRoot is the checkout the findings are reported against, usually
	// the current directory. Files an agent touched inside it get a path
	// relative to it, so code scanning can link to them.
	SrcRoot string
}

// SARIF 2.1.0, only the parts tattlr fills in.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool                   `json:"tool"`
	OriginalURIBaseIDs map[string]sarifArtifactLoc `json:"originalUriBaseIds,omitempty"`
	Results            []sarifResult               `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	HelpURI              string         `json:"helpUri"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
}

type sarifArtifactLoc struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.Critical, rules.High:
		return "error"
	case rules.Medium:
		return "warning"
	}
	return "note"
}

// securitySeverity is the 0-10 score GitHub code scanning uses to label
// alerts critical, high, medium or low.
func securitySeverity(s rules.Severity) string {
	switch s {
	case rules.Critical:
		return "9.5"
	case rules.High:
		return "8.0"
	case rules.Medium:
		return "5.5"
	}
	return "3.0"
}

const rulesURL = "https://github.com/kaygaaf/tattlr#what-it-detects"

// SARIF writes the findings as a SARIF 2.1.0 log, the format GitHub code
// scanning and most security dashboards read.
func SARIF(w io.Writer, r *scan.Result, o SARIFOptions) error {
	ids := make([]string, 0, len(rules.Catalog))
	for id := range rules.Catalog {
		ids = append(ids, id)
	}
	for _, f := range r.Findings {
		if _, ok := rules.Catalog[f.Rule]; !ok && !slices.Contains(ids, f.Rule) {
			ids = append(ids, f.Rule)
		}
	}
	sort.Strings(ids)
	index := map[string]int{}
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name: "tattlr", Version: o.Version, InformationURI: "https://github.com/kaygaaf/tattlr",
		}},
		Results: []sarifResult{},
	}
	for i, id := range ids {
		index[id] = i
		info, ok := rules.Catalog[id]
		if !ok {
			info = rules.Info{ID: id, Title: findingTitle(r, id), Category: "other", Severity: rules.High}
		}
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID: id, Name: ruleName(id), ShortDescription: sarifText{info.Title}, HelpURI: rulesURL,
			DefaultConfiguration: sarifConfig{sarifLevel(info.Severity)},
			Properties: map[string]any{
				"tags":              []string{"security", "ai-agent", info.Category},
				"security-severity": securitySeverity(info.Severity),
				"precision":         "high",
			},
		})
	}

	root := o.SrcRoot
	if root != "" {
		root = filepath.Clean(root)
		run.OriginalURIBaseIDs = map[string]sarifArtifactLoc{"SRCROOT": {URI: fileURI(root) + "/"}}
	}
	for _, f := range r.Findings {
		e := f.Event
		msg := f.Title
		if f.Detail != "" {
			msg += " (" + f.Detail + ")"
		}
		msg += fmt.Sprintf(". %s ran: %s", e.Agent, tilde(f.Evidence, r.HomeDir()))
		if e.Project != "" {
			msg += fmt.Sprintf(" in %s", tilde(e.Project, r.HomeDir()))
		}
		if !e.Time.IsZero() {
			msg += " at " + e.Time.UTC().Format("2006-01-02 15:04 UTC")
		}
		sum := sha256.Sum256([]byte(strings.Join([]string{f.Rule, e.Agent, e.SessionID, e.Time.UTC().String(), f.Evidence}, "\x00")))
		props := map[string]any{"agent": e.Agent, "tool": e.Tool, "category": f.Category, "severity": f.Severity.String()}
		if e.SessionID != "" {
			props["session"] = e.SessionID
		}
		run.Results = append(run.Results, sarifResult{
			RuleID: f.Rule, RuleIndex: index[f.Rule], Level: sarifLevel(f.Severity),
			Message:             sarifText{msg},
			Locations:           []sarifLocation{{sarifPhysical{location(e.Path, e.Source, root)}}},
			PartialFingerprints: map[string]string{"tattlrFinding/v1": hex.EncodeToString(sum[:16])},
			Properties:          props,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}

// location points at the file the agent touched when it is inside the
// checkout, and at the agent's session log otherwise.
func location(path, source, root string) sarifArtifactLoc {
	if root != "" {
		for _, p := range splitList(path) {
			if !filepath.IsAbs(p) {
				continue
			}
			rel, err := filepath.Rel(root, filepath.Clean(p))
			if err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
				return sarifArtifactLoc{URI: filepath.ToSlash(rel), URIBaseID: "SRCROOT"}
			}
		}
	}
	if source != "" {
		if abs, err := filepath.Abs(source); err == nil {
			source = abs
		}
		return sarifArtifactLoc{URI: fileURI(source)}
	}
	return sarifArtifactLoc{URI: "tattlr-unknown-log"}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "\n") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fileURI(p string) string {
	p = filepath.ToSlash(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // C:/x on Windows
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

// ruleName turns "git-force-push" into "GitForcePush", the style SARIF
// viewers expect for rule names.
func ruleName(id string) string {
	var b strings.Builder
	for _, part := range strings.FieldsFunc(id, func(r rune) bool { return r == '-' || r == '_' }) {
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

func findingTitle(r *scan.Result, id string) string {
	for _, f := range r.Findings {
		if f.Rule == id && f.Title != "" {
			return f.Title
		}
	}
	return id
}
