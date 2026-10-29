// Package redact masks secret values before anything is printed or saved.
package redact

import (
	"regexp"
	"strings"
)

type rule struct {
	re   *regexp.Regexp
	repl string
}

var rules = []rule{
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)`), "[REDACTED PRIVATE KEY]"},
	{regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), "${1}****************"},
	{regexp.MustCompile(`\b(gh[pousr]_)[A-Za-z0-9]{20,}`), "${1}[REDACTED]"},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`), "github_pat_[REDACTED]"},
	{regexp.MustCompile(`\b(sk-(?:ant-|proj-)?)[A-Za-z0-9_\-]{16,}`), "${1}[REDACTED]"},
	{regexp.MustCompile(`\b((?:sk|rk)_(?:live|test)_)[A-Za-z0-9]{10,}`), "${1}[REDACTED]"}, // Stripe
	{regexp.MustCompile(`\b(glpat-)[A-Za-z0-9_\-]{16,}`), "${1}[REDACTED]"},
	{regexp.MustCompile(`\b(npm_)[A-Za-z0-9]{30,}`), "${1}[REDACTED]"},
	{regexp.MustCompile(`\b(hf_)[A-Za-z0-9]{30,}`), "${1}[REDACTED]"},
	{regexp.MustCompile(`\b(xox[abposr]-)[A-Za-z0-9\-]{10,}`), "${1}[REDACTED]"},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{30,}`), "AIza[REDACTED]"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`), "[REDACTED JWT]"},
	{regexp.MustCompile(`(?i)\b(bearer|token|basic)\s+[A-Za-z0-9._~+/\-]{16,}=*`), "$1 [REDACTED]"},
	{regexp.MustCompile(`(https?://)[^/\s:@]+:[^/\s@]+@`), "${1}[REDACTED]@"},
	// KEY=value and KEY: value where the key name looks sensitive.
	{regexp.MustCompile(`(?i)\b([A-Z0-9_\-]*(?:secret|token|passw(?:or)?d|pwd|api[_\-]?key|access[_\-]?key|private[_\-]?key|credential|auth)[A-Z0-9_\-]*)(["']?\s*[:=]\s*["']?)([^\s"'&;|]{4,})`), "$1$2[REDACTED]"},
	// SOMETHING_KEY=value in shell style (upper case only, so "monkey=" is safe).
	{regexp.MustCompile(`\b([A-Z][A-Z0-9]*_KEY)(["']?\s*[:=]\s*["']?)([^\s"'&;|]{4,})`), "$1$2[REDACTED]"},
}

// String masks secret-looking values in s.
func String(s string) string {
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	return s
}

// Line redacts s, collapses whitespace and cuts it to max runes.
func Line(s string, max int) string {
	s = String(s)
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if max > 0 && len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}
