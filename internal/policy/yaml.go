package policy

import (
	"fmt"
	"strings"
)

// A tiny YAML reader for the policy file. It understands nested maps,
// "- item" lists of scalars, inline [a, b] lists, quotes and # comments.
// That is all a policy needs, and it keeps tattlr free of dependencies.

type yline struct {
	n      int
	indent int
	text   string
}

func parseYAML(src string) (map[string]any, error) {
	var lines []yline
	for i, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		if strings.Contains(raw, "\t") && strings.TrimLeft(raw, " \t") != "" && strings.HasPrefix(strings.TrimLeft(raw, " "), "\t") {
			return nil, fmt.Errorf("line %d: use spaces, not tabs, to indent", i+1)
		}
		t := stripComment(raw)
		if strings.TrimSpace(t) == "" || strings.TrimSpace(t) == "---" {
			continue
		}
		ind := len(t) - len(strings.TrimLeft(t, " "))
		lines = append(lines, yline{i + 1, ind, strings.TrimSpace(t)})
	}
	p := &yparser{lines: lines}
	if len(lines) == 0 {
		return map[string]any{}, nil
	}
	m, err := p.mapAt(lines[0].indent)
	if err != nil {
		return nil, err
	}
	if p.i < len(p.lines) {
		return nil, fmt.Errorf("line %d: unexpected indentation", p.lines[p.i].n)
	}
	return m, nil
}

func stripComment(s string) string {
	q := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '\'' || c == '"':
			q = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

type yparser struct {
	lines []yline
	i     int
}

func (p *yparser) mapAt(indent int) (map[string]any, error) {
	out := map[string]any{}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent < indent {
			break
		}
		if l.indent > indent {
			return nil, fmt.Errorf("line %d: unexpected indentation", l.n)
		}
		if strings.HasPrefix(l.text, "- ") || l.text == "-" {
			return nil, fmt.Errorf("line %d: list item where a key was expected", l.n)
		}
		k, v, ok := splitKey(l.text)
		if !ok {
			return nil, fmt.Errorf("line %d: expected \"key: value\"", l.n)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("line %d: %q is set twice", l.n, k)
		}
		p.i++
		if v != "" {
			sv, err := scalarOrInline(v, l.n)
			if err != nil {
				return nil, err
			}
			out[k] = sv
			continue
		}
		// Nested block, or nothing.
		if p.i >= len(p.lines) || p.lines[p.i].indent <= indent && !strings.HasPrefix(p.lines[p.i].text, "-") {
			out[k] = nil
			continue
		}
		next := p.lines[p.i]
		if strings.HasPrefix(next.text, "- ") || next.text == "-" {
			if next.indent < indent {
				out[k] = nil
				continue
			}
			lst, err := p.listAt(next.indent)
			if err != nil {
				return nil, err
			}
			out[k] = lst
			continue
		}
		sub, err := p.mapAt(next.indent)
		if err != nil {
			return nil, err
		}
		out[k] = sub
	}
	return out, nil
}

func (p *yparser) listAt(indent int) ([]any, error) {
	var out []any
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent != indent || !(strings.HasPrefix(l.text, "- ") || l.text == "-") {
			if l.indent > indent {
				return nil, fmt.Errorf("line %d: lists can only hold plain values", l.n)
			}
			break
		}
		v := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
		sv, err := scalar(v, l.n)
		if err != nil {
			return nil, err
		}
		out = append(out, sv)
		p.i++
	}
	return out, nil
}

func splitKey(t string) (string, string, bool) {
	q := byte(0)
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '\'' || c == '"':
			q = c
		case c == ':' && (i+1 == len(t) || t[i+1] == ' '):
			k := strings.TrimSpace(t[:i])
			k = unquote(k)
			if k == "" {
				return "", "", false
			}
			return k, strings.TrimSpace(t[i+1:]), true
		}
	}
	return "", "", false
}

func scalarOrInline(v string, n int) (any, error) {
	if strings.HasPrefix(v, "[") {
		if !strings.HasSuffix(v, "]") {
			return nil, fmt.Errorf("line %d: inline list must end with ]", n)
		}
		inner := strings.TrimSpace(v[1 : len(v)-1])
		out := []any{}
		if inner == "" {
			return out, nil
		}
		for _, part := range splitComma(inner) {
			s, err := scalar(strings.TrimSpace(part), n)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	}
	if v == "{}" {
		return map[string]any{}, nil
	}
	return scalar(v, n)
}

func splitComma(s string) []string {
	var out []string
	q := byte(0)
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '\'' || c == '"':
			q = c
		case c == ',':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func scalar(v string, n int) (any, error) {
	if v == "" || v == "~" || v == "null" {
		return nil, nil
	}
	if (strings.HasPrefix(v, `"`) || strings.HasPrefix(v, "'")) && (len(v) < 2 || v[len(v)-1] != v[0]) {
		return nil, fmt.Errorf("line %d: unclosed quote", n)
	}
	if strings.HasPrefix(v, "{") || strings.HasPrefix(v, "&") || strings.HasPrefix(v, "*") || strings.HasPrefix(v, "|") || strings.HasPrefix(v, ">") {
		return nil, fmt.Errorf("line %d: %q is fancier YAML than tattlr reads; use plain values", n, v)
	}
	return unquote(v), nil
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"') {
		r := strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\n`, "\n", `\t`, "\t")
		return r.Replace(v[1 : len(v)-1])
	}
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return strings.ReplaceAll(v[1:len(v)-1], "''", "'")
	}
	return v
}
