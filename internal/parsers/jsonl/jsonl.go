// Package jsonl has small helpers shared by the log parsers.
package jsonl

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MaxOutput caps how much tool output is kept per event.
const MaxOutput = 64 * 1024

// EachLine calls fn for every non-empty line of a JSONL file. Lines that are
// not valid JSON objects are skipped, since logs get truncated mid-write.
func EachLine(path string, fn func(m map[string]any)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return EachLineReader(f, fn)
}

// EachLineReader is EachLine for an io.Reader.
func EachLineReader(r io.Reader, fn func(m map[string]any)) error {
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			var m map[string]any
			if json.Unmarshal(line, &m) == nil && m != nil {
				fn(m)
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Str returns m[key] as a string, or "".
func Str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// FirstStr returns the first non-empty string value among keys.
func FirstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := Str(m, k); s != "" {
			return s
		}
	}
	return ""
}

// Obj returns m[key] as an object, or nil.
func Obj(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	o, _ := m[key].(map[string]any)
	return o
}

// Arr returns m[key] as an array, or nil.
func Arr(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	a, _ := m[key].([]any)
	return a
}

// Bool returns m[key] as a bool.
func Bool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

// Time parses an ISO timestamp, or epoch millis given as a number.
func Time(v any) time.Time {
	switch t := v.(type) {
	case string:
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000Z07:00", "2006-01-02T15:04:05"} {
			if ts, err := time.Parse(layout, t); err == nil {
				return ts
			}
		}
	case float64:
		if t > 1e12 {
			return time.UnixMilli(int64(t))
		}
		if t > 1e9 {
			return time.Unix(int64(t), 0)
		}
	}
	return time.Time{}
}

// Compact renders a value as compact JSON, for args summaries.
func Compact(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// Truncate cuts s to at most n bytes.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ContentText flattens tool result content: a string, or a list of
// {type:"text", text:...} blocks, or anything else as JSON.
func ContentText(v any) string {
	switch c := v.(type) {
	case nil:
		return ""
	case string:
		return Truncate(c, MaxOutput)
	case []any:
		var sb strings.Builder
		for _, item := range c {
			if m, ok := item.(map[string]any); ok {
				if t := Str(m, "text"); t != "" {
					sb.WriteString(t)
					sb.WriteByte('\n')
					continue
				}
			}
			sb.WriteString(Compact(item))
			sb.WriteByte('\n')
		}
		return Truncate(sb.String(), MaxOutput)
	default:
		return Truncate(Compact(v), MaxOutput)
	}
}

// Walk returns every file under root accepted by keep. Missing roots are fine.
func Walk(root string, keep func(path string) bool) []string {
	var out []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() && keep(p) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// ModTime returns a file's mtime, or zero.
func ModTime(path string) time.Time {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

// ShellScript turns an argv like ["bash","-lc","ls"] into "ls", and any
// other argv into a space-joined string.
func ShellScript(argv []any) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		if s, ok := a.(string); ok {
			parts = append(parts, s)
		}
	}
	if len(parts) >= 3 {
		base := filepath.Base(parts[0])
		switch base {
		case "bash", "sh", "zsh", "dash", "fish":
			if strings.HasPrefix(parts[1], "-") && strings.Contains(parts[1], "c") {
				return strings.Join(parts[2:], " ")
			}
		}
	}
	return strings.Join(parts, " ")
}
