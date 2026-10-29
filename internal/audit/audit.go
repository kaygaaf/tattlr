// Package audit keeps the local JSONL log of every hook decision.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Entry is one hook decision. Evidence is always redacted before it gets
// here; the raw command or file content is never written.
type Entry struct {
	Time      time.Time `json:"time"`
	Agent     string    `json:"agent"`
	HookEvent string    `json:"hook_event,omitempty"`
	Session   string    `json:"session,omitempty"`
	Cwd       string    `json:"cwd,omitempty"`
	Tool      string    `json:"tool,omitempty"`
	Kind      string    `json:"kind,omitempty"`
	Evidence  string    `json:"evidence,omitempty"`
	Decision  string    `json:"decision"`
	Would     string    `json:"would,omitempty"`
	Mode      string    `json:"mode"`
	Rules     []string  `json:"rules,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Tainted   bool      `json:"tainted,omitempty"` // this call touched a canary
	// Approval is set when the ask went to tattlr ui: approved, denied or
	// timed out.
	Approval string `json:"approval,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Append writes one entry. The file is private to the user (0600) and is
// opened in append mode so concurrent hooks don't clobber each other.
func Append(path string, e Entry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	// One write call per line keeps lines whole under O_APPEND.
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Read returns every entry in the log, oldest first. Broken lines are
// skipped. A missing log is not an error.
func Read(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return decode(f), nil
}

// Tail returns the entries in roughly the last n bytes of the log. Hooks
// use it to see what a session did recently without reading a big file.
func Tail(path string, n int64) ([]Entry, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > n {
		if _, err := f.Seek(fi.Size()-n, io.SeekStart); err != nil {
			return nil, err
		}
		r := bufio.NewReader(f)
		if _, err := r.ReadString('\n'); err != nil { // drop the partial line
			return nil, nil
		}
		return decode(r), nil
	}
	return decode(f), nil
}

func decode(r io.Reader) []Entry {
	var out []Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil && !e.Time.IsZero() {
			out = append(out, e)
		}
	}
	return out
}

// Tainted reports whether this agent session touched a canary earlier.
func Tainted(entries []Entry, agent, session string) bool {
	if session == "" {
		return false
	}
	for _, e := range entries {
		if e.Tainted && e.Agent == agent && e.Session == session {
			return true
		}
	}
	return false
}
