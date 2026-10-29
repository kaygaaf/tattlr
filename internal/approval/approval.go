// Package approval lets a hook ask a running "tattlr ui" whether a call
// may go ahead. It is for agents that have no ask prompt of their own.
//
// tattlr ui writes ui.json (0600) in the state folder with its port and a
// random per-run token. The token never goes over the wire: the hook signs
// a fresh nonce with it, and the UI signs its answer the same way, so a
// stray process that grabs the port can neither read the token nor fake
// an approval.
package approval

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/kaygaaf/tattlr/internal/config"
)

// Info is what tattlr ui leaves in ui.json while it runs.
type Info struct {
	Port    int       `json:"port"`
	Token   string    `json:"token"`
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
}

// Request is one call waiting for a human. Every field is already
// redacted by the hook.
type Request struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Agent    string    `json:"agent"`
	Tool     string    `json:"tool,omitempty"`
	Kind     string    `json:"kind,omitempty"`
	Cwd      string    `json:"cwd,omitempty"`
	Session  string    `json:"session,omitempty"`
	Evidence string    `json:"evidence,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Severity string    `json:"severity,omitempty"`
	Rules    []string  `json:"rules,omitempty"`
	// TimeoutMS is how long the hook will wait.
	TimeoutMS int64 `json:"timeout_ms"`
}

// The answers a UI can give.
const (
	Approve = "approve"
	Deny    = "deny"
	Timeout = "timeout"
)

// Answer is the UI's reply.
type Answer struct {
	Decision string `json:"decision"`
	Proof    string `json:"proof"`
}

// Headers on the hook's request.
const (
	NonceHeader = "X-Tattlr-Nonce"
	AuthHeader  = "X-Tattlr-Auth"
)

// AskPath is the UI endpoint hooks call.
const AskPath = "/api/hook/ask"

// ErrNotRunning means there is no UI to ask.
var ErrNotRunning = errors.New("tattlr ui is not running")

// InfoPath is where tattlr ui says where it is.
func InfoPath(home string) string { return filepath.Join(config.StateDir(home), "ui.json") }

// WriteInfo saves ui.json, readable by the user only.
func WriteInfo(home string, in Info) error {
	p := InfoPath(home)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(in)
	tmp := p + ".tmp" + strconv.Itoa(os.Getpid())
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// RemoveInfo deletes ui.json if it still belongs to this run.
func RemoveInfo(home, token string) {
	if in, err := ReadInfo(home); err == nil && in.Token == token {
		os.Remove(InfoPath(home))
	}
}

// ReadInfo loads ui.json. It refuses a file other users can write or read,
// since the token in it is what approvals hang on.
func ReadInfo(home string) (Info, error) {
	p := InfoPath(home)
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return Info{}, ErrNotRunning
	}
	if err != nil {
		return Info{}, err
	}
	if !fi.Mode().IsRegular() {
		return Info{}, fmt.Errorf("%s is not a regular file", p)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return Info{}, fmt.Errorf("%s is readable by other users; not trusting it", p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return Info{}, err
	}
	var in Info
	if err := json.Unmarshal(b, &in); err != nil {
		return Info{}, fmt.Errorf("%s: %w", p, err)
	}
	if in.Port <= 0 || in.Port > 65535 || len(in.Token) < 32 {
		return Info{}, fmt.Errorf("%s looks broken", p)
	}
	return in, nil
}

// NewToken returns 32 random bytes as hex.
func NewToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Sign is the HMAC both sides use. who is "hook" or "ui".
func Sign(token, who, nonce, extra string) string {
	m := hmac.New(sha256.New, []byte(token))
	_, _ = io.WriteString(m, who+"\n"+nonce+"\n"+extra)
	return hex.EncodeToString(m.Sum(nil))
}

// Verify compares a signature in constant time.
func Verify(token, who, nonce, extra, sig string) bool {
	return hmac.Equal([]byte(Sign(token, who, nonce, extra)), []byte(sig))
}

// Ask sends req to the running UI and waits up to timeout for a click. It
// returns ErrNotRunning quickly when there is no UI.
func Ask(home string, req Request, timeout time.Duration) (string, error) {
	in, err := ReadInfo(home)
	if err != nil {
		return "", err
	}
	return AskAt(in, req, timeout)
}

// AskAt is Ask against a known UI.
func AskAt(in Info, req Request, timeout time.Duration) (string, error) {
	req.TimeoutMS = timeout.Milliseconds()
	body, _ := json.Marshal(req)
	nonce := NewToken()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(in.Port))
	// Find out fast if nobody is listening, before waiting on a human.
	conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return "", ErrNotRunning
	}
	conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+addr+AskPath, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	hr.Host = addr
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set(NonceHeader, nonce)
	hr.Header.Set(AuthHeader, Sign(in.Token, "hook", nonce, string(body)))
	cl := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := cl.Do(hr)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tattlr ui said %s", resp.Status)
	}
	var a Answer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&a); err != nil {
		return "", err
	}
	if !Verify(in.Token, "ui", nonce, a.Decision, a.Proof) {
		return "", errors.New("tattlr ui answer is not signed with this run's token")
	}
	switch a.Decision {
	case Approve, Deny, Timeout:
		return a.Decision, nil
	}
	return "", fmt.Errorf("unknown answer %q", a.Decision)
}
