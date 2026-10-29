package ui

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kaygaaf/tattlr/internal/approval"
	"github.com/kaygaaf/tattlr/internal/audit"
	"github.com/kaygaaf/tattlr/internal/config"
	"github.com/kaygaaf/tattlr/internal/hook"
	"github.com/kaygaaf/tattlr/internal/scan"
)

type rig struct {
	t      *testing.T
	home   string
	s      *Server
	base   string
	cookie *http.Cookie
	cl     *http.Client
}

func start(t *testing.T) *rig {
	t.Helper()
	home := t.TempDir()
	s := New(Options{Home: home, Poll: 20 * time.Millisecond,
		Scan: func() (*scan.Result, error) {
			return &scan.Result{Sessions: 3, ToolCalls: 40, Flagged: 2, Score: 35, Agents: []scan.AgentStats{{Agent: "codex", ToolCalls: 40}}}, nil
		}})
	ln, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	// Wait for ui.json.
	for i := 0; i < 100; i++ {
		if _, err := approval.ReadInfo(home); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cl := &http.Client{Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &rig{t: t, home: home, s: s, base: fmt.Sprintf("http://127.0.0.1:%d", s.port), cl: cl}
}

func (r *rig) do(method, path string, body string, hdr map[string]string) (*http.Response, string) {
	r.t.Helper()
	req, _ := http.NewRequest(method, r.base+path, strings.NewReader(body))
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	if r.cookie != nil {
		req.AddCookie(r.cookie)
	}
	resp, err := r.cl.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (r *rig) login() {
	r.t.Helper()
	resp, _ := r.do("GET", "/?token="+url.QueryEscape(r.s.login), "", nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		r.t.Fatalf("login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, c := range resp.Cookies() {
		if c.Name == r.s.cookieName() {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				r.t.Errorf("cookie flags: %+v", c)
			}
			r.cookie = c
		}
	}
	if r.cookie == nil {
		r.t.Fatal("no cookie")
	}
}

func (r *rig) post(path, body string) (*http.Response, string) {
	return r.do("POST", path, body, map[string]string{"Content-Type": "application/json", "X-CSRF-Token": r.s.csrf, "Origin": r.base})
}

func (r *rig) waitPending(n int) []pendingView {
	r.t.Helper()
	for i := 0; i < 200; i++ {
		if p := r.s.pendingList(); len(p) == n {
			return p
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.t.Fatalf("never got %d pending", n)
	return nil
}

func TestGateAndHeaders(t *testing.T) {
	r := start(t)
	if resp, body := r.do("GET", "/", "", nil); resp.StatusCode != 401 || !strings.Contains(body, "printed") {
		t.Errorf("no cookie: %d", resp.StatusCode)
	}
	if resp, _ := r.do("GET", "/?token=nope", "", nil); resp.StatusCode != 403 {
		t.Errorf("bad token: %d", resp.StatusCode)
	}
	if resp, _ := r.do("GET", "/api/state", "", nil); resp.StatusCode != 401 {
		t.Errorf("api without cookie: %d", resp.StatusCode)
	}
	r.login()
	resp, body := r.do("GET", "/", "", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, `content="`+r.s.csrf+`"`) {
		t.Fatalf("index: %d", resp.StatusCode)
	}
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"script-src 'self'", "frame-ancestors 'none'", "default-src 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(body, "<script>") {
		t.Error("inline script allowed")
	}
	for k, v := range map[string]string{"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"} {
		if resp.Header.Get(k) != v {
			t.Errorf("%s = %q", k, resp.Header.Get(k))
		}
	}
	// DNS rebinding: a page on evil.example that resolves to 127.0.0.1.
	if resp, _ := r.do("GET", "/api/state", "", map[string]string{"Host": "evil.example:" + fmt.Sprint(r.s.port)}); resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("rebinding host: %d", resp.StatusCode)
	}
	if resp, _ := r.do("GET", "/", "", map[string]string{"Host": fmt.Sprintf("localhost:%d", r.s.port)}); resp.StatusCode != 200 {
		t.Errorf("localhost host: %d", resp.StatusCode)
	}
	// Static files are embedded.
	for _, f := range []string{"/app.js", "/app.css", "/favicon.svg"} {
		if resp, body := r.do("GET", f, "", nil); resp.StatusCode != 200 || len(body) < 100 {
			t.Errorf("%s: %d", f, resp.StatusCode)
		}
	}
	// ui.json is private.
	fi, err := os.Stat(approval.InfoPath(r.home))
	if err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 { // no Unix modes on Windows
		t.Errorf("ui.json: %v %v", fi, err)
	}
}

func TestApproveFlow(t *testing.T) {
	r := start(t)
	r.login()
	got := make(chan string, 1)
	go func() {
		d, err := approval.Ask(r.home, approval.Request{Agent: "codex", Tool: "Bash", Evidence: "git push --force", Severity: "high"}, 5*time.Second)
		if err != nil {
			d = "error: " + err.Error()
		}
		got <- d
	}()
	p := r.waitPending(1)[0]
	if p.Evidence != "git push --force" || p.Deadline == 0 {
		t.Errorf("pending: %+v", p)
	}
	body := fmt.Sprintf(`{"id":%q,"decision":"approve"}`, p.ID)

	// CSRF: each missing piece is refused.
	cases := map[string]map[string]string{
		"no csrf":    {"Content-Type": "application/json", "Origin": r.base},
		"bad csrf":   {"Content-Type": "application/json", "Origin": r.base, "X-CSRF-Token": "x"},
		"no origin":  {"Content-Type": "application/json", "X-CSRF-Token": r.s.csrf},
		"bad origin": {"Content-Type": "application/json", "X-CSRF-Token": r.s.csrf, "Origin": "http://evil.example"},
		"form post":  {"Content-Type": "text/plain", "X-CSRF-Token": r.s.csrf, "Origin": r.base},
	}
	for name, h := range cases {
		if resp, _ := r.do("POST", "/api/decide", body, h); resp.StatusCode < 400 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	saved := r.cookie
	r.cookie = nil
	if resp, _ := r.post("/api/decide", body); resp.StatusCode != 401 {
		t.Errorf("no cookie: %d", resp.StatusCode)
	}
	r.cookie = saved
	if resp, _ := r.post("/api/decide", `{"id":"x","decision":"maybe"}`); resp.StatusCode != 400 {
		t.Errorf("bad decision: %d", resp.StatusCode)
	}
	if resp, b := r.post("/api/decide", body); resp.StatusCode != 200 {
		t.Fatalf("decide: %d %s", resp.StatusCode, b)
	}
	if d := <-got; d != approval.Approve {
		t.Errorf("hook got %q", d)
	}
	if resp, _ := r.post("/api/decide", body); resp.StatusCode != 404 {
		t.Errorf("second click: %d", resp.StatusCode)
	}

	// Nobody clicks.
	d, err := approval.Ask(r.home, approval.Request{Agent: "codex"}, 200*time.Millisecond)
	if err != nil || d != approval.Timeout {
		t.Errorf("timeout: %q %v", d, err)
	}
	r.waitPending(0)
}

func TestForgedHookRequests(t *testing.T) {
	r := start(t)
	body := `{"agent":"codex","timeout_ms":100}`
	nonce := approval.NewToken()
	bad := map[string]string{approval.NonceHeader: nonce, approval.AuthHeader: approval.Sign("wrong-token-wrong-token-wrong-token", "hook", nonce, body)}
	if resp, _ := r.do("POST", approval.AskPath, body, bad); resp.StatusCode != 403 {
		t.Errorf("bad sig: %d", resp.StatusCode)
	}
	good := map[string]string{approval.NonceHeader: nonce, approval.AuthHeader: approval.Sign(r.s.hook, "hook", nonce, body)}
	resp, b := r.do("POST", approval.AskPath, body, good)
	var a approval.Answer
	_ = json.Unmarshal([]byte(b), &a)
	if resp.StatusCode != 200 || a.Decision != approval.Timeout || !approval.Verify(r.s.hook, "ui", nonce, a.Decision, a.Proof) {
		t.Errorf("good: %d %s", resp.StatusCode, b)
	}
	if resp, _ := r.do("POST", approval.AskPath, body, good); resp.StatusCode != 403 {
		t.Errorf("replay: %d", resp.StatusCode)
	}
	// A tampered body fails the signature.
	if resp, _ := r.do("POST", approval.AskPath, strings.Replace(body, "codex", "claude", 1), map[string]string{
		approval.NonceHeader: approval.NewToken(), approval.AuthHeader: good[approval.AuthHeader]}); resp.StatusCode != 403 {
		t.Errorf("tampered: %d", resp.StatusCode)
	}
}

func TestHookThroughUI(t *testing.T) {
	r := start(t)
	r.login()
	proj := filepath.Join(r.home, "code", "app")
	_ = os.MkdirAll(proj, 0o755)
	in := `{"session_id":"c1","cwd":` + jsonString(proj) + `,"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}`
	type out struct {
		res hook.Result
		out string
	}
	ch := make(chan out, 1)
	go func() {
		var o, e bytes.Buffer
		res := hook.RunResult("codex", strings.NewReader(in), &o, &e, hook.Options{Home: r.home, Bin: "/x/tattlr"})
		ch <- out{res, o.String()}
	}()
	p := r.waitPending(1)[0]
	if p.Agent != "codex" || !strings.Contains(p.Reason, "orce") {
		t.Errorf("pending: %+v", p)
	}
	if resp, _ := r.post("/api/decide", fmt.Sprintf(`{"id":%q,"decision":"approve"}`, p.ID)); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	o := <-ch
	if o.res.Exit != 0 || strings.Contains(o.out, "deny") {
		t.Errorf("codex was not let through: %d %q", o.res.Exit, o.out)
	}
	es, _ := audit.Read(config.AuditPath(r.home))
	if len(es) != 1 || es[0].Approval != "approved" || es[0].Decision != "allow" {
		t.Errorf("audit: %+v", es)
	}
}

func TestStreamAndState(t *testing.T) {
	r := start(t)
	r.login()
	path := config.AuditPath(r.home)
	if err := audit.Append(path, audit.Entry{Time: time.Now(), Agent: "claude", Decision: "deny", Mode: "protect", Evidence: "rm -rf ~"}); err != nil {
		t.Fatal(err)
	}
	resp, body := r.do("GET", "/api/state", "", nil)
	var st struct {
		Mode    string        `json:"mode"`
		Timeout int           `json:"approval_timeout"`
		Entries []audit.Entry `json:"entries"`
		Stats   stats         `json:"stats"`
	}
	if err := json.Unmarshal([]byte(body), &st); err != nil || resp.StatusCode != 200 {
		t.Fatalf("state: %d %s", resp.StatusCode, body)
	}
	if st.Mode != "protect" || st.Timeout != 30 || len(st.Entries) != 1 || st.Stats.Blocked != 1 {
		t.Errorf("state: %+v", st)
	}

	req, _ := http.NewRequest("GET", r.base+"/api/stream", nil)
	req.AddCookie(r.cookie)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sr, err := r.cl.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer sr.Body.Close()
	if sr.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal(sr.Header.Get("Content-Type"))
	}
	time.Sleep(60 * time.Millisecond) // let the watcher take its first look
	_ = audit.Append(path, audit.Entry{Time: time.Now(), Agent: "codex", Decision: "allow", Mode: "protect", Evidence: "go test ./..."})
	sc := bufio.NewScanner(sr.Body)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "event: audit") {
			sc.Scan()
			if strings.Contains(sc.Text(), "go test ./...") {
				return
			}
		}
	}
	t.Fatal("no audit event on the stream")
}

func TestRapSheet(t *testing.T) {
	r := start(t)
	r.login()
	resp, body := r.do("GET", "/api/rapsheet", "", nil)
	var rs rapSheet
	if err := json.Unmarshal([]byte(body), &rs); err != nil || resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if rs.Score != 35 || rs.Verdict == "" || len(rs.Agents) != 1 || rs.Moments == nil {
		t.Errorf("%+v", rs)
	}
}

func TestOnlyLoopback(t *testing.T) {
	s := New(Options{Home: t.TempDir()})
	ln, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if a := ln.Addr().String(); !strings.HasPrefix(a, "127.0.0.1:") {
		t.Errorf("listening on %s", a)
	}
}

// The CSP has no 'unsafe-inline' for styles, so a style="" attribute set from
// app.js is silently dropped by the browser. Styles go through the CSSOM (the
// css prop in h()) instead.
func TestNoInlineStyleAttributes(t *testing.T) {
	js, err := webFS.ReadFile("web/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(js, []byte(`style: "`)) || bytes.Contains(js, []byte(`setAttribute("style"`)) {
		t.Fatal("app.js sets an inline style attribute; the CSP blocks it, use the css prop")
	}
	html, _ := webFS.ReadFile("web/index.html")
	if bytes.Contains(html, []byte(" style=")) || bytes.Contains(html, []byte("<script>")) {
		t.Fatal("index.html has inline style or script")
	}
}

// jsonString quotes s for pasting into a JSON test payload (Windows paths
// have backslashes).
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
