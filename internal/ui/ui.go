// Package ui is the local web page behind "tattlr ui": a live timeline of
// hook decisions, the rap sheet, and an inbox where asks from agents that
// can't ask (Codex, Cursor file edits) wait for a click.
//
// It only listens on 127.0.0.1. The page needs a per-run login token
// (printed in the terminal, swapped for a SameSite=Strict cookie), every
// POST needs a CSRF token and a same-origin Origin header, and every
// request needs a Host of 127.0.0.1 or localhost so DNS rebinding can't
// reach it. Hooks sign their requests with a separate token from ui.json.
package ui

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kaygaaf/tattlr/internal/approval"
	"github.com/kaygaaf/tattlr/internal/audit"
	"github.com/kaygaaf/tattlr/internal/config"
	"github.com/kaygaaf/tattlr/internal/policy"
	"github.com/kaygaaf/tattlr/internal/scan"
)

//go:embed web
var webFS embed.FS

// DefaultPort is where tattlr ui listens unless told otherwise.
const DefaultPort = 7477

// Options configure the server.
type Options struct {
	Home string
	Port int // 0 picks a free port
	Now  func() time.Time
	// Scan builds the rap sheet. nil means scan.Run over Home.
	Scan func() (*scan.Result, error)
	// Poll is how often the audit log is checked. 0 means 400ms.
	Poll time.Duration
}

// Server is one run of tattlr ui.
type Server struct {
	o       Options
	port    int
	login   string // in the URL
	hook    string // in ui.json, signs hook requests
	session string // cookie value
	csrf    string

	mu      sync.Mutex
	pending map[string]*pending
	nonces  map[string]time.Time
	subs    map[chan sse]struct{}
	rap     *rapSheet
	rapAt   time.Time
	offset  int64
}

type pending struct {
	req      approval.Request
	deadline time.Time
	answer   chan string
}

type sse struct {
	event string
	data  []byte
}

// New makes a server with fresh tokens. Call Listen or Handler next.
func New(o Options) *Server {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Poll == 0 {
		o.Poll = 400 * time.Millisecond
	}
	if o.Scan == nil {
		home := o.Home
		o.Scan = func() (*scan.Result, error) { return scan.Run(scan.Options{Home: home, Now: time.Now()}) }
	}
	return &Server{o: o, login: approval.NewToken(), hook: approval.NewToken(), session: approval.NewToken(),
		csrf: approval.NewToken(), pending: map[string]*pending{}, nonces: map[string]time.Time{}, subs: map[chan sse]struct{}{}}
}

// Listen binds 127.0.0.1 and records the port.
func (s *Server) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(s.o.Port)))
	if err != nil {
		return nil, err
	}
	s.port = ln.Addr().(*net.TCPAddr).Port
	return ln, nil
}

// URL is the link to open, with the login token.
func (s *Server) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/?token=%s", s.port, s.login)
}

// Info is what goes in ui.json.
func (s *Server) Info() approval.Info {
	return approval.Info{Port: s.port, Token: s.hook, Login: s.login, PID: os.Getpid(), Started: s.o.Now().UTC()}
}

// Serve runs until ctx ends. It writes ui.json while it runs.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if err := approval.WriteInfo(s.o.Home, s.Info()); err != nil {
		ln.Close()
		return fmt.Errorf("could not write %s: %w", approval.InfoPath(s.o.Home), err)
	}
	defer approval.RemoveInfo(s.o.Home, s.hook)
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go s.watch(ctx)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Handler is the whole app.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFS, "web")
	files := http.FileServer(http.FS(static))
	mux.HandleFunc("/", s.index)
	for _, f := range []string{"/app.js", "/app.css", "/favicon.svg"} {
		mux.Handle(f, files)
	}
	mux.HandleFunc("/api/state", s.authed(s.state))
	mux.HandleFunc("/api/stream", s.authed(s.stream))
	mux.HandleFunc("/api/rapsheet", s.authed(s.rapsheet))
	mux.HandleFunc("/api/decide", s.authed(s.decide))
	mux.HandleFunc(approval.AskPath, s.ask)
	return s.guard(mux)
}

// guard checks the Host header and sets headers every answer gets.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.goodHost(r.Host) {
			http.Error(w, "tattlr ui only answers on 127.0.0.1", http.StatusMisdirectedRequest)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) goodHost(host string) bool {
	p := strconv.Itoa(s.port)
	return host == "127.0.0.1:"+p || host == "localhost:"+p
}

func (s *Server) goodOrigin(o string) bool {
	p := strconv.Itoa(s.port)
	return o == "http://127.0.0.1:"+p || o == "http://localhost:"+p
}

func (s *Server) cookieName() string { return "tattlr_ui_" + strconv.Itoa(s.port) }

func same(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (s *Server) loggedIn(r *http.Request) bool {
	c, err := r.Cookie(s.cookieName())
	return err == nil && same(c.Value, s.session)
}

// authed wraps the browser API: cookie always, CSRF and Origin on POST.
func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.loggedIn(r) {
			jsonError(w, http.StatusUnauthorized, "open the link tattlr ui printed")
			return
		}
		if r.Method != http.MethodGet {
			if r.Method != http.MethodPost {
				jsonError(w, http.StatusMethodNotAllowed, "use GET or POST")
				return
			}
			if !s.goodOrigin(r.Header.Get("Origin")) || !same(r.Header.Get("X-CSRF-Token"), s.csrf) {
				jsonError(w, http.StatusForbidden, "bad CSRF token or origin")
				return
			}
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				jsonError(w, http.StatusUnsupportedMediaType, "send JSON")
				return
			}
		}
		h(w, r)
	}
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "use GET", http.StatusMethodNotAllowed)
		return
	}
	if t := r.URL.Query().Get("token"); t != "" {
		if !same(t, s.login) {
			page(w, http.StatusForbidden, "That link is from another run of tattlr ui. Use the one it printed this time.")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: s.session, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		// Drop the token from the address bar and history.
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if !s.loggedIn(r) {
		page(w, http.StatusUnauthorized, "Open the link tattlr ui printed in your terminal. It has a token that's new every run.")
		return
	}
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(strings.Replace(string(b), "{{CSRF}}", s.csrf, 1)))
}

func page(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>tattlr</title><link rel="stylesheet" href="/app.css"><body class="gate"><main><h1>tattlr</h1><p>%s</p></main></body>`, html.EscapeString(msg))
}

func jsonError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------- state and the live stream ----------------

type stats struct {
	Checked  int `json:"checked"`
	Blocked  int `json:"blocked"`
	Asked    int `json:"asked"`
	Approved int `json:"approved"`
	Would    int `json:"would"`
}

type pendingView struct {
	approval.Request
	Deadline int64 `json:"deadline"` // unix ms
}

func (s *Server) state(w http.ResponseWriter, _ *http.Request) {
	pol, perr := policy.Load(config.PolicyPath(s.o.Home))
	if pol == nil {
		pol = policy.Default()
	}
	es, _ := audit.Tail(config.AuditPath(s.o.Home), 2<<20)
	if len(es) > 500 {
		es = es[len(es)-500:]
	}
	if es == nil {
		es = []audit.Entry{}
	}
	out := map[string]any{
		"mode": pol.Mode, "approval_timeout": int(pol.ApprovalTimeout / time.Second), "notify": pol.Notify,
		"entries": es, "pending": s.pendingList(), "stats": Stats(es, s.o.Now()), "now": s.o.Now().UnixMilli(),
	}
	if perr != nil {
		out["policy_error"] = perr.Error()
	}
	writeJSON(w, out)
}

func (s *Server) pendingList() []pendingView {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []pendingView{}
	for _, p := range s.pending {
		out = append(out, pendingView{Request: p.req, Deadline: p.deadline.UnixMilli()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Deadline < out[j].Deadline })
	return out
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, http.StatusInternalServerError, "no streaming")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	ch := make(chan sse, 32)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}()
	fmt.Fprint(w, "retry: 2000\n\n")
	fl.Flush()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case m := <-ch:
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", m.event, m.data)
			fl.Flush()
		case <-tick.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

func (s *Server) broadcast(event string, v any) {
	b, _ := json.Marshal(v)
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- sse{event, b}:
		default: // a slow tab misses an update; it reloads state on reconnect
		}
	}
}

// watch tails the audit log and pushes new lines to every open tab.
func (s *Server) watch(ctx context.Context) {
	path := config.AuditPath(s.o.Home)
	if fi, err := os.Stat(path); err == nil {
		s.offset = fi.Size()
	}
	t := time.NewTicker(s.o.Poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if es := s.readNew(path); len(es) > 0 {
				s.broadcast("audit", es)
			}
		}
	}
}

// readNew returns whole lines added since the last call.
func (s *Server) readNew(path string) []audit.Entry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil
	}
	if fi.Size() < s.offset { // rotated or cut
		s.offset = 0
	}
	if fi.Size() == s.offset {
		return nil
	}
	if _, err := f.Seek(s.offset, io.SeekStart); err != nil {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return nil
	}
	end := strings.LastIndexByte(string(b), '\n')
	if end < 0 {
		return nil
	}
	s.offset += int64(end + 1)
	var out []audit.Entry
	for _, line := range strings.Split(string(b[:end]), "\n") {
		var e audit.Entry
		if json.Unmarshal([]byte(line), &e) == nil && !e.Time.IsZero() {
			out = append(out, e)
		}
	}
	return out
}

// ---------------- rap sheet ----------------

type rapSheet struct {
	Generated time.Time          `json:"generated"`
	Sessions  int                `json:"sessions"`
	ToolCalls int                `json:"tool_calls"`
	Flagged   int                `json:"flagged"`
	Score     int                `json:"score"`
	Verdict   string             `json:"verdict"`
	Logs      int                `json:"logs"`
	First     time.Time          `json:"first"`
	Last      time.Time          `json:"last"`
	Agents    []scan.AgentStats  `json:"agents"`
	Offenses  []rapOffense       `json:"offenses"`
	Moments   []rapMoment        `json:"moments"`
	Protect   *scan.ProtectStats `json:"protect,omitempty"`
}

type rapOffense struct {
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Count    int      `json:"count"`
	Agents   []string `json:"agents"`
}

type rapMoment struct {
	Severity string    `json:"severity"`
	Titles   []string  `json:"titles"`
	Evidence string    `json:"evidence"`
	Agent    string    `json:"agent"`
	Project  string    `json:"project"`
	Time     time.Time `json:"time"`
}

func (s *Server) rapsheet(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cached, at := s.rap, s.rapAt
	s.mu.Unlock()
	if cached == nil || r.URL.Query().Get("fresh") == "1" || s.o.Now().Sub(at) > 30*time.Second {
		res, err := s.o.Scan()
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		cached = slim(res)
		s.mu.Lock()
		s.rap, s.rapAt = cached, s.o.Now()
		s.mu.Unlock()
	}
	writeJSON(w, cached)
}

// slim keeps only what the page shows. Evidence is already redacted.
func slim(r *scan.Result) *rapSheet {
	out := &rapSheet{Generated: r.Generated, Sessions: r.Sessions, ToolCalls: r.ToolCalls, Flagged: r.Flagged,
		Score: r.Score, Verdict: scan.Verdict(r.Score), Logs: r.Logs, First: r.First, Last: r.Last,
		Agents: r.Agents, Offenses: []rapOffense{}, Moments: []rapMoment{}}
	if out.Agents == nil {
		out.Agents = []scan.AgentStats{}
	}
	for i, o := range r.Offenses {
		if i == 12 {
			break
		}
		out.Offenses = append(out.Offenses, rapOffense{Title: o.Title, Severity: o.Severity.String(), Count: o.Count, Agents: o.Agents})
	}
	for i, m := range r.Moments {
		if i == 8 {
			break
		}
		out.Moments = append(out.Moments, rapMoment{Severity: m.Severity.String(), Titles: m.Titles, Evidence: m.Evidence,
			Agent: m.Event.Agent, Project: m.Event.Project, Time: m.Event.Time})
	}
	if r.Protect != nil {
		p := *r.Protect
		if len(p.Stopped) > 10 {
			p.Stopped = p.Stopped[:10]
		}
		out.Protect = &p
	}
	return out
}

// ---------------- approvals ----------------

// ask is what hooks call. It holds the request open until someone clicks,
// the wait runs out, or the hook goes away.
func (s *Server) ask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "could not read the request")
		return
	}
	nonce := r.Header.Get(approval.NonceHeader)
	if len(nonce) < 32 || len(nonce) > 128 || !approval.Verify(s.hook, "hook", nonce, string(body), r.Header.Get(approval.AuthHeader)) {
		jsonError(w, http.StatusForbidden, "bad signature")
		return
	}
	if !s.freshNonce(nonce) {
		jsonError(w, http.StatusForbidden, "nonce used before")
		return
	}
	var req approval.Request
	if err := json.Unmarshal(body, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "bad JSON")
		return
	}
	wait := time.Duration(req.TimeoutMS) * time.Millisecond
	if wait <= 0 {
		wait = policy.DefaultApprovalTimeout
	}
	if wait > policy.MaxApprovalTimeout {
		wait = policy.MaxApprovalTimeout
	}
	req.ID = approval.NewToken()[:16]
	p := &pending{req: req, deadline: s.o.Now().Add(wait), answer: make(chan string, 1)}
	s.mu.Lock()
	s.pending[req.ID] = p
	s.mu.Unlock()
	s.broadcast("pending", s.pendingList())

	decision := approval.Timeout
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case decision = <-p.answer:
	case <-t.C:
	case <-r.Context().Done():
	}
	s.mu.Lock()
	delete(s.pending, req.ID)
	s.mu.Unlock()
	s.broadcast("pending", s.pendingList())
	s.broadcast("resolved", map[string]string{"id": req.ID, "decision": decision})
	writeJSON(w, approval.Answer{Decision: decision, Proof: approval.Sign(s.hook, "ui", nonce, decision)})
}

func (s *Server) freshNonce(n string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.o.Now()
	for k, t := range s.nonces {
		if now.Sub(t) > 2*policy.MaxApprovalTimeout {
			delete(s.nonces, k)
		}
	}
	if _, ok := s.nonces[n]; ok {
		return false
	}
	s.nonces[n] = now
	return true
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var in struct {
		ID       string `json:"id"`
		Decision string `json:"decision"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, "bad JSON")
		return
	}
	if in.Decision != approval.Approve && in.Decision != approval.Deny {
		jsonError(w, http.StatusBadRequest, "decision must be approve or deny")
		return
	}
	s.mu.Lock()
	p := s.pending[in.ID]
	if p != nil {
		delete(s.pending, in.ID)
	}
	s.mu.Unlock()
	if p == nil {
		jsonError(w, http.StatusNotFound, "that request is gone (it timed out or was answered)")
		return
	}
	p.answer <- in.Decision
	writeJSON(w, map[string]string{"ok": in.Decision})
}

// Stats sums up entries from the last day for the header.
func Stats(es []audit.Entry, now time.Time) stats {
	var st stats
	for _, e := range es {
		if now.Sub(e.Time) > 24*time.Hour {
			continue
		}
		st.Checked++
		switch e.Decision {
		case "deny":
			st.Blocked++
		case "ask":
			st.Asked++
		}
		if e.Approval == "approved" {
			st.Approved++
		}
		if e.Would != "" {
			st.Would++
		}
	}
	return st
}
