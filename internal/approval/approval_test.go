package approval

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestInfoRoundTrip(t *testing.T) {
	home := t.TempDir()
	in := Info{Port: 4242, Token: NewToken(), Login: "x", PID: 1}
	if err := WriteInfo(home, in); err != nil {
		t.Fatal(err)
	}
	got, err := ReadInfo(home)
	if err != nil {
		t.Fatal(err)
	}
	if got.Port != in.Port || got.Token != in.Token {
		t.Fatalf("got %+v", got)
	}

	// someone else's token should not remove our file
	RemoveInfo(home, "nope")
	if _, err := ReadInfo(home); err != nil {
		t.Fatalf("file went away: %v", err)
	}
	RemoveInfo(home, in.Token)
	if _, err := ReadInfo(home); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("want ErrNotRunning, got %v", err)
	}
}

func TestReadInfoRefusesLooseFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no unix perms")
	}
	home := t.TempDir()
	if err := WriteInfo(home, Info{Port: 1, Token: NewToken()}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(InfoPath(home), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadInfo(home); err == nil {
		t.Fatal("read a world readable ui.json")
	}
}

func TestReadInfoRefusesBrokenFile(t *testing.T) {
	home := t.TempDir()
	if err := WriteInfo(home, Info{Port: 0, Token: "short"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadInfo(home); err == nil {
		t.Fatal("accepted a ui.json with no port and a short token")
	}
}

func TestSignVerify(t *testing.T) {
	tok := NewToken()
	sig := Sign(tok, "hook", "n1", "body")
	if !Verify(tok, "hook", "n1", "body", sig) {
		t.Fatal("own signature did not verify")
	}
	// the who field matters, so a hook signature can't pass as a ui answer
	if Verify(tok, "ui", "n1", "body", sig) {
		t.Fatal("hook signature passed as ui")
	}
	if Verify(tok, "hook", "n2", "body", sig) || Verify(NewToken(), "hook", "n1", "body", sig) {
		t.Fatal("signature verified with the wrong nonce or token")
	}
}

// fakeUI answers every ask with decision, signed with signTok.
func fakeUI(t *testing.T, tok, signTok, decision string) Info {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != AskPath {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		nonce := r.Header.Get(NonceHeader)
		if !Verify(tok, "hook", nonce, string(body), r.Header.Get(AuthHeader)) {
			http.Error(w, "bad sig", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(Answer{Decision: decision, Proof: Sign(signTok, "ui", nonce, decision)})
	}))
	t.Cleanup(srv.Close)
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(p)
	return Info{Port: port, Token: tok}
}

func TestAskAt(t *testing.T) {
	tok := NewToken()
	for _, d := range []string{Approve, Deny, Timeout} {
		got, err := AskAt(fakeUI(t, tok, tok, d), Request{ID: "1", Agent: "codex"}, time.Second)
		if err != nil || got != d {
			t.Fatalf("%s: got %q, %v", d, got, err)
		}
	}
}

func TestAskAtRejectsForgedAnswer(t *testing.T) {
	tok := NewToken()
	if _, err := AskAt(fakeUI(t, tok, NewToken(), Approve), Request{ID: "1"}, time.Second); err == nil {
		t.Fatal("took an approve signed with some other token")
	}
}

func TestAskAtUnknownDecision(t *testing.T) {
	tok := NewToken()
	if _, err := AskAt(fakeUI(t, tok, tok, "maybe"), Request{ID: "1"}, time.Second); err == nil {
		t.Fatal("took an unknown decision")
	}
}

func TestAskWithoutUI(t *testing.T) {
	if _, err := Ask(t.TempDir(), Request{}, time.Second); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("want ErrNotRunning, got %v", err)
	}
	// ui.json left behind but nothing listening
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	if _, err := AskAt(Info{Port: port, Token: NewToken()}, Request{}, time.Second); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("want ErrNotRunning, got %v", err)
	}
}
