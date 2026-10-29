package cli

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kaygaaf/tattlr/internal/approval"
)

// syncBuf is a bytes.Buffer safe to read while the server writes.
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestUICommand(t *testing.T) {
	home := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	var out, errb syncBuf
	done := make(chan int)
	go func() {
		done <- Run([]string{"ui", "--port", "0", "--home", home}, Env{Stdout: &out, Stderr: &errb, Home: home, Now: time.Now(), Ctx: ctx})
	}()
	var in approval.Info
	for i := 0; i < 200; i++ {
		var err error
		if in, err = approval.ReadInfo(home); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if in.Port == 0 {
		t.Fatalf("no ui.json; out %q err %q", out.String(), errb.String())
	}
	for i := 0; i < 100 && !strings.Contains(out.String(), "Ctrl+C"); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if s := out.String(); !strings.Contains(s, "http://127.0.0.1:") || !strings.Contains(s, "?token="+in.Login) || strings.Contains(s, in.Token) {
		t.Errorf("output: %q", s)
	}
	// A second copy refuses instead of stealing ui.json.
	var o2, e2 syncBuf
	if code := Run([]string{"ui", "--port", "0", "--home", home}, Env{Stdout: &o2, Stderr: &e2, Home: home, Ctx: ctx}); code != 1 || !strings.Contains(e2.String(), "already running") {
		t.Errorf("second ui: %d %q", code, e2.String())
	}
	cancel()
	if code := <-done; code != 0 {
		t.Errorf("exit %d: %s", code, errb.String())
	}
	if _, err := os.Stat(approval.InfoPath(home)); !os.IsNotExist(err) {
		t.Error("ui.json left behind")
	}
	if code := Run([]string{"ui", "--port", "70000"}, Env{Stdout: &o2, Stderr: &e2, Home: home}); code != 2 {
		t.Errorf("bad port: %d", code)
	}
}
