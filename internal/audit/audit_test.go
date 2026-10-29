package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAppendReadTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "audit.jsonl")
	now := time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e := Entry{Time: now, Agent: "claude-code", Session: fmt.Sprint(i), Decision: "allow", Mode: "protect"}
			if i == 7 {
				e.Tainted = true
			}
			if err := Append(path, e); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	es, err := Read(path)
	if err != nil || len(es) != 50 {
		t.Fatalf("read %d entries, %v", len(es), err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	if !Tainted(es, "claude-code", "7") || Tainted(es, "codex", "7") || Tainted(es, "claude-code", "8") {
		t.Error("taint lookup wrong")
	}
	tail, _ := Tail(path, 300)
	if len(tail) == 0 || len(tail) >= 50 {
		t.Errorf("tail returned %d", len(tail))
	}
	if es, err := Read(filepath.Join(t.TempDir(), "nope")); err != nil || es != nil {
		t.Error("missing log should be empty")
	}
}
