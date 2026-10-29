package jsonl

import (
	"strings"
	"testing"
	"time"
)

func TestEachLineReaderSkipsJunk(t *testing.T) {
	in := "{\"a\":1}\n\nnot json\n[1,2]\n{\"b\":\"x\"}\n{\"trunc"
	var n int
	if err := EachLineReader(strings.NewReader(in), func(m map[string]any) { n++ }); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("got %d objects, want 2", n)
	}
}

func TestTime(t *testing.T) {
	want := time.Date(2026, 10, 24, 21, 14, 0, 0, time.UTC)
	tests := []struct {
		name string
		in   any
	}{
		{"rfc3339", "2026-10-24T21:14:00Z"},
		{"millis z", "2026-10-24T21:14:00.000Z"},
		{"offset", "2026-10-24T23:14:00+02:00"},
		{"epoch ms", float64(want.UnixMilli())},
		{"epoch s", float64(want.Unix())},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Time(tc.in); !got.Equal(want) {
				t.Errorf("Time(%v) = %v", tc.in, got)
			}
		})
	}
	if !Time("yesterday").IsZero() || !Time(nil).IsZero() {
		t.Error("garbage should give zero time")
	}
}

func TestShellScript(t *testing.T) {
	tests := []struct {
		in   []any
		want string
	}{
		{[]any{"bash", "-lc", "ls -la"}, "ls -la"},
		{[]any{"/bin/zsh", "-c", "echo hi"}, "echo hi"},
		{[]any{"git", "status"}, "git status"},
		{[]any{"python3", "-c", "print(1)"}, "python3 -c print(1)"},
	}
	for _, tc := range tests {
		if got := ShellScript(tc.in); got != tc.want {
			t.Errorf("ShellScript(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestContentText(t *testing.T) {
	blocks := []any{map[string]any{"type": "text", "text": "one"}, map[string]any{"type": "image"}}
	got := ContentText(blocks)
	if !strings.Contains(got, "one\n") || !strings.Contains(got, `"image"`) {
		t.Errorf("got %q", got)
	}
	if ContentText(nil) != "" {
		t.Error("nil should be empty")
	}
}
