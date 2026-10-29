package notify

import (
	"strings"
	"testing"
)

func TestCommand(t *testing.T) {
	name, args, ok := Command("linux", "tattlr blocked codex", "-rf \"x\"\nnext line")
	if !ok || name != "notify-send" || args[len(args)-3] != "--" || args[len(args)-1] != `-rf "x" next line` {
		t.Errorf("linux: %s %q", name, args)
	}
	name, args, ok = Command("darwin", `say "hi"`, `back\slash "quote"`)
	want := `display notification "back\\slash \"quote\"" with title "say \"hi\""`
	if !ok || name != "osascript" || args[1] != want {
		t.Errorf("darwin: %s %q", name, args)
	}
	name, args, ok = Command("windows", "it's <bad>", "a & b')+$(x)")
	s := args[len(args)-1]
	i, j := strings.Index(s, "LoadXml('")+len("LoadXml('"), strings.Index(s, "</toast>')")
	if !ok || name != "powershell" || i < 9 || j < i {
		t.Fatalf("windows: %s %q", name, s)
	}
	// No raw single quote may end the PowerShell string early.
	if xml := s[i:j]; strings.Contains(xml, "'") || !strings.Contains(xml, "it&apos;s &lt;bad&gt;") || !strings.Contains(xml, "a &amp; b&apos;)+$(x)") {
		t.Errorf("windows xml: %q", xml)
	}
	if _, _, ok := Command("plan9", "a", "b"); ok {
		t.Error("plan9 should have no notifier")
	}
	if got := clean(strings.Repeat("x", 300)+"\x1b[31m", 10); got != "xxxxxxxxx…" {
		t.Errorf("clean: %q", got)
	}
}
