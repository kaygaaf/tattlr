package protect

import (
	"os"
	"testing"
)

// A real hooks/list reply from Codex 0.165.0, paths redacted.
const hooksListUntrusted = `{"id":2,"result":{"data":[{"cwd":"/home/kay/code/proj","hooks":[{"key":"/home/kay/.codex/config.toml:pre_tool_use:0:0","eventName":"preToolUse","handlerType":"command","command":"/home/kay/.local/bin/tattlr hook codex","async":false,"matcher":".*","timeoutSec":40,"statusMessage":null,"additionalContextLimit":null,"sourcePath":"/home/kay/.codex/config.toml","source":"user","pluginId":null,"displayOrder":0,"enabled":true,"isManaged":false,"currentHash":"sha256:e9dfa3bf8f24bfc596c5cb3091054e51f33097bcebd97f8e50e01b199e153e97","trustStatus":"untrusted"}],"warnings":[],"errors":[]}]}}`

func TestParseHooksList(t *testing.T) {
	if s, ok := parseHooksList([]byte(hooksListUntrusted)); !ok || s != TrustUntrusted {
		t.Errorf("got %q %v", s, ok)
	}
	if _, ok := parseHooksList([]byte(`{"id":1,"result":{"userAgent":"x"}}`)); ok {
		t.Error("initialize reply taken as hooks/list")
	}
	other := `{"id":2,"result":{"data":[{"hooks":[{"command":"other-tool","trustStatus":"untrusted"}]}]}}`
	if s, ok := parseHooksList([]byte(other)); !ok || s != TrustUnknown {
		t.Errorf("someone else's hook counted: %q", s)
	}
}

func TestTrustFromTOML(t *testing.T) {
	cfg := "/home/kay/.codex/config.toml"
	plain := "[[hooks.PreToolUse]]\nmatcher = \".*\"\n"
	if got := trustFromTOML(plain, cfg); got != TrustUntrusted {
		t.Errorf("no record: %q", got)
	}
	rec := plain + "\n[hooks.state.\"" + cfg + ":pre_tool_use:0:0\"]\ntrusted_hash = \"sha256:abc\"\n"
	if got := trustFromTOML(rec, cfg); got != TrustUnknown {
		t.Errorf("with record: %q", got)
	}
}

func TestMain(m *testing.M) {
	// Never spawn a real codex from tests.
	codexBin = func() string { return "" }
	os.Exit(m.Run())
}
