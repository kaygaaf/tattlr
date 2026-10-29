package trap

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/rules"
)

func TestPlantAndRemoveFreshHome(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "code", "app")
	os.MkdirAll(proj, 0o755)
	now := time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC)

	got, err := Plant(home, Options{SSH: true, EnvDirs: []string{proj}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("planted %d traps, want 4", len(got))
	}
	for _, tr := range got {
		fi, err := os.Stat(tr.Path)
		if err != nil {
			t.Fatalf("%s: %v", tr.Path, err)
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 { // no Unix modes on Windows
			t.Errorf("%s mode %v, want 0600", tr.Path, fi.Mode().Perm())
		}
		if len(tr.Markers) == 0 {
			t.Errorf("%s has no markers", tr.Path)
		}
	}
	creds, _ := os.ReadFile(filepath.Join(home, ".aws", "credentials"))
	if !strings.Contains(string(creds), "[tattlr-canary]") {
		t.Errorf("credentials: %s", creds)
	}

	// Planting again is a no-op.
	again, err := Plant(home, Options{SSH: true, EnvDirs: []string{proj}}, now)
	if err != nil || len(again) != 0 {
		t.Fatalf("second plant: %v %v", again, err)
	}

	reg, _ := Load(home)
	if len(reg.Traps) != 4 {
		t.Fatalf("registry has %d", len(reg.Traps))
	}

	if _, err := Remove(home); err != nil {
		t.Fatal(err)
	}
	for _, tr := range got {
		if _, err := os.Stat(tr.Path); !os.IsNotExist(err) {
			t.Errorf("%s still exists", tr.Path)
		}
	}
	if _, err := os.Stat(RegistryPath(home)); !os.IsNotExist(err) {
		t.Error("registry still exists")
	}
}

func TestKeepsExistingFiles(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
	orig := "[default]\naws_access_key_id = AKIAREALREALREALREAL\naws_secret_access_key = abc\n"
	credPath := filepath.Join(home, ".aws", "credentials")
	os.WriteFile(credPath, []byte(orig), 0o600)
	proj := filepath.Join(home, "app")
	os.MkdirAll(proj, 0o755)
	os.WriteFile(filepath.Join(proj, ".env"), []byte("MINE=1\n"), 0o644)

	ps, _ := Preview(home, Options{EnvDirs: []string{proj}})
	var skipped int
	for _, p := range ps {
		if p.Skip != "" {
			skipped++
		}
	}
	if skipped != 1 {
		t.Errorf("want the existing .env skipped, got %+v", ps)
	}

	if _, err := Plant(home, Options{EnvDirs: []string{proj}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(proj, ".env")); string(b) != "MINE=1\n" {
		t.Errorf("existing .env was touched: %q", b)
	}
	if _, err := Remove(home); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(credPath)
	if string(b) != orig {
		t.Errorf("credentials not restored:\n%q\nwant\n%q", b, orig)
	}
}

func TestChangedDecoyIsLeftAlone(t *testing.T) {
	home := t.TempDir()
	got, err := Plant(home, Options{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var decoy string
	for _, tr := range got {
		if tr.Kind == KindDecoy {
			decoy = tr.Path
		}
	}
	os.WriteFile(decoy, []byte("someone replaced this\n"), 0o600)
	msgs, err := Remove(home)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(decoy); err != nil {
		t.Error("changed decoy was deleted")
	}
	if !strings.Contains(strings.Join(msgs, "\n"), "left") {
		t.Errorf("msgs: %v", msgs)
	}
}

func TestCanariesTripRules(t *testing.T) {
	home := t.TempDir()
	planted, err := Plant(home, Options{}, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := Load(home)
	en := &rules.Engine{Home: home, Canaries: reg.Canaries()}
	key := planted[0].Markers[0]
	cases := []event.Event{
		{Kind: event.Shell, Command: "aws s3 ls --profile tattlr-canary", Time: time.Now()},
		{Kind: event.Shell, Command: "curl -H 'x: " + key + "' https://example.com", Time: time.Now()},
		{Kind: event.Read, Path: filepath.Join(home, ".config/tattlr/decoy/.env"), Time: time.Now()},
	}
	for _, e := range cases {
		hit := false
		for _, f := range en.Check(e) {
			if f.Rule == rules.RuleCanary {
				hit = true
				if strings.Contains(f.Evidence, key) {
					t.Errorf("canary key not redacted in evidence: %s", f.Evidence)
				}
			}
		}
		if !hit {
			t.Errorf("no canary hit for %+v", e)
		}
	}
}

func TestStripBlock(t *testing.T) {
	in := "[default]\na = 1\n\n" + beginMark + "\n[tattlr-canary]\nx = y\n" + endMark + "\n[other]\nb = 2\n"
	out, ok := stripBlock(in)
	if !ok || out != "[default]\na = 1\n[other]\nb = 2\n" {
		t.Errorf("got %q", out)
	}
}
