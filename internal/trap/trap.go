// Package trap plants fake credentials (canaries) and keeps a local list of
// them so `tattlr scan` can tell when an agent went looking.
//
// Everything stays on disk. Nothing phones home. The keys are random strings
// in the right shape; none of them work anywhere.
package trap

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kaygaaf/tattlr/internal/rules"
)

// Trap kinds.
const (
	KindAWS    = "aws-profile"
	KindDecoy  = "decoy-env"
	KindEnv    = "project-env"
	KindSSH    = "ssh-key"
	beginMark  = "# >>> tattlr canary >>>"
	endMark    = "# <<< tattlr canary <<<"
	ProfileTag = "tattlr-canary"
)

// Trap is one planted canary.
type Trap struct {
	Kind        string    `json:"kind"`
	Path        string    `json:"path"`
	Markers     []string  `json:"markers"`
	Planted     time.Time `json:"planted"`
	CreatedFile bool      `json:"created_file"`
}

// Registry is the list of planted canaries, stored at
// ~/.config/tattlr/traps.json.
type Registry struct {
	Version int    `json:"version"`
	Traps   []Trap `json:"traps"`
}

// RegistryPath returns where the registry lives for a home dir.
func RegistryPath(home string) string {
	return filepath.Join(home, ".config", "tattlr", "traps.json")
}

// Load reads the registry. A missing file is an empty registry.
func Load(home string) (*Registry, error) {
	b, err := os.ReadFile(RegistryPath(home))
	if errors.Is(err, os.ErrNotExist) {
		return &Registry{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}
	var r Registry
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("read %s: %w", RegistryPath(home), err)
	}
	return &r, nil
}

// Save writes the registry with owner-only permissions.
func (r *Registry) Save(home string) error {
	p := RegistryPath(home)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	return os.WriteFile(p, append(b, '\n'), 0o600)
}

// Canaries converts the registry for the rule engine.
func (r *Registry) Canaries() []rules.Canary {
	var out []rules.Canary
	for _, t := range r.Traps {
		out = append(out, rules.Canary{Path: t.Path, Markers: t.Markers, Planted: t.Planted})
	}
	return out
}

func (r *Registry) has(kind, path string) bool {
	for _, t := range r.Traps {
		if t.Kind == kind && t.Path == path {
			return true
		}
	}
	return false
}

// Options says which canaries to plant.
type Options struct {
	SSH     bool     // also plant a decoy SSH private key
	EnvDirs []string // also drop a .env into these folders (only where none exists)
}

// Plan is one canary that Plant would create.
type Plan struct {
	Kind   string
	Path   string
	Action string // human description
	Skip   string // reason it will be skipped, if any
}

func targets(home string, o Options) []Plan {
	ps := []Plan{
		{Kind: KindAWS, Path: filepath.Join(home, ".aws", "credentials"), Action: "add a [" + ProfileTag + "] profile"},
		{Kind: KindDecoy, Path: filepath.Join(home, ".config", "tattlr", "decoy", ".env"), Action: "write a decoy .env"},
	}
	if o.SSH {
		ps = append(ps, Plan{Kind: KindSSH, Path: filepath.Join(home, ".ssh", "id_ed25519_backup"), Action: "write a decoy SSH key"})
	}
	for _, d := range o.EnvDirs {
		abs, err := filepath.Abs(d)
		if err != nil {
			abs = d
		}
		ps = append(ps, Plan{Kind: KindEnv, Path: filepath.Join(abs, ".env"), Action: "write a decoy .env"})
	}
	return ps
}

// Preview lists what Plant would do without touching anything.
func Preview(home string, o Options) ([]Plan, error) {
	reg, err := Load(home)
	if err != nil {
		return nil, err
	}
	ps := targets(home, o)
	for i, p := range ps {
		switch {
		case reg.has(p.Kind, p.Path):
			ps[i].Skip = "already planted"
		case p.Kind == KindAWS:
			if b, err := os.ReadFile(p.Path); err == nil && strings.Contains(string(b), beginMark) {
				ps[i].Skip = "already planted"
			}
		default:
			if _, err := os.Lstat(p.Path); err == nil {
				ps[i].Skip = "file already exists, leaving it alone"
			}
		}
	}
	return ps, nil
}

// Plant creates the canaries and records them. It never overwrites an
// existing file; for ~/.aws/credentials it appends a marked block.
func Plant(home string, o Options, now time.Time) ([]Trap, error) {
	reg, err := Load(home)
	if err != nil {
		return nil, err
	}
	ps, err := Preview(home, o)
	if err != nil {
		return nil, err
	}
	var planted []Trap
	for _, p := range ps {
		if p.Skip != "" {
			continue
		}
		t := Trap{Kind: p.Kind, Path: p.Path, Planted: now.UTC().Truncate(time.Second)}
		switch p.Kind {
		case KindAWS:
			t.CreatedFile, t.Markers, err = plantAWS(p.Path)
		case KindDecoy, KindEnv:
			t.Markers, err = writeNew(p.Path, decoyEnv)
			t.CreatedFile = true
		case KindSSH:
			t.Markers, err = writeNew(p.Path, decoySSH)
			t.CreatedFile = true
		}
		if err != nil {
			// Keep what we already planted on record so --remove can clean it.
			reg.Traps = append(reg.Traps, planted...)
			_ = reg.Save(home)
			return planted, fmt.Errorf("plant %s: %w", p.Path, err)
		}
		planted = append(planted, t)
	}
	reg.Traps = append(reg.Traps, planted...)
	if len(planted) > 0 {
		if err := reg.Save(home); err != nil {
			return planted, err
		}
	}
	return planted, nil
}

func plantAWS(path string) (created bool, markers []string, err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, nil, err
	}
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, nil, err
	}
	created = errors.Is(err, os.ErrNotExist)
	keyID := "AKIA" + randString(16, upperAlnum)
	secret := randString(40, base64ish)
	block := fmt.Sprintf("%s\n[%s]\naws_access_key_id = %s\naws_secret_access_key = %s\nregion = us-east-1\n%s\n",
		beginMark, ProfileTag, keyID, secret, endMark)
	buf := string(old)
	if buf != "" && !strings.HasSuffix(buf, "\n") {
		buf += "\n"
	}
	if buf != "" {
		buf += "\n"
	}
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.WriteFile(path, []byte(buf+block), mode); err != nil {
		return created, nil, err
	}
	return created, []string{keyID, secret, ProfileTag}, nil
}

func writeNew(path string, gen func() (string, []string)) ([]string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	body, markers := gen()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_, err = f.WriteString(body)
	return markers, err
}

func decoyEnv() (string, []string) {
	openai := "sk-proj-" + randString(48, base64ish)
	stripe := "sk_live_" + randString(24, alnum)
	keyID := "AKIA" + randString(16, upperAlnum)
	secret := randString(40, base64ish)
	pw := randString(20, alnum)
	body := fmt.Sprintf(`# production
OPENAI_API_KEY=%s
STRIPE_SECRET_KEY=%s
AWS_ACCESS_KEY_ID=%s
AWS_SECRET_ACCESS_KEY=%s
DATABASE_URL=postgres://admin:%s@db.internal:5432/prod
`, openai, stripe, keyID, secret, pw)
	return body, []string{openai, stripe, keyID, secret, pw}
}

func decoySSH() (string, []string) {
	blob := randString(280, base64ish)
	var lines []string
	for i := 0; i < len(blob); i += 70 {
		end := i + 70
		if end > len(blob) {
			end = len(blob)
		}
		lines = append(lines, blob[i:end])
	}
	body := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + strings.Join(lines, "\n") + "\n-----END OPENSSH PRIVATE KEY-----\n"
	return body, []string{blob[:40]}
}

// Remove deletes every recorded canary and the registry. Files tattlr created
// are only deleted if they still contain one of its markers.
func Remove(home string) ([]string, error) {
	reg, err := Load(home)
	if err != nil {
		return nil, err
	}
	var done []string
	var errs []error
	for _, t := range reg.Traps {
		msg, err := removeOne(t)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.Path, err))
			continue
		}
		done = append(done, msg)
	}
	if len(errs) > 0 {
		return done, errors.Join(errs...)
	}
	if err := os.Remove(RegistryPath(home)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return done, err
	}
	// Tidy up the decoy folder if it is empty now.
	_ = os.Remove(filepath.Join(home, ".config", "tattlr", "decoy"))
	return done, nil
}

func removeOne(t Trap) (string, error) {
	b, err := os.ReadFile(t.Path)
	if errors.Is(err, os.ErrNotExist) {
		return "already gone: " + t.Path, nil
	}
	if err != nil {
		return "", err
	}
	s := string(b)
	if t.Kind == KindAWS {
		cleaned, ok := stripBlock(s)
		if !ok {
			return "no canary block found in " + t.Path, nil
		}
		if t.CreatedFile && strings.TrimSpace(cleaned) == "" {
			return "removed " + t.Path, os.Remove(t.Path)
		}
		fi, _ := os.Stat(t.Path)
		return "removed the [" + ProfileTag + "] profile from " + t.Path, os.WriteFile(t.Path, []byte(cleaned), fi.Mode().Perm())
	}
	for _, m := range t.Markers {
		if m != "" && strings.Contains(s, m) {
			return "removed " + t.Path, os.Remove(t.Path)
		}
	}
	return "left " + t.Path + " alone (it was changed since tattlr wrote it)", nil
}

// stripBlock removes the marked canary block and the blank line before it.
func stripBlock(s string) (string, bool) {
	i := strings.Index(s, beginMark)
	if i < 0 {
		return s, false
	}
	j := strings.Index(s[i:], endMark)
	if j < 0 {
		return s, false
	}
	end := i + j + len(endMark)
	if end < len(s) && s[end] == '\n' {
		end++
	}
	before := strings.TrimRight(s[:i], "\n")
	if before != "" {
		before += "\n"
	}
	return before + s[end:], true
}

const (
	upperAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	alnum      = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	base64ish  = alnum + "+/"
)

func randString(n int, set string) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(set)))
	for i := range b {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		b[i] = set[v.Int64()]
	}
	return string(b)
}
