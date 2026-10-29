// Package protect wires tattlr into each agent's hook config: install,
// uninstall and status. Every edit is shown as a diff first, backed up, and
// written atomically. Running install twice changes nothing.
package protect

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kaygaaf/tattlr/internal/config"
	"github.com/kaygaaf/tattlr/internal/policy"
)

// Agents protect knows how to wire up, in display order.
var Agents = []string{"claude", "codex", "cursor", "openclaw"}

// Options for install and uninstall.
type Options struct {
	Home   string
	Bin    string // absolute path of the tattlr binary the hooks will call
	Agents []string
	Yes    bool // skip the confirm prompt
	IsTTY  bool // stdin is a terminal, so we may prompt
	In     io.Reader
	Out    io.Writer
	Now    func() time.Time
}

// State is what protect remembers in ~/.config/tattlr/protect.json.
type State struct {
	Bin    string                `json:"bin"`
	Agents map[string]AgentState `json:"agents"`
}

// AgentState records one install.
type AgentState struct {
	Path      string    `json:"path"`
	Created   bool      `json:"created"` // we created the file, so uninstall may delete it
	Installed time.Time `json:"installed"`
}

// change is one planned file edit.
type change struct {
	agent   string
	path    string
	before  []byte
	after   []byte
	existed bool
	remove  bool // delete the file instead of writing after
	notes   []string
}

func (c change) noop() bool { return !c.remove && string(c.before) == string(c.after) }

// ErrAborted is returned when the user says no.
var ErrAborted = errors.New("nothing changed")

// LoadState reads protect.json (an empty state when missing).
func LoadState(home string) (*State, error) {
	st := &State{Agents: map[string]AgentState{}}
	b, err := os.ReadFile(config.StatePath(home))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("%s: %w", config.StatePath(home), err)
	}
	if st.Agents == nil {
		st.Agents = map[string]AgentState{}
	}
	return st, nil
}

func (s *State) save(home string) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	return writeAtomic(config.StatePath(home), append(b, '\n'), 0o600)
}

// Detect returns the agents that look installed in home.
func Detect(home string) []string {
	var out []string
	for _, a := range []string{"claude", "codex", "cursor"} {
		if fi, err := os.Stat(agentDir(home, a)); err == nil && fi.IsDir() {
			out = append(out, a)
		}
	}
	return out
}

func agentDir(home, agent string) string {
	switch agent {
	case "claude":
		return filepath.Join(home, ".claude")
	case "codex":
		return filepath.Join(home, ".codex")
	case "cursor":
		return filepath.Join(home, ".cursor")
	}
	return ""
}

func checkAgents(as []string) error {
	for _, a := range as {
		ok := false
		for _, k := range Agents {
			ok = ok || a == k
		}
		if !ok {
			return fmt.Errorf("unknown agent %q (use %s)", a, strings.Join(Agents, ", "))
		}
	}
	return nil
}

// Install adds tattlr's hooks for the chosen agents.
func Install(o Options) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	if !filepath.IsAbs(o.Bin) {
		return fmt.Errorf("binary path %q is not absolute", o.Bin)
	}
	agents := o.Agents
	if len(agents) == 0 {
		agents = Detect(o.Home)
		if len(agents) == 0 {
			return errors.New("found no Claude Code, Codex or Cursor config in your home; pass --agent to pick one")
		}
	}
	if err := checkAgents(agents); err != nil {
		return err
	}
	pol, err := policy.Load(config.PolicyPath(o.Home))
	if err != nil {
		return fmt.Errorf("fix your policy first: %w", err)
	}
	strict := pol.Mode == policy.Strict

	var cs []change
	for _, a := range agents {
		if a == "openclaw" {
			fmt.Fprint(o.Out, openClawHelp(o.Bin))
			continue
		}
		c, err := planInstall(a, o, strict)
		if err != nil {
			return fmt.Errorf("%s: %w", a, err)
		}
		cs = append(cs, c)
	}
	st, err := LoadState(o.Home)
	if err != nil {
		return err
	}
	if err := apply(cs, o, st, true); err != nil {
		return err
	}
	if created, err := policy.WriteDefault(config.PolicyPath(o.Home)); err != nil {
		return err
	} else if created {
		fmt.Fprintf(o.Out, "Wrote the default policy to %s (mode: protect).\n", tilde(config.PolicyPath(o.Home), o.Home))
	}
	if len(cs) > 0 {
		st.Bin = o.Bin
		if err := st.save(o.Home); err != nil {
			return err
		}
	}
	return nil
}

// Uninstall removes only the entries tattlr added.
func Uninstall(o Options) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	st, err := LoadState(o.Home)
	if err != nil {
		return err
	}
	agents := o.Agents
	if len(agents) == 0 {
		agents = []string{"claude", "codex", "cursor"}
	}
	if err := checkAgents(agents); err != nil {
		return err
	}
	var cs []change
	for _, a := range agents {
		if a == "openclaw" {
			fmt.Fprintln(o.Out, "openclaw: remove the tattlr plugin with `openclaw plugins uninstall tattlr`.")
			continue
		}
		c, err := planUninstall(a, o, st)
		if err != nil {
			return fmt.Errorf("%s: %w", a, err)
		}
		cs = append(cs, c)
	}
	if err := apply(cs, o, st, false); err != nil {
		return err
	}
	if len(st.Agents) == 0 {
		st.Bin = ""
	}
	return st.save(o.Home)
}

// apply shows the diffs, asks, then writes.
func apply(cs []change, o Options, st *State, install bool) error {
	var todo []change
	for _, c := range cs {
		for _, n := range c.notes {
			fmt.Fprintf(o.Out, "%s: %s\n", c.agent, n)
		}
		if c.noop() {
			if install {
				fmt.Fprintf(o.Out, "%s: already installed in %s\n", c.agent, tilde(c.path, o.Home))
			} else {
				fmt.Fprintf(o.Out, "%s: nothing to remove in %s\n", c.agent, tilde(c.path, o.Home))
			}
			continue
		}
		todo = append(todo, c)
	}
	if len(todo) == 0 {
		return nil
	}
	for _, c := range todo {
		p := tilde(c.path, o.Home)
		if c.remove {
			fmt.Fprintf(o.Out, "%s: delete %s (tattlr created it and it is empty again)\n", c.agent, p)
			continue
		}
		fmt.Fprint(o.Out, unifiedDiff(p, string(c.before), string(c.after)))
	}
	if !o.Yes {
		if !o.IsTTY {
			return errors.New("not a terminal, so I can't ask; rerun with --yes to apply the changes above")
		}
		fmt.Fprint(o.Out, "Apply these changes? [y/N] ")
		line, _ := bufio.NewReader(o.In).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return ErrAborted
		}
	}
	for _, c := range todo {
		if c.existed {
			bak, err := backup(c, o)
			if err != nil {
				return err
			}
			fmt.Fprintf(o.Out, "%s: backed up %s to %s\n", c.agent, tilde(c.path, o.Home), tilde(bak, o.Home))
		}
		if c.remove {
			if err := os.Remove(c.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		} else if err := writeAtomic(c.path, c.after, 0o600); err != nil {
			return err
		}
		if install {
			prev, had := st.Agents[c.agent]
			created := !c.existed || (had && prev.Created && prev.Path == c.path)
			st.Agents[c.agent] = AgentState{Path: c.path, Created: created, Installed: o.Now().UTC()}
			fmt.Fprintf(o.Out, "%s: hooked up in %s\n", c.agent, tilde(c.path, o.Home))
		} else {
			delete(st.Agents, c.agent)
			fmt.Fprintf(o.Out, "%s: removed from %s\n", c.agent, tilde(c.path, o.Home))
		}
	}
	return nil
}

func backup(c change, o Options) (string, error) {
	dir := config.BackupDir(o.Home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	stamp := o.Now().UTC().Format("20060102T150405")
	var f *os.File
	var p string
	for i := 0; ; i++ {
		name := fmt.Sprintf("%s-%s.%s.bak", c.agent, filepath.Base(c.path), stamp)
		if i > 0 {
			name = fmt.Sprintf("%s-%s.%s-%d.bak", c.agent, filepath.Base(c.path), stamp, i)
		}
		p = filepath.Join(dir, name)
		var err error
		f, err = os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) || i > 100 {
			return "", err
		}
	}
	if _, err := f.Write(c.before); err != nil {
		f.Close()
		return "", err
	}
	return p, f.Close()
}

// writeAtomic writes through a temp file and rename. It follows symlinks so
// a dotfiles-managed config stays a symlink, and keeps the existing mode.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tattlr-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readMaybe(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return b, err == nil, err
}

// Command is the hook command line for an agent.
func Command(bin, agent string) string { return shellQuote(bin) + " hook " + agent }

func shellQuote(s string) string {
	if regexp.MustCompile(`^[A-Za-z0-9_./-]+$`).MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func isOurs(cmd, agent string) bool {
	return strings.Contains(cmd, "tattlr") && regexp.MustCompile(`\bhook\s+`+agent+`\b`).MatchString(cmd)
}

func tilde(p, home string) string {
	if rel, err := filepath.Rel(home, p); err == nil && !strings.HasPrefix(rel, "..") {
		return "~/" + rel
	}
	return p
}

func openClawHelp(bin string) string {
	return fmt.Sprintf(`openclaw: OpenClaw hooks are plugins, so there is no config to edit. Install the plugin:
  openclaw plugins install ./integrations/openclaw
  and set TATTLR_BIN=%s if tattlr is not on PATH.
`, bin)
}
