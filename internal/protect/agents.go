package protect

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

const hookTimeout = 10 // seconds; tattlr answers in milliseconds

func configPath(home, agent string) string {
	switch agent {
	case "claude":
		return filepath.Join(home, ".claude", "settings.json")
	case "codex":
		// Prefer hooks.json when the user already has one.
		hj := filepath.Join(home, ".codex", "hooks.json")
		if _, ok, _ := readMaybe(hj); ok {
			return hj
		}
		return filepath.Join(home, ".codex", "config.toml")
	case "cursor":
		return filepath.Join(home, ".cursor", "hooks.json")
	case "gemini":
		return filepath.Join(home, ".gemini", "settings.json")
	}
	return ""
}

// cursorEvents are the Cursor hooks tattlr registers. preToolUse only
// catches file writes and deletes; shell, MCP and reads have their own.
var cursorEvents = []struct{ name, matcher string }{
	{"beforeShellExecution", ""},
	{"beforeMCPExecution", ""},
	{"beforeReadFile", ""},
	{"preToolUse", "Write|Delete"},
}

func planInstall(agent string, o Options, strict bool) (change, error) {
	path := configPath(o.Home, agent)
	before, existed, err := readMaybe(path)
	if err != nil {
		return change{}, err
	}
	c := change{agent: agent, path: path, before: before, existed: existed}
	cmd := Command(o.Bin, agent)
	if agent == "codex" && strings.HasSuffix(path, ".toml") {
		c.after, c.notes, err = tomlInstall(string(before), cmd)
		c.notes = append(c.notes, codexTrustNote)
		return c, err
	}
	root, err := parseJSON(before)
	if err != nil {
		return c, fmt.Errorf("%s is not valid JSON (%v); fix it or move it aside first", tilde(path, o.Home), err)
	}
	if root.obj == nil {
		return c, fmt.Errorf("%s is not a JSON object", tilde(path, o.Home))
	}
	switch agent {
	case "claude", "codex":
		h := map[string]any{"type": "command", "command": cmd, "timeout": hookTimeout}
		entry := fromPairs("matcher", "*", "hooks", &node{isA: true, arr: []*node{hookNode(h, strict && agent == "claude")}})
		if agent == "codex" {
			entry = fromPairs("matcher", ".*", "hooks", &node{isA: true, arr: []*node{hookNode(h, false)}})
			c.notes = append(c.notes, codexTrustNote)
		}
		if agent == "claude" && root.get("disableAllHooks") != nil && string(root.get("disableAllHooks").raw) == "true" {
			c.notes = append(c.notes, "warning: disableAllHooks is true in this file, so no hooks run until you remove it")
		}
		hooks := ensureObj(root, "hooks")
		groups := ensureArr(hooks, "PreToolUse")
		if countGroupsOurs(groups, agent) != 1 || !hasEqual(groups, entry) {
			stripGroups(groups, agent)
			groups.arr = append(groups.arr, entry)
		}
	case "gemini":
		// Gemini times hooks in milliseconds and names them for /hooks.
		h := fromPairs("type", "command", "command", cmd, "name", "tattlr", "timeout", hookTimeout*1000)
		entry := fromPairs("matcher", ".*", "hooks", &node{isA: true, arr: []*node{h}})
		if hc := root.get("hooksConfig"); hc != nil && hc.obj != nil {
			if en := hc.get("enabled"); en != nil && string(en.raw) == "false" {
				c.notes = append(c.notes, "warning: hooksConfig.enabled is false in this file, so no hooks run until you remove it")
			}
		}
		c.notes = append(c.notes, geminiNote)
		hooks := ensureObj(root, "hooks")
		groups := ensureArr(hooks, "BeforeTool")
		if countGroupsOurs(groups, agent) != 1 || !hasEqual(groups, entry) {
			stripGroups(groups, agent)
			groups.arr = append(groups.arr, entry)
		}
	case "cursor":
		if root.get("version") == nil {
			root.set("version", scalar(1))
		}
		hooks := ensureObj(root, "hooks")
		for _, ev := range cursorEvents {
			pairs := []any{"command", cmd, "timeout", hookTimeout}
			if ev.matcher != "" {
				pairs = append(pairs, "matcher", ev.matcher)
			}
			if strict {
				pairs = append(pairs, "failClosed", true)
			}
			entry := fromPairs(pairs...)
			list := ensureArr(hooks, ev.name)
			if countFlatOurs(list, agent) != 1 || !hasEqual(list, entry) {
				stripFlat(list, agent)
				list.arr = append(list.arr, entry)
			}
		}
	}
	c.after = root.render()
	if existed && string(before) != string(c.after) && sameJSONIgnoringLayout(before, c.after) {
		c.after = before // only whitespace would change
	}
	return c, nil
}

func planUninstall(agent string, o Options, st *State) (change, error) {
	path := configPath(o.Home, agent)
	if s, ok := st.Agents[agent]; ok && s.Path != "" {
		path = s.Path
	}
	before, existed, err := readMaybe(path)
	if err != nil {
		return change{}, err
	}
	c := change{agent: agent, path: path, before: before, after: before, existed: existed}
	if !existed {
		return c, nil
	}
	created := st.Agents[agent].Created
	if strings.HasSuffix(path, ".toml") {
		after := tomlStrip(string(before))
		c.after = []byte(after)
		if created && strings.TrimSpace(after) == "" && after != string(before) {
			c.remove = true
		}
		return c, nil
	}
	root, err := parseJSON(before)
	if err != nil || root.obj == nil {
		return c, fmt.Errorf("%s is not a JSON object; remove the tattlr entries by hand", tilde(path, o.Home))
	}
	changed := false
	if hooks := root.get("hooks"); hooks != nil && hooks.obj != nil {
		for _, k := range append([]string(nil), hooks.obj.keys...) {
			list := hooks.get(k)
			if list == nil || !list.isA {
				continue
			}
			n := len(list.arr)
			if agent == "cursor" {
				stripFlat(list, agent)
			} else {
				stripGroups(list, agent)
			}
			if len(list.arr) != n {
				changed = true
				if len(list.arr) == 0 {
					hooks.del(k)
				}
			}
		}
		if changed && len(hooks.obj.keys) == 0 {
			root.del("hooks")
		}
	}
	if !changed {
		return c, nil
	}
	c.after = root.render()
	if created && (len(root.obj.keys) == 0 || (agent == "cursor" && len(root.obj.keys) == 1 && root.get("version") != nil)) {
		c.remove = true
	}
	return c, nil
}

func hookNode(h map[string]any, onFailureBlock bool) *node {
	n := fromPairs("type", h["type"], "command", h["command"], "timeout", h["timeout"])
	if onFailureBlock {
		n.set("onFailure", scalar("block"))
	}
	return n
}

func ensureObj(n *node, k string) *node {
	v := n.get(k)
	if v == nil || v.obj == nil {
		v = newObj()
		n.set(k, v)
	}
	return v
}

func ensureArr(n *node, k string) *node {
	v := n.get(k)
	if v == nil || !v.isA {
		v = &node{isA: true}
		n.set(k, v)
	}
	return v
}

func hasEqual(list, entry *node) bool {
	want := string(entry.render())
	for _, v := range list.arr {
		if string(v.render()) == want {
			return true
		}
	}
	return false
}

// Claude and Codex nest commands in matcher groups.
func groupHooks(g *node) *node {
	h := g.get("hooks")
	if h == nil || !h.isA {
		return nil
	}
	return h
}

func countGroupsOurs(groups *node, agent string) int {
	n := 0
	for _, g := range groups.arr {
		if h := groupHooks(g); h != nil {
			for _, x := range h.arr {
				if isOurs(x.get("command").str(), agent) {
					n++
				}
			}
		}
	}
	return n
}

// stripGroups drops our commands, and groups left empty by that.
func stripGroups(groups *node, agent string) {
	var keep []*node
	for _, g := range groups.arr {
		h := groupHooks(g)
		if h == nil {
			keep = append(keep, g)
			continue
		}
		var hs []*node
		for _, x := range h.arr {
			if !isOurs(x.get("command").str(), agent) {
				hs = append(hs, x)
			}
		}
		if len(hs) == 0 && len(h.arr) > 0 {
			continue
		}
		h.arr = hs
		keep = append(keep, g)
	}
	groups.arr = keep
}

func countFlatOurs(list *node, agent string) int {
	n := 0
	for _, x := range list.arr {
		if isOurs(x.get("command").str(), agent) {
			n++
		}
	}
	return n
}

func stripFlat(list *node, agent string) {
	var keep []*node
	for _, x := range list.arr {
		if !isOurs(x.get("command").str(), agent) {
			keep = append(keep, x)
		}
	}
	list.arr = keep
}

func sameJSONIgnoringLayout(a, b []byte) bool {
	na, err1 := parseJSON(a)
	nb, err2 := parseJSON(b)
	return err1 == nil && err2 == nil && na.canonical() == nb.canonical()
}

// ---------------- Codex config.toml ----------------

const (
	tomlBegin = "# >>> tattlr protect >>>"
	tomlEnd   = "# <<< tattlr protect <<<"
)

const geminiNote = "Gemini CLI fails open if a hook crashes or times out, so strict mode can't force a block there. Settings files with comments are not supported."

const codexTrustNote = "Codex asks you to trust new hooks: open Codex and run /hooks once to turn this one on."

var (
	tomlBlockRe     = regexp.MustCompile(`(?ms)\n*^` + regexp.QuoteMeta(tomlBegin) + `$.*?^` + regexp.QuoteMeta(tomlEnd) + `$\n?`)
	tomlInlineHooks = regexp.MustCompile(`(?m)^\s*(hooks|PreToolUse)\s*=`)
	tomlHooksOff    = regexp.MustCompile(`(?m)^\s*(codex_)?hooks\s*=\s*false`)
)

func tomlBlock(cmd string) string {
	q := strings.ReplaceAll(strings.ReplaceAll(cmd, `\`, `\\`), `"`, `\"`)
	return tomlBegin + "\n" +
		"[[hooks.PreToolUse]]\n" +
		"matcher = \".*\"\n\n" +
		"[[hooks.PreToolUse.hooks]]\n" +
		"type = \"command\"\n" +
		"command = \"" + q + "\"\n" +
		fmt.Sprintf("timeout = %d\n", hookTimeout) +
		tomlEnd + "\n"
}

func tomlInstall(src, cmd string) ([]byte, []string, error) {
	var notes []string
	rest := tomlStrip(src)
	if tomlInlineHooks.MatchString(rest) {
		return nil, nil, errors.New("config.toml sets hooks inline; move them to ~/.codex/hooks.json or [[hooks.PreToolUse]] tables and rerun")
	}
	if tomlHooksOff.MatchString(rest) {
		notes = append(notes, "warning: hooks are switched off in config.toml ([features] hooks = false); turn them on or tattlr never runs")
	}
	block := tomlBlock(cmd)
	if strings.Contains(src, block) {
		return []byte(src), notes, nil
	}
	out := strings.TrimRight(rest, "\n")
	if out != "" {
		out += "\n\n"
	}
	return []byte(out + block), notes, nil
}

func tomlStrip(src string) string {
	out := tomlBlockRe.ReplaceAllString(src, "\n")
	if strings.TrimSpace(out) == "" {
		return ""
	}
	if !strings.Contains(src, tomlBegin) {
		return src
	}
	return strings.TrimRight(out, "\n") + "\n"
}
