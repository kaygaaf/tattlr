package rules

import "strings"

// segment is one simple command inside a shell line, like the "curl x" in
// "curl x | sh".
type segment struct {
	Args     []string
	Out      []string // > and >> targets
	Append   []string // >> targets only
	In       []string // < sources
	PipeNext bool     // this segment pipes into the next one
}

// splitShell is a small, forgiving shell lexer. It understands quotes,
// backslashes, pipes, &&, ||, ;, & and redirects. It does not try to be a
// real shell; it only needs to be good enough to find commands and targets.
func splitShell(s string) []segment {
	var segs []segment
	cur := segment{}
	var word strings.Builder
	inWord := false
	pending := "" // "out", "append" or "in" when the next word is a redirect target

	flushWord := func() {
		if !inWord {
			return
		}
		w := word.String()
		word.Reset()
		inWord = false
		switch pending {
		case "out":
			cur.Out = append(cur.Out, w)
		case "append":
			cur.Out = append(cur.Out, w)
			cur.Append = append(cur.Append, w)
		case "in":
			cur.In = append(cur.In, w)
		default:
			cur.Args = append(cur.Args, w)
		}
		pending = ""
	}
	flushSeg := func(pipe bool) {
		flushWord()
		cur.PipeNext = pipe
		if len(cur.Args) > 0 || len(cur.Out) > 0 {
			segs = append(segs, cur)
		}
		cur = segment{}
	}

	r := []rune(s)
	for i := 0; i < len(r); i++ {
		c := r[i]
		switch {
		case c == '\\' && i+1 < len(r):
			i++
			if r[i] != '\n' {
				word.WriteRune(r[i])
				inWord = true
			}
		case c == '\'':
			inWord = true
			for i++; i < len(r) && r[i] != '\''; i++ {
				word.WriteRune(r[i])
			}
		case c == '"':
			inWord = true
			for i++; i < len(r) && r[i] != '"'; i++ {
				if r[i] == '\\' && i+1 < len(r) {
					i++
				}
				word.WriteRune(r[i])
			}
		case c == ' ' || c == '\t':
			flushWord()
		case c == '\n' || c == ';' || c == '(' || c == ')' || c == '`' || c == '{' && !inWord || c == '}' && !inWord:
			flushSeg(false)
		case c == '|':
			if i+1 < len(r) && r[i+1] == '|' {
				i++
				flushSeg(false)
			} else {
				if i+1 < len(r) && r[i+1] == '&' {
					i++
				}
				flushSeg(true)
			}
		case c == '&':
			if i+1 < len(r) && r[i+1] == '>' {
				flushWord()
				i++
				pending = "out"
				if i+1 < len(r) && r[i+1] == '>' {
					i++
					pending = "append"
				}
			} else {
				if i+1 < len(r) && r[i+1] == '&' {
					i++
				}
				flushSeg(false)
			}
		case c == '>':
			// "2>" and "1>": drop the fd digit we just read.
			if inWord && (word.String() == "1" || word.String() == "2") {
				word.Reset()
				inWord = false
			}
			flushWord()
			pending = "out"
			if i+1 < len(r) && r[i+1] == '>' {
				i++
				pending = "append"
			}
			if i+1 < len(r) && r[i+1] == '&' {
				// 2>&1: skip the target fd.
				i++
				for i+1 < len(r) && r[i+1] >= '0' && r[i+1] <= '9' {
					i++
				}
				pending = ""
			}
		case c == '<':
			flushWord()
			if i+1 < len(r) && r[i+1] == '<' {
				// heredoc or herestring; treat as input, skip marker
				i++
				if i+1 < len(r) && r[i+1] == '<' {
					i++
				}
			}
			pending = "in"
		case c == '$' && i+1 < len(r) && r[i+1] == '(':
			i++
			flushSeg(false)
		default:
			word.WriteRune(c)
			inWord = true
		}
	}
	flushSeg(false)
	for i := range segs {
		segs[i].Args = stripPrefixes(segs[i].Args)
	}
	return segs
}

// stripPrefixes drops leading env assignments and wrappers like "sudo",
// "env", "time", "nohup", "command", "exec", "xargs" so Args[0] is the real
// program. sudo itself is caught elsewhere on the raw text.
func stripPrefixes(args []string) []string {
	for len(args) > 0 {
		a := args[0]
		if a == "env" && len(positionalNoAssign(args[1:])) == 0 {
			return args
		}
		switch {
		case strings.Contains(a, "=") && !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "="):
			args = args[1:]
		case a == "sudo" || a == "doas" || a == "env" || a == "time" || a == "nohup" || a == "command" ||
			a == "exec" || a == "nice" || a == "xargs" || a == "then" || a == "do" || a == "else" || a == "!":
			args = args[1:]
			for len(args) > 0 && strings.HasPrefix(args[0], "-") {
				// sudo -u root: skip the flag and its value when it takes one
				f := args[0]
				args = args[1:]
				if (f == "-u" || f == "-g" || f == "-n" && a == "nice") && len(args) > 0 {
					args = args[1:]
				}
			}
		default:
			return args
		}
	}
	return args
}

func prog(seg segment) string {
	if len(seg.Args) == 0 {
		return ""
	}
	p := seg.Args[0]
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	return p
}

// hasFlag reports whether the short flag letter or any long flag is set.
func hasFlag(args []string, short byte, long ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		for _, l := range long {
			if a == l || strings.HasPrefix(a, l+"=") {
				return true
			}
		}
		if len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.IndexByte(a[1:], short) >= 0 {
			return true
		}
	}
	return false
}

func positional(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

// words splits a command into rough path-like tokens for path matching.
func words(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\'', '"', '(', ')', '`', ';', '|', '&', '<', '>', '=', ',', '{', '}':
			return true
		}
		return false
	})
}

func positionalNoAssign(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") && !strings.Contains(a, "=") {
			out = append(out, a)
		}
	}
	return out
}
