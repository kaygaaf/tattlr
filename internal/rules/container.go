package rules

import "strings"

// checkContainer flags container runs that hand the container the host:
// --privileged, the Docker socket, the host root filesystem, the host PID
// namespace or CAP_SYS_ADMIN. An agent that does this can do anything the
// host can, sandbox or not.
func checkContainer(p string, args []string, add func(string, string, Severity)) {
	pos := positional(args[1:])
	if p == "nsenter" {
		if t := flagValue(args, "-t", "--target"); t == "1" {
			add(RuleContainer, "nsenter --target 1", 0)
		}
		return
	}
	// docker run, docker container run, podman create and so on.
	verb := ""
	for _, w := range pos {
		if w == "run" || w == "create" {
			verb = w
			break
		}
		if w != "container" {
			return
		}
	}
	if verb == "" {
		return
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return
		}
		name, val := a, ""
		if j := strings.IndexByte(a, '='); j > 0 && strings.HasPrefix(a, "-") {
			name, val = a[:j], a[j+1:]
		} else if i+1 < len(args) && takesValue[a] {
			val = args[i+1]
			i++
		}
		switch name {
		case "--privileged":
			if val == "" || val == "true" {
				add(RuleContainer, p+" "+verb+" --privileged", 0)
			}
		case "-v", "--volume", "--mount":
			src := val
			if name == "--mount" {
				src = mountSource(val)
			} else if k := strings.IndexByte(val, ':'); k >= 0 {
				src = val[:k]
			}
			switch {
			case strings.HasSuffix(src, "docker.sock") || strings.HasSuffix(src, "podman.sock") || strings.HasSuffix(src, "containerd.sock"):
				add(RuleContainer, "mounted "+src, 0)
			case src == "/" || src == "/etc" || src == "/root" || src == "/proc" || src == "/sys" || src == "/dev":
				add(RuleContainer, "mounted host "+src, 0)
			}
		case "--pid":
			if val == "host" {
				add(RuleContainer, p+" "+verb+" --pid=host", 0)
			}
		case "--cap-add":
			if v := strings.ToUpper(val); v == "ALL" || v == "SYS_ADMIN" || v == "CAP_SYS_ADMIN" {
				add(RuleContainer, "--cap-add="+val, 0)
			}
		}
	}
}

// takesValue lists docker run flags we look at whose value can be the next
// word.
var takesValue = map[string]bool{
	"-v": true, "--volume": true, "--mount": true, "--pid": true, "--cap-add": true,
}

func mountSource(spec string) string {
	for _, kv := range strings.Split(spec, ",") {
		k, v, _ := strings.Cut(kv, "=")
		if k == "source" || k == "src" {
			return v
		}
	}
	return ""
}

func flagValue(args []string, short, long string) string {
	for i, a := range args {
		if (a == short || a == long) && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, long+"=") {
			return strings.TrimPrefix(a, long+"=")
		}
		if strings.HasPrefix(a, short) && len(a) > len(short) && !strings.HasPrefix(a, "--") {
			return a[len(short):]
		}
	}
	return ""
}
