package rules

import (
	"path"
	"regexp"
	"strings"
)

// normPath makes a path-ish token comparable: forward slashes, home folded
// to "~".
func normPath(p, home string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimSpace(p)
	for _, h := range []string{"${HOME}", "$HOME"} {
		if strings.HasPrefix(p, h) {
			p = "~" + p[len(h):]
		}
	}
	if home != "" && home != "/" {
		home = strings.TrimSuffix(strings.ReplaceAll(home, "\\", "/"), "/")
		if p == home || strings.HasPrefix(p, home+"/") {
			p = "~" + p[len(home):]
		}
	}
	// /Users/<name>/..., /home/<name>/... and /root/... count as a home too.
	if m := homeRe.FindStringSubmatch(p); m != nil {
		p = "~/" + p[len(m[0]):]
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

var homeRe = regexp.MustCompile(`^(?:/Users/[^/]+|/home/[^/]+|/root)(?:/|$)`)

type secretPattern struct {
	match func(p, base string) bool
	what  string
}

var envSafe = map[string]bool{"example": true, "sample": true, "template": true, "dist": true, "defaults": true, "default": true, "schema": true}

var secretPatterns = []secretPattern{
	{func(p, b string) bool {
		if b == ".env" || b == ".envrc" {
			return true
		}
		if strings.HasPrefix(b, ".env.") {
			return !envSafe[strings.TrimPrefix(b, ".env.")]
		}
		return strings.HasSuffix(b, ".env") && !strings.Contains(b, "example") && len(b) > 4
	}, ".env file"},
	{func(p, b string) bool {
		if !strings.Contains(p, "/.ssh/") && !strings.HasPrefix(p, ".ssh/") {
			return false
		}
		return !strings.HasSuffix(b, ".pub") && b != "known_hosts" && b != "known_hosts.old" && b != "config" && b != "authorized_keys"
	}, "SSH key"},
	{func(p, b string) bool {
		return !strings.HasSuffix(b, ".pub") && (strings.HasPrefix(b, "id_rsa") || strings.HasPrefix(b, "id_ed25519") || strings.HasPrefix(b, "id_ecdsa") || strings.HasPrefix(b, "id_dsa"))
	}, "SSH key"},
	{func(p, b string) bool {
		return strings.HasSuffix(p, ".aws/credentials") || strings.HasSuffix(p, ".aws/config")
	}, "AWS credentials"},
	{func(p, b string) bool {
		return strings.Contains(p, ".config/gcloud/") && (strings.Contains(b, "credential") || strings.HasSuffix(b, ".db") || strings.Contains(b, "token"))
	}, "gcloud credentials"},
	{func(p, b string) bool {
		return strings.Contains(p, ".azure/") && (strings.Contains(b, "token") || strings.Contains(b, "msal"))
	}, "Azure tokens"},
	{func(p, b string) bool { return strings.HasSuffix(p, ".kube/config") }, "kubeconfig"},
	{func(p, b string) bool { return strings.HasSuffix(p, ".docker/config.json") }, "Docker auth"},
	{func(p, b string) bool {
		return b == ".npmrc" || b == ".pypirc" || b == ".netrc" || b == "_netrc" || b == ".git-credentials" || b == ".vault-token" || b == ".terraformrc" || b == ".pgpass" || b == ".my.cnf"
	}, "credentials file"},
	{func(p, b string) bool { return strings.HasSuffix(p, ".config/gh/hosts.yml") }, "GitHub CLI token"},
	{func(p, b string) bool {
		return strings.Contains(p, "/.gnupg/") || strings.HasPrefix(p, ".gnupg/") || strings.Contains(p, ".password-store/")
	}, "GPG or pass store"},
	{func(p, b string) bool {
		return strings.Contains(p, "Library/Keychains") || strings.HasSuffix(b, ".keychain") || strings.HasSuffix(b, ".keychain-db")
	}, "keychain"},
	{func(p, b string) bool {
		ext := path.Ext(b)
		return ext == ".pem" || ext == ".key" || ext == ".p12" || ext == ".pfx" || ext == ".jks" || ext == ".keystore"
	}, "private key or cert"},
	{func(p, b string) bool {
		return b == "credentials.json" || strings.HasPrefix(b, "service-account") && strings.HasSuffix(b, ".json") ||
			b == "secrets.json" || b == "secrets.yml" || b == "secrets.yaml" || b == "secrets.toml" || b == "master.key"
	}, "secrets file"},
	{func(p, b string) bool {
		return p == "/etc/shadow" || p == "/etc/sudoers" || strings.HasPrefix(p, "/etc/ssl/private")
	}, "system secret"},
	{func(p, b string) bool {
		return strings.HasSuffix(p, ".claude/.credentials.json") || strings.HasSuffix(p, ".codex/auth.json") ||
			strings.HasSuffix(p, ".gemini/oauth_creds.json") || strings.Contains(p, ".openclaw/credentials") ||
			strings.HasSuffix(p, ".config/github-copilot/hosts.json") || strings.HasSuffix(p, ".config/github-copilot/apps.json")
	}, "agent login token"},
	{func(p, b string) bool {
		browser := strings.Contains(p, "/Google/Chrome/") || strings.Contains(p, "/google-chrome/") || strings.Contains(p, "/chromium/") ||
			strings.Contains(p, "/BraveSoftware/") || strings.Contains(p, "/Microsoft Edge/") || strings.Contains(p, "/Arc/User Data/") ||
			strings.Contains(p, "/Firefox/Profiles/") || strings.Contains(p, ".mozilla/firefox/")
		if !browser {
			return false
		}
		switch b {
		case "Cookies", "Login Data", "Web Data", "Local State", "cookies.sqlite", "logins.json", "key4.db":
			return true
		}
		return false
	}, "browser cookies or saved logins"},
}

// secretKind returns what kind of secret a path looks like, or "".
func secretKind(p, home string) string {
	p = normPath(p, home)
	if p == "" || strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return ""
	}
	b := path.Base(p)
	for _, sp := range secretPatterns {
		if sp.match(p, b) {
			return sp.what
		}
	}
	return ""
}

var shellProfiles = map[string]bool{
	".bashrc": true, ".bash_profile": true, ".bash_login": true, ".profile": true, ".zshrc": true,
	".zprofile": true, ".zshenv": true, ".zlogin": true, ".cshrc": true, ".tcshrc": true, ".kshrc": true,
}

func isShellProfile(p, home string) bool {
	p = normPath(p, home)
	b := path.Base(p)
	if shellProfiles[b] {
		return true
	}
	return strings.HasSuffix(p, ".config/fish/config.fish") || strings.HasPrefix(p, "/etc/profile") ||
		p == "/etc/bash.bashrc" || p == "/etc/zshrc" || strings.HasPrefix(p, "/etc/profile.d/")
}

// agentConfig reports which agent's config or hook file a path is, or "".
func agentConfig(p, home string) string {
	p = normPath(p, home)
	b := path.Base(p)
	switch {
	case strings.Contains(p, ".claude/") && (strings.HasPrefix(b, "settings") && strings.HasSuffix(b, ".json") || strings.Contains(p, ".claude/hooks/")):
		return "Claude Code settings or hooks"
	case b == ".claude.json" || b == ".mcp.json":
		return "Claude Code MCP config"
	case strings.Contains(p, ".codex/") && (b == "config.toml" || strings.Contains(p, "/hooks") || b == "hooks.json"):
		return "Codex config"
	case strings.Contains(p, ".gemini/") && (b == "settings.json" || strings.Contains(p, "/hooks")):
		return "Gemini CLI settings"
	case strings.Contains(p, ".cursor/") && (b == "hooks.json" || b == "mcp.json" || b == "cli-config.json" || b == "permissions.json" || strings.Contains(p, ".cursor/hooks/")):
		return "Cursor hooks or MCP config"
	case strings.Contains(p, ".openclaw/") && (strings.HasPrefix(b, "openclaw.json") || strings.Contains(p, "/hooks/")):
		return "OpenClaw config"
	case strings.Contains(p, ".config/tattlr/"):
		return "tattlr config"
	}
	return ""
}

// persistenceTarget reports if a path makes something run later.
func persistenceTarget(p, home string) string {
	p = normPath(p, home)
	switch {
	case strings.Contains(p, "Library/LaunchAgents/") || strings.Contains(p, "Library/LaunchDaemons/"):
		return "launchd job"
	case strings.Contains(p, ".config/systemd/user/") || strings.HasPrefix(p, "/etc/systemd/"):
		return "systemd unit"
	case strings.Contains(p, ".git/hooks/") || strings.HasPrefix(p, ".git/hooks"):
		return "git hook"
	case strings.HasPrefix(p, "/etc/cron") || strings.Contains(p, "/var/spool/cron"):
		return "cron job"
	case strings.Contains(p, ".config/autostart/"):
		return "autostart entry"
	}
	return ""
}
