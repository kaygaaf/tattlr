// Package notify pops a desktop notification without waiting for it.
// It uses notify-send on Linux and the BSDs, osascript on macOS and a
// PowerShell toast on Windows. Nothing is sent anywhere else.
package notify

import (
	"os/exec"
	"runtime"
	"strings"
	"unicode/utf8"
)

// Command returns the program and arguments that show a notification on
// goos, or ok=false when there is no way to do it.
func Command(goos, title, body string) (name string, args []string, ok bool) {
	title, body = clean(title, 80), clean(body, 240)
	switch goos {
	case "darwin":
		script := "display notification " + appleQuote(body) + " with title " + appleQuote(title)
		return "osascript", []string{"-e", script}, true
	case "windows":
		return "powershell", []string{"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", toastScript(title, body)}, true
	case "linux", "freebsd", "openbsd", "netbsd", "dragonfly":
		// "--" so a body that starts with a dash is not read as a flag.
		return "notify-send", []string{"-a", "tattlr", "-u", "normal", "--", title, body}, true
	}
	return "", nil, false
}

// Send shows a notification if the system has a way to. It starts the
// helper and returns right away; the hook never waits on it.
func Send(title, body string) error {
	name, args, ok := Command(runtime.GOOS, title, body)
	if !ok {
		return nil
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	cmd := exec.Command(path, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// clean keeps one line of printable text, at most n runes.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > n {
		s = string([]rune(s)[:n-1]) + "…"
	}
	return s
}

// appleQuote makes an AppleScript string literal.
func appleQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// psQuote makes a PowerShell single-quoted string.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

// powershellAppID borrows PowerShell's own app id so the toast shows up
// without registering a shortcut.
const powershellAppID = `{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe`

func toastScript(title, body string) string {
	xml := `<toast><visual><binding template="ToastGeneric"><text>` + xmlEscape(title) + `</text><text>` + xmlEscape(body) + `</text></binding></visual></toast>`
	return strings.Join([]string{
		`[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null`,
		`[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null`,
		`$x = New-Object Windows.Data.Xml.Dom.XmlDocument`,
		`$x.LoadXml(` + psQuote(xml) + `)`,
		`[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier(` + psQuote(powershellAppID) + `).Show([Windows.UI.Notifications.ToastNotification]::new($x))`,
	}, "; ")
}
