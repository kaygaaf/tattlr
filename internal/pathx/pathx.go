// Package pathx handles paths that come out of agent logs. Those can be
// Unix paths (/home/kay/x) or Windows paths (C:\Users\kay\x) no matter
// which OS tattlr itself runs on, so path/filepath is the wrong tool.
package pathx

import (
	"path"
	"strings"
)

// IsAbs reports whether p is absolute on either Unix or Windows.
func IsAbs(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return true
	}
	return HasDrive(p) && len(p) > 2 && (p[2] == '/' || p[2] == '\\')
}

// HasDrive reports whether p starts with a Windows drive letter like "C:".
func HasDrive(p string) bool {
	return len(p) >= 2 && p[1] == ':' && (p[0] >= 'a' && p[0] <= 'z' || p[0] >= 'A' && p[0] <= 'Z')
}

// windowsStyle reports whether p looks like a Windows path.
func windowsStyle(p string) bool {
	return HasDrive(p) || strings.Contains(p, `\`) && !strings.Contains(p, "/")
}

// Join joins rel onto dir in dir's own style.
func Join(dir, rel string) string {
	if windowsStyle(dir) {
		s := path.Join(strings.ReplaceAll(dir, `\`, "/"), strings.ReplaceAll(rel, `\`, "/"))
		return strings.ReplaceAll(s, "/", `\`)
	}
	return path.Join(dir, rel)
}
