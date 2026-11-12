package rules

import "strings"

// Cloud instance metadata endpoints. Agents hit these to steal
// temporary cloud credentials from the machine they are running on.
//
// Hosts are listed longest first so metadata.google.internal wins over
// metadata.goog. Matching requires a host boundary, so metadata.googleapis.com
// and 169.254.170.23 do not also count as metadata.goog or 169.254.170.2.
var imdsHosts = []string{
	"metadata.google.internal",
	"169.254.169.254",
	"169.254.170.23",
	"169.254.170.2",
	"100.100.100.200",
	"fd00:ec2::254",
	"metadata.goog",
}

func imdsHost(s string) string {
	l := strings.ToLower(s)
	for _, h := range imdsHosts {
		if hostPresent(l, h) {
			return h
		}
	}
	return ""
}

func hostPresent(s, h string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], h)
		if j < 0 {
			return false
		}
		j += i
		after := j + len(h)
		if after < len(s) && isHostCont(s[after]) {
			i = j + 1
			continue
		}
		return true
	}
}

func isHostCont(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b == '.' || b == ':'
}
