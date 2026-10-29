package main

import "testing"

func TestResolveVersion(t *testing.T) {
	cases := []struct{ ldflag, module, want string }{
		{"0.1.0", "", "0.1.0"},               // GoReleaser build
		{"0.1.0", "v0.1.0", "0.1.0"},         // GoReleaser wins over build info
		{"dev", "v0.1.0", "0.1.0"},           // go install ...@v0.1.0
		{"dev", "v0.2.0-rc.1", "0.2.0-rc.1"}, // prerelease tag
		{"dev", "(devel)", "dev"},            // go build in a checkout
		{"dev", "", "dev"},                   // no build info
		{"v0.1.0", "", "0.1.0"},              // someone passes the tag in by hand
		{"dev", "v0.0.0-20261029140107-b6e3064abcde", "0.0.0-20261029140107-b6e3064abcde"}, // go install ...@main
	}
	for _, c := range cases {
		if got := resolveVersion(c.ldflag, c.module); got != c.want {
			t.Errorf("resolveVersion(%q, %q) = %q, want %q", c.ldflag, c.module, got, c.want)
		}
	}
}
