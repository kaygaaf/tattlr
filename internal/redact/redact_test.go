package redact

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	cases := []struct {
		name, in string
		mustNot  []string
		mustHave []string
	}{
		{"aws key", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", []string{"IOSFODNN7EXAMPLE"}, []string{"AWS_ACCESS_KEY_ID="}},
		{"aws inline", "key AKIAIOSFODNN7EXAMPLE here", []string{"IOSFODNN7EXAMPLE"}, []string{"AKIA****"}},
		{"github token", "git clone https://ghp_abcdefghijklmnopqrstuvwxyz0123@github.com/x/y", []string{"abcdefghijklmnop"}, []string{"github.com/x/y"}},
		{"openai", "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwx", []string{"abcdefghijklmnop"}, nil},
		{"anthropic", "curl -H 'x-api-key: sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaa'", []string{"aaaaaaaaaaaaaaaa"}, nil},
		{"bearer", `curl -H "Authorization: Bearer abcdef0123456789abcdef"`, []string{"abcdef0123456789"}, []string{"Authorization:"}},
		{"password assign", "mysql -u root --password=hunter2hunter2", []string{"hunter2"}, nil},
		{"url creds", "git push https://kay:s3cr3tpass@example.com/repo.git", []string{"s3cr3tpass"}, []string{"example.com/repo.git"}},
		{"private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----", []string{"b3BlbnNzaC1"}, []string{"[REDACTED PRIVATE KEY]"}},
		{"plain command untouched", "rm -rf node_modules && npm install", nil, []string{"rm -rf node_modules && npm install"}},
		{"path untouched", "cat ~/.aws/credentials", nil, []string{"cat ~/.aws/credentials"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := String(c.in)
			for _, s := range c.mustNot {
				if strings.Contains(got, s) {
					t.Errorf("String(%q) = %q, still contains %q", c.in, got, s)
				}
			}
			for _, s := range c.mustHave {
				if !strings.Contains(got, s) {
					t.Errorf("String(%q) = %q, missing %q", c.in, got, s)
				}
			}
		})
	}
}

func TestLine(t *testing.T) {
	if got := Line("a\n  b\tc", 0); got != "a b c" {
		t.Fatalf("got %q", got)
	}
	if got := Line("abcdefghij", 5); got != "abcd…" {
		t.Fatalf("got %q", got)
	}
}
