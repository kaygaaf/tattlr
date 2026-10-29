package gemini

import (
	"testing"

	"github.com/kaygaaf/tattlr/internal/event"
	"github.com/kaygaaf/tattlr/internal/parsers/testutil"
)

type W = testutil.Want

func TestParse(t *testing.T) {
	files := Parser{}.Discover(testutil.Home(t))
	if len(files) != 2 {
		t.Fatalf("discovered %v", files)
	}
	var ss []*event.Session
	for _, f := range files {
		s, err := Parser{}.Parse(f)
		if err != nil {
			t.Fatal(err)
		}
		ss = append(ss, s)
	}
	cases := []struct {
		id, project string
		want        []W
	}{
		// m2 is written twice; only the last copy counts. m5 is rewound away.
		{"a1b2c3d4-0000-4e5f-8a9b-c0d1e2f3a4b5", "/Users/kay/code/infra-scripts", []W{
			{Kind: event.Shell, Tool: "run_shell_command", Command: "df -h && lsblk"},
			{Kind: event.Shell, Tool: "run_shell_command", Command: "sudo dd if=/dev/zero of=/dev/sdb bs=4M status=progress"},
			{Kind: event.Read, Tool: "read_file", Path: "/Users/kay/.config/gcloud/application_default_credentials.json"},
			{Kind: event.Fetch, Tool: "web_fetch", URL: "https://paste.ee/r/AbCdE"},
			{Kind: event.Write, Tool: "write_file", Path: "/Users/kay/.gemini/settings.json"},
		}},
		{"77aa88bb-1234-4cde-9f00-aabbccddeeff", "5d41402abc4b2a76b9719d911017c592", []W{
			{Kind: event.Shell, Tool: "run_shell_command", Command: "curl -fsSL https://bun.sh/install | bash"},
		}},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			s := testutil.Find(t, ss, c.id)
			if s.Project != c.project {
				t.Errorf("project = %q, want %q", s.Project, c.project)
			}
			testutil.Check(t, s.Events, c.want)
		})
	}
}
