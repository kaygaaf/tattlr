package pathx

import "testing"

func TestIsAbs(t *testing.T) {
	for p, want := range map[string]bool{
		"/home/kay": true, `C:\Users\kay`: true, "c:/x": true, `\\srv\share`: true,
		"C:": false, "C:x": false, "a/b": false, "~/x": false, "": false,
	} {
		if IsAbs(p) != want {
			t.Errorf("IsAbs(%q) = %v", p, !want)
		}
	}
}

func TestJoin(t *testing.T) {
	for _, c := range [][3]string{
		{"/home/kay/app", "src/a.go", "/home/kay/app/src/a.go"},
		{`C:\Users\kay\app`, "src/a.go", `C:\Users\kay\app\src\a.go`},
		{`C:\Users\kay\app`, `..\b.txt`, `C:\Users\kay\b.txt`},
	} {
		if got := Join(c[0], c[1]); got != c[2] {
			t.Errorf("Join(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}
