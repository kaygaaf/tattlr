package report

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kaygaaf/tattlr/internal/rules"
	"github.com/kaygaaf/tattlr/internal/scan"
)

// The card only shows totals and rule titles. No commands, paths or project
// names, so it is safe to post.

var sevColor = map[rules.Severity]string{
	rules.Critical: "#ff3b3b", rules.High: "#ff8a3d", rules.Medium: "#f5c542", rules.Low: "#8a93a6",
}

// Card size. 16:9 is what X shows uncropped in the timeline, and it still
// looks fine as a link preview.
const (
	cardW = 1200
	cardH = 675
)

// Card writes a 1200x675 SVG share card.
func Card(w io.Writer, r *scan.Result, loc *time.Location) error {
	if loc == nil {
		loc = time.Local
	}
	var b strings.Builder
	esc := html.EscapeString
	f := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	f(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', monospace">`+"\n", cardW, cardH, cardW, cardH)
	f(`<rect width="%d" height="%d" fill="#101216"/>`+"\n", cardW, cardH)
	f(`<rect x="0" y="0" width="%d" height="8" fill="#ff3b3b"/>`+"\n", cardW)
	// Mugshot height lines on the right edge.
	for i := 0; i < 10; i++ {
		y := 90 + i*55
		f(`<line x1="1165" y1="%d" x2="1190" y2="%d" stroke="#2a2f3a" stroke-width="2"/>`+"\n", y, y)
	}

	f(`<rect x="60" y="50" width="132" height="40" rx="4" fill="#ff3b3b"/>` + "\n")
	f(`<text x="126" y="78" font-size="24" font-weight="700" fill="#ffffff" text-anchor="middle" letter-spacing="3">TATTLR</text>` + "\n")
	f(`<text x="212" y="80" font-size="30" font-weight="700" fill="#f2f4f8">My AI agents' rap sheet</text>` + "\n")
	f(`<text x="60" y="124" font-size="19" fill="#8a93a6">%s</text>`+"\n", esc(cardSubtitle(r, loc)))
	if q := cardQuip(r); q != "" {
		f(`<text x="60" y="168" font-size="23" fill="#f5c542">%s</text>`+"\n", esc(clip(q, 76)))
	}

	// Big numbers.
	crit, high := 0, 0
	for _, a := range r.Agents {
		crit += a.BySeverity["critical"]
		high += a.BySeverity["high"]
	}
	worst := "nobody"
	if len(r.Agents) > 0 && r.Agents[0].Score > 0 {
		worst = r.Agents[0].Agent
	}
	const sy = 252
	stat := func(x int, value, label, color string) {
		f(`<text x="%d" y="%d" font-size="60" font-weight="700" fill="%s">%s</text>`+"\n", x, sy, color, esc(value))
		f(`<text x="%d" y="%d" font-size="17" fill="#8a93a6" letter-spacing="1">%s</text>`+"\n", x, sy+32, esc(strings.ToUpper(label)))
	}
	stat(60, fmt.Sprint(r.Flagged), "flagged calls", "#f2f4f8")
	stat(300, fmt.Sprint(crit), "critical", sevColor[rules.Critical])
	stat(470, fmt.Sprint(high), "high", sevColor[rules.High])
	wx := 640
	if ps := r.Protect; ps != nil && ps.Blocked > 0 {
		stat(620, fmt.Sprint(ps.Blocked), "blocked live", "#5fd38d")
		wx = 840
	}
	worstSize := 44
	if len(worst)*27 > 1140-wx {
		worstSize = 34
	}
	f(`<text x="%d" y="%d" font-size="%d" font-weight="700" fill="#f2f4f8">%s</text>`+"\n", wx, sy-6, worstSize, esc(worst))
	f(`<text x="%d" y="%d" font-size="17" fill="#8a93a6" letter-spacing="1">MOST WANTED</text>`+"\n", wx, sy+32)

	f(`<line x1="60" y1="322" x2="1110" y2="322" stroke="#2a2f3a" stroke-width="2"/>` + "\n")

	// Left: agents with score bars.
	const ly = 364
	f(`<text x="60" y="%d" font-size="17" fill="#8a93a6" letter-spacing="1">AGENTS</text>`+"\n", ly)
	max := 1
	for _, a := range r.Agents {
		if a.Score > max {
			max = a.Score
		}
	}
	for i, a := range r.Agents {
		if i == 5 {
			break
		}
		y := ly + 44 + i*46
		f(`<text x="60" y="%d" font-size="22" fill="#f2f4f8">%s</text>`+"\n", y, esc(a.Agent))
		bw := 1 + a.Score*200/max
		color := sevColor[rules.Low]
		switch {
		case a.Score >= 120:
			color = sevColor[rules.Critical]
		case a.Score >= 50:
			color = sevColor[rules.High]
		case a.Score >= 15:
			color = sevColor[rules.Medium]
		}
		f(`<rect x="240" y="%d" width="%d" height="18" rx="3" fill="%s"/>`+"\n", y-16, bw, color)
		f(`<text x="%d" y="%d" font-size="17" fill="#8a93a6">%s</text>`+"\n", 250+bw, y-1, esc(a.Verdict))
	}

	if len(r.Agents) == 0 {
		f(`<text x="60" y="%d" font-size="22" fill="#8a93a6">No agent logs found.</text>`+"\n", ly+44)
	}

	// Right: top offenses.
	f(`<text x="660" y="%d" font-size="17" fill="#8a93a6" letter-spacing="1">TOP OFFENSES</text>`+"\n", ly)
	for i, off := range r.Offenses {
		if i == 5 {
			break
		}
		y := ly + 44 + i*46
		f(`<circle cx="668" cy="%d" r="7" fill="%s"/>`+"\n", y-7, sevColor[off.Severity])
		f(`<text x="688" y="%d" font-size="22" fill="#f2f4f8">%dx</text>`+"\n", y, off.Count)
		f(`<text x="748" y="%d" font-size="18" fill="#d5d9e2">%s</text>`+"\n", y-1, esc(clip(off.Title, 35)))
	}
	if len(r.Offenses) == 0 {
		f(`<text x="660" y="%d" font-size="22" fill="#5fd38d">Clean record. Suspicious.</text>`+"\n", ly+44)
	}

	f(`<text x="60" y="640" font-size="16" fill="#5c6475">Scanned locally with tattlr. No commands, paths or secrets on this card.</text>` + "\n")
	f(`<text x="1110" y="640" font-size="16" fill="#8a93a6" text-anchor="end">github.com/kaygaaf/tattlr</text>` + "\n")
	f("</svg>\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// cardQuip is the headline joke without numbers that could look odd out of
// context. Empty when nothing was flagged.
func cardQuip(r *scan.Result) string {
	if r.Flagged == 0 || len(r.Offenses) == 0 {
		return ""
	}
	return quip(r.Offenses[0], onlyAttempts(r, r.Offenses[0].Rule))
}

func cardSubtitle(r *scan.Result, loc *time.Location) string {
	return summaryLine(r, loc, true)
}

// WriteCard writes the card to path. A .png path is rendered at 2x from the
// SVG with rsvg-convert, resvg, inkscape, ImageMagick or Chrome, whichever is
// installed first in that order.
func WriteCard(path string, r *scan.Result, loc *time.Location) error {
	var buf bytes.Buffer
	if err := Card(&buf, r, loc); err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Ext(path), ".png") {
		return os.WriteFile(path, buf.Bytes(), 0o644)
	}
	tmp, err := os.CreateTemp("", "tattlr-card-*.svg")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		return err
	}
	tmp.Close()
	tries := [][]string{
		{"rsvg-convert", "-w", fmt.Sprint(2 * cardW), "-h", fmt.Sprint(2 * cardH), "-o", path, tmp.Name()},
		{"resvg", "-w", fmt.Sprint(2 * cardW), tmp.Name(), path},
		{"inkscape", tmp.Name(), "--export-type=png", "--export-filename=" + path},
		{"magick", tmp.Name(), path},
		{"convert", tmp.Name(), path},
	}
	for _, c := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"} {
		abs, _ := filepath.Abs(path)
		tries = append(tries, []string{c, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
			"--force-device-scale-factor=2", fmt.Sprintf("--window-size=%d,%d", cardW, cardH), "--screenshot=" + abs, "file://" + tmp.Name()})
	}
	for _, t := range tries {
		if _, err := exec.LookPath(t[0]); err != nil {
			continue
		}
		if out, err := exec.Command(t[0], t[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s failed: %v: %s", t[0], err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	svg := strings.TrimSuffix(path, filepath.Ext(path)) + ".svg"
	if err := os.WriteFile(svg, buf.Bytes(), 0o644); err != nil {
		return err
	}
	return errors.New("no SVG to PNG converter found (install rsvg-convert, resvg or Chrome); wrote " + svg + " instead")
}
