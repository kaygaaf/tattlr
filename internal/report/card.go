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

// Card writes a 1200x630 SVG share card.
func Card(w io.Writer, r *scan.Result, loc *time.Location) error {
	if loc == nil {
		loc = time.Local
	}
	var b strings.Builder
	esc := html.EscapeString
	f := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	f(`<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', monospace">` + "\n")
	f(`<rect width="1200" height="630" fill="#101216"/>` + "\n")
	f(`<rect x="0" y="0" width="1200" height="8" fill="#ff3b3b"/>` + "\n")
	// Mugshot height lines on the right edge.
	for i := 0; i < 9; i++ {
		y := 90 + i*55
		f(`<line x1="1165" y1="%d" x2="1190" y2="%d" stroke="#2a2f3a" stroke-width="2"/>`+"\n", y, y)
	}

	f(`<rect x="60" y="48" width="132" height="40" rx="4" fill="#ff3b3b"/>` + "\n")
	f(`<text x="126" y="76" font-size="24" font-weight="700" fill="#ffffff" text-anchor="middle" letter-spacing="3">TATTLR</text>` + "\n")
	f(`<text x="212" y="78" font-size="30" font-weight="700" fill="#f2f4f8">My AI agents' rap sheet</text>` + "\n")
	f(`<text x="60" y="122" font-size="20" fill="#8a93a6">%s</text>`+"\n", esc(cardSubtitle(r, loc)))

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
	stat := func(x int, value, label, color string) {
		f(`<text x="%d" y="210" font-size="60" font-weight="700" fill="%s">%s</text>`+"\n", x, color, esc(value))
		f(`<text x="%d" y="242" font-size="18" fill="#8a93a6" letter-spacing="1">%s</text>`+"\n", x, esc(strings.ToUpper(label)))
	}
	stat(60, fmt.Sprint(r.Flagged), "flagged tool calls", "#f2f4f8")
	stat(370, fmt.Sprint(crit), "critical", sevColor[rules.Critical])
	stat(570, fmt.Sprint(high), "high", sevColor[rules.High])
	worstSize := 44
	if len(worst) > 11 {
		worstSize = 36
	}
	f(`<text x="760" y="204" font-size="%d" font-weight="700" fill="#f2f4f8">%s</text>`+"\n", worstSize, esc(worst))
	f(`<text x="760" y="242" font-size="18" fill="#8a93a6" letter-spacing="1">MOST WANTED</text>` + "\n")

	f(`<line x1="60" y1="276" x2="1110" y2="276" stroke="#2a2f3a" stroke-width="2"/>` + "\n")

	// Left: agents with score bars.
	f(`<text x="60" y="318" font-size="18" fill="#8a93a6" letter-spacing="1">AGENTS</text>` + "\n")
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
		y := 356 + i*46
		f(`<text x="60" y="%d" font-size="22" fill="#f2f4f8">%s</text>`+"\n", y, esc(a.Agent))
		bw := 1 + a.Score*230/max
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
		f(`<text x="%d" y="%d" font-size="18" fill="#8a93a6">%s</text>`+"\n", 250+bw, y, esc(a.Verdict))
	}

	// Right: top offenses.
	f(`<text x="660" y="318" font-size="18" fill="#8a93a6" letter-spacing="1">TOP OFFENSES</text>` + "\n")
	for i, off := range r.Offenses {
		if i == 5 {
			break
		}
		y := 356 + i*46
		f(`<circle cx="668" cy="%d" r="7" fill="%s"/>`+"\n", y-7, sevColor[off.Severity])
		f(`<text x="688" y="%d" font-size="22" fill="#f2f4f8">%dx</text>`+"\n", y, off.Count)
		f(`<text x="748" y="%d" font-size="18" fill="#d5d9e2">%s</text>`+"\n", y, esc(clip(off.Title, 36)))
	}
	if len(r.Offenses) == 0 {
		f(`<text x="660" y="356" font-size="22" fill="#5fd38d">Clean record. Suspicious.</text>` + "\n")
	}

	f(`<text x="60" y="600" font-size="16" fill="#5c6475">Scanned locally with tattlr. No commands, paths or secrets on this card.</text>` + "\n")
	f(`<text x="1110" y="600" font-size="16" fill="#8a93a6" text-anchor="end">github.com/kaygaaf/tattlr</text>` + "\n")
	f("</svg>\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func cardSubtitle(r *scan.Result, loc *time.Location) string {
	return summaryLine(r, loc)
}

// WriteCard writes the card to path. A .png path is rendered from the SVG
// with rsvg-convert, resvg, inkscape or ImageMagick if one is installed.
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
		{"rsvg-convert", "-w", "1200", "-h", "630", "-o", path, tmp.Name()},
		{"resvg", "-w", "1200", tmp.Name(), path},
		{"inkscape", tmp.Name(), "--export-type=png", "--export-filename=" + path},
		{"magick", tmp.Name(), path},
		{"convert", tmp.Name(), path},
	}
	for _, c := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"} {
		abs, _ := filepath.Abs(path)
		tries = append(tries, []string{c, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
			"--window-size=1200,630", "--screenshot=" + abs, "file://" + tmp.Name()})
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
