package report

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/gomono"
	"golang.org/x/image/font/gofont/gomonobold"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"

	"github.com/kaygaaf/tattlr/internal/rules"
	"github.com/kaygaaf/tattlr/internal/scan"
)

const pngScale = 2

var (
	colBg     = color.RGBA{0x10, 0x12, 0x16, 0xff}
	colFg     = color.RGBA{0xf2, 0xf4, 0xf8, 0xff}
	colMuted  = color.RGBA{0x8a, 0x93, 0xa6, 0xff}
	colDim    = color.RGBA{0x5c, 0x64, 0x75, 0xff}
	colLine   = color.RGBA{0x2a, 0x2f, 0x3a, 0xff}
	colRed    = color.RGBA{0xff, 0x3b, 0x3b, 0xff}
	colYellow = color.RGBA{0xf5, 0xc5, 0x42, 0xff}
	colGreen  = color.RGBA{0x5f, 0xd3, 0x8d, 0xff}
	colBody   = color.RGBA{0xd5, 0xd9, 0xe2, 0xff}
	colWhite  = color.RGBA{0xff, 0xff, 0xff, 0xff}
)

var (
	fontsOnce sync.Once
	fontsErr  error
	fontMono  *opentype.Font
	fontBold  *opentype.Font
)

func loadCardFonts() error {
	fontsOnce.Do(func() {
		fontMono, fontsErr = opentype.Parse(gomono.TTF)
		if fontsErr != nil {
			return
		}
		fontBold, fontsErr = opentype.Parse(gomonobold.TTF)
	})
	return fontsErr
}

func cardFace(bold bool, size int) (font.Face, error) {
	if err := loadCardFonts(); err != nil {
		return nil, err
	}
	src := fontMono
	if bold {
		src = fontBold
	}
	return opentype.NewFace(src, &opentype.FaceOptions{
		Size:    float64(size * pngScale),
		DPI:     72,
		Hinting: font.HintingFull,
	})
}

func hexColor(s string) color.RGBA {
	var r, g, b uint8
	if _, err := fmt.Sscanf(s, "#%02x%02x%02x", &r, &g, &b); err != nil {
		return colMuted
	}
	return color.RGBA{r, g, b, 0xff}
}

func writePNG(path string, r *scan.Result, loc *time.Location) error {
	img, err := rasterCard(r, loc)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

type pngCard struct {
	img   *image.RGBA
	faces map[faceKey]font.Face
}

type faceKey struct {
	bold bool
	size int
}

func (p *pngCard) face(bold bool, size int) (font.Face, error) {
	k := faceKey{bold, size}
	if f, ok := p.faces[k]; ok {
		return f, nil
	}
	f, err := cardFace(bold, size)
	if err != nil {
		return nil, err
	}
	p.faces[k] = f
	return f, nil
}

func (p *pngCard) px(v int) int { return v * pngScale }

func (p *pngCard) fill(x, y, w, h int, c color.RGBA) {
	draw.Draw(p.img, image.Rect(p.px(x), p.px(y), p.px(x+w), p.px(y+h)), image.NewUniform(c), image.Point{}, draw.Src)
}

func (p *pngCard) hline(x1, x2, y, width int, c color.RGBA) {
	if x2 < x1 {
		x1, x2 = x2, x1
	}
	top := p.px(y) - p.px(width)/2
	draw.Draw(p.img, image.Rect(p.px(x1), top, p.px(x2), top+p.px(width)), image.NewUniform(c), image.Point{}, draw.Src)
}

func (p *pngCard) circle(cx, cy, r int, c color.RGBA) {
	fillCirclePx(p.img, p.px(cx), p.px(cy), p.px(r), c)
}

func fillCirclePx(img *image.RGBA, cx, cy, r int, c color.RGBA) {
	r2 := r * r
	for dy := -r; dy <= r; dy++ {
		for dx := -r; dx <= r; dx++ {
			if dx*dx+dy*dy <= r2 {
				img.SetRGBA(cx+dx, cy+dy, c)
			}
		}
	}
}

func (p *pngCard) roundRect(x, y, w, h, r int, c color.RGBA) {
	x, y, w, h, r = p.px(x), p.px(y), p.px(w), p.px(h), p.px(r)
	if r*2 > w {
		r = w / 2
	}
	if r*2 > h {
		r = h / 2
	}
	draw.Draw(p.img, image.Rect(x+r, y, x+w-r, y+h), image.NewUniform(c), image.Point{}, draw.Src)
	draw.Draw(p.img, image.Rect(x, y+r, x+w, y+h-r), image.NewUniform(c), image.Point{}, draw.Src)
	fillCirclePx(p.img, x+r, y+r, r, c)
	fillCirclePx(p.img, x+w-1-r, y+r, r, c)
	fillCirclePx(p.img, x+r, y+h-1-r, r, c)
	fillCirclePx(p.img, x+w-1-r, y+h-1-r, r, c)
}

func textWidth(face font.Face, s string, tracking int) int {
	runes := []rune(s)
	if len(runes) == 0 {
		return 0
	}
	w := 0
	for i, r := range runes {
		w += font.MeasureString(face, string(r)).Ceil()
		if i < len(runes)-1 {
			w += tracking
		}
	}
	return w
}

func (p *pngCard) text(face font.Face, x, y int, c color.Color, s string, tracking int) {
	d := &font.Drawer{
		Dst:  p.img,
		Src:  image.NewUniform(c),
		Face: face,
		Dot:  fixed.P(p.px(x), p.px(y)),
	}
	if tracking == 0 {
		d.DrawString(s)
		return
	}
	tr := tracking * pngScale
	runes := []rune(s)
	for i, r := range runes {
		d.DrawString(string(r))
		if i < len(runes)-1 {
			d.Dot.X += fixed.I(tr)
		}
	}
}

func (p *pngCard) textCenter(face font.Face, cx, y int, c color.Color, s string, tracking int) {
	w := textWidth(face, s, tracking*pngScale)
	p.text(face, (p.px(cx)-w/2)/pngScale, y, c, s, tracking)
}

func rasterCard(r *scan.Result, loc *time.Location) (*image.RGBA, error) {
	if loc == nil {
		loc = time.Local
	}
	if err := loadCardFonts(); err != nil {
		return nil, err
	}
	p := &pngCard{
		img:   image.NewRGBA(image.Rect(0, 0, cardW*pngScale, cardH*pngScale)),
		faces: map[faceKey]font.Face{},
	}
	draw.Draw(p.img, p.img.Bounds(), image.NewUniform(colBg), image.Point{}, draw.Src)

	bold := func(size int) font.Face {
		f, err := p.face(true, size)
		if err != nil {
			return nil
		}
		return f
	}
	reg := func(size int) font.Face {
		f, err := p.face(false, size)
		if err != nil {
			return nil
		}
		return f
	}
	// Load the faces we need up front so a font error isn't a nil draw later.
	for _, size := range []int{16, 17, 18, 19, 22, 23, 24, 30, 34, 44, 60} {
		if _, err := p.face(false, size); err != nil {
			return nil, err
		}
		if _, err := p.face(true, size); err != nil {
			return nil, err
		}
	}

	p.fill(0, 0, cardW, 8, colRed)
	for i := 0; i < 10; i++ {
		y := 90 + i*55
		p.hline(1165, 1190, y, 2, colLine)
	}

	p.roundRect(60, 50, 132, 40, 4, colRed)
	p.textCenter(bold(24), 126, 78, colWhite, "TATTLR", 3)
	p.text(bold(30), 212, 80, colFg, "My AI agents' rap sheet", 0)
	p.text(reg(19), 60, 124, colMuted, cardSubtitle(r, loc), 0)
	if q := cardQuip(r); q != "" {
		p.text(reg(23), 60, 168, colYellow, clip(q, 76), 0)
	}

	crit, high, blocked, worst, showBlocked := cardHeadline(r)
	const sy = 252
	stat := func(x int, value, label string, c color.RGBA) {
		p.text(bold(60), x, sy, c, value, 0)
		p.text(reg(17), x, sy+32, colMuted, strings.ToUpper(label), 1)
	}
	stat(statFlaggedX, fmt.Sprint(r.Flagged), "flagged calls", colFg)
	stat(statScoreX, fmt.Sprint(r.Score), "score", colFg)
	stat(statCritX, fmt.Sprint(crit), "critical", hexColor(sevColor[rules.Critical]))
	stat(statHighX, fmt.Sprint(high), "high", hexColor(sevColor[rules.High]))
	wx := statWorstX
	if showBlocked {
		stat(statBlockedX, fmt.Sprint(blocked), "blocked live", colGreen)
		wx = statWorstBlockedX
	}
	worstSize := 44
	if len(worst)*27 > 1140-wx {
		worstSize = 34
	}
	p.text(bold(worstSize), wx, sy-6, colFg, worst, 0)
	p.text(reg(17), wx, sy+32, colMuted, "MOST WANTED", 1)

	p.hline(60, 1110, 322, 2, colLine)

	const ly = 364
	p.text(reg(17), 60, ly, colMuted, "AGENTS", 1)
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
		p.text(reg(22), 60, y, colFg, a.Agent, 0)
		bw := 1 + a.Score*200/max
		bar := hexColor(sevColor[rules.Low])
		switch {
		case a.Score >= 120:
			bar = hexColor(sevColor[rules.Critical])
		case a.Score >= 50:
			bar = hexColor(sevColor[rules.High])
		case a.Score >= 15:
			bar = hexColor(sevColor[rules.Medium])
		}
		p.roundRect(240, y-16, bw, 18, 3, bar)
		p.text(reg(17), 250+bw, y-1, colMuted, a.Verdict, 0)
	}
	if len(r.Agents) == 0 {
		p.text(reg(22), 60, ly+44, colMuted, "No agent logs found.", 0)
	}

	p.text(reg(17), 660, ly, colMuted, "TOP OFFENSES", 1)
	for i, off := range r.Offenses {
		if i == 5 {
			break
		}
		y := ly + 44 + i*46
		p.circle(668, y-7, 7, hexColor(sevColor[off.Severity]))
		p.text(reg(22), 688, y, colFg, fmt.Sprintf("%dx", off.Count), 0)
		p.text(reg(18), 748, y-1, colBody, clip(off.Title, 35), 0)
	}
	if len(r.Offenses) == 0 {
		p.text(reg(22), 660, ly+44, colGreen, "Clean record. Suspicious.", 0)
	}

	p.text(reg(16), 60, 640, colDim, "Scanned locally with tattlr. No commands, paths or secrets on this card.", 0)
	url := "github.com/kaygaaf/tattlr"
	face16 := reg(16)
	uw := textWidth(face16, url, 0)
	p.text(face16, (p.px(1110)-uw)/pngScale, 640, colMuted, url, 0)
	return p.img, nil
}
