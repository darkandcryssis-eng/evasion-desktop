package main

import "math"

// The tray panel is drawn here, in plain Go, so every edge, glow and toggle is
// anti-aliased and the picture can be checked on any platform. The Windows side
// only blits the result and lays system text over it.

const (
	trayDPIButton = 1001 + iota
	trayTelegramButton
	trayDiagnoseButton
	trayOpenButton
	trayExitButton
)

const (
	trayPanelWidth, trayPanelHeight = 296, 312
	trayPanelRadius                 = 20
	// Clear space around the panel for its shadow, in panel units.
	trayShadow = 16
)

type trayBox struct{ X, Y, W, H float64 }

var trayBoxes = map[int]trayBox{
	trayDPIButton:      {12, 62, 272, 64},
	trayTelegramButton: {12, 132, 272, 64},
	trayDiagnoseButton: {12, 202, 272, 46},
	trayOpenButton:     {12, 258, 180, 40},
	trayExitButton:     {200, 258, 84, 40},
}

type trayTone struct{ R, G, B float64 }

func trayHex(v uint32) trayTone {
	return trayTone{float64(v >> 16 & 255), float64(v >> 8 & 255), float64(v & 255)}
}
func (t trayTone) hex() uint32 { return uint32(t.R+.5)<<16 | uint32(t.G+.5)<<8 | uint32(t.B+.5) }
func (t trayTone) mix(o trayTone, k float64) trayTone {
	return trayTone{t.R + (o.R-t.R)*k, t.G + (o.G-t.G)*k, t.B + (o.B-t.B)*k}
}

type trayTheme struct {
	dark                                                                       bool
	background, tile, raised, line, ink, muted, faint, accent, solid, solidInk trayTone
	track, knob, warning                                                       trayTone
}

func trayThemeFor(dark bool) trayTheme {
	if dark {
		return trayTheme{dark: true, background: trayHex(0x050506), tile: trayHex(0x121214), raised: trayHex(0x1c1c20), line: trayHex(0x232327), ink: trayHex(0xf5f5f7), muted: trayHex(0xa9a9b4), faint: trayHex(0x70707c),
			accent: trayHex(0x7c6cff), solid: trayHex(0xf5f5f7), solidInk: trayHex(0x0a0a0c), track: trayHex(0x2a2a30), knob: trayHex(0x8a8a96), warning: trayHex(0xff9c5b)}
	}
	return trayTheme{background: trayHex(0xe3e3e8), tile: trayHex(0xf4f4f7), raised: trayHex(0xffffff), line: trayHex(0xd3d3da), ink: trayHex(0x0b0b0e), muted: trayHex(0x53535e), faint: trayHex(0x868692),
		accent: trayHex(0x4d38ff), solid: trayHex(0x0b0b0e), solidInk: trayHex(0xffffff), track: trayHex(0xcfcfd8), knob: trayHex(0xffffff), warning: trayHex(0xc2530a)}
}

// trayCanvas is a window of device pixels (BGRX, top-down) onto the panel,
// which is described in 96-dpi units.
type trayCanvas struct {
	pix            []byte
	w, h           int
	originX, origY int
	scale          float64
}

func newTrayCanvas(w, h, originX, originY int, scale float64) *trayCanvas {
	w, h = max(1, w), max(1, h)
	return &trayCanvas{pix: make([]byte, w*h*4), w: w, h: h, originX: originX, origY: originY, scale: scale}
}

// each visits the device pixels of this canvas inside a box given in panel units.
func (c *trayCanvas) each(x0, y0, x1, y1 float64, visit func(i int, x, y float64)) {
	left := max(0, int(math.Floor(x0*c.scale))-c.originX)
	top := max(0, int(math.Floor(y0*c.scale))-c.origY)
	right := min(c.w, int(math.Ceil(x1*c.scale))-c.originX)
	bottom := min(c.h, int(math.Ceil(y1*c.scale))-c.origY)
	for py := top; py < bottom; py++ {
		y := (float64(py+c.origY) + .5) / c.scale
		for px := left; px < right; px++ {
			visit((py*c.w+px)*4, (float64(px+c.originX)+.5)/c.scale, y)
		}
	}
}

func (c *trayCanvas) blend(i int, t trayTone, a float64) {
	if a <= 0 {
		return
	}
	a = min(1, a)
	c.pix[i] = byte(float64(c.pix[i])*(1-a) + t.B*a + .5)
	c.pix[i+1] = byte(float64(c.pix[i+1])*(1-a) + t.G*a + .5)
	c.pix[i+2] = byte(float64(c.pix[i+2])*(1-a) + t.R*a + .5)
	c.pix[i+3] = 255
}

func (c *trayCanvas) light(i int, t trayTone, a float64) {
	if a <= 0.002 {
		return
	}
	c.pix[i] = byte(min(255, float64(c.pix[i])+t.B*a))
	c.pix[i+1] = byte(min(255, float64(c.pix[i+1])+t.G*a))
	c.pix[i+2] = byte(min(255, float64(c.pix[i+2])+t.R*a))
}

func (c *trayCanvas) cover(distance float64) float64 { return min(1, max(0, .5-distance*c.scale)) }

func roundBoxDistance(x, y float64, b trayBox, r float64) float64 {
	r = min(r, min(b.W, b.H)/2)
	qx := math.Abs(x-(b.X+b.W/2)) - (b.W/2 - r)
	qy := math.Abs(y-(b.Y+b.H/2)) - (b.H/2 - r)
	return math.Hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - r
}

func (c *trayCanvas) fillBox(b trayBox, r float64, t trayTone, alpha float64) {
	c.each(b.X-1, b.Y-1, b.X+b.W+1, b.Y+b.H+1, func(i int, x, y float64) {
		c.blend(i, t, alpha*c.cover(roundBoxDistance(x, y, b, r)))
	})
}

// strokeBox draws a line of the given width just inside the box edge.
func (c *trayCanvas) strokeBox(b trayBox, r, width float64, t trayTone, alpha float64) {
	c.each(b.X-1, b.Y-1, b.X+b.W+1, b.Y+b.H+1, func(i int, x, y float64) {
		c.blend(i, t, alpha*c.cover(math.Abs(roundBoxDistance(x, y, b, r)+width/2)-width/2))
	})
}

func (c *trayCanvas) disc(cx, cy, r float64, t trayTone, alpha float64) {
	c.each(cx-r-1, cy-r-1, cx+r+1, cy+r+1, func(i int, x, y float64) {
		c.blend(i, t, alpha*c.cover(math.Hypot(x-cx, y-cy)-r))
	})
}

func (c *trayCanvas) ring(cx, cy, r, width float64, t trayTone, alpha float64) {
	c.each(cx-r-width-1, cy-r-width-1, cx+r+width+1, cy+r+width+1, func(i int, x, y float64) {
		c.blend(i, t, alpha*c.cover(math.Abs(math.Hypot(x-cx, y-cy)-r)-width/2))
	})
}

// glow adds light that falls off from a circle of radius r (r = 0 is a point).
func (c *trayCanvas) glow(cx, cy, r, spread float64, t trayTone, strength float64) {
	reach := r + spread*3
	c.each(cx-reach, cy-reach, cx+reach, cy+reach, func(i int, x, y float64) {
		d := math.Hypot(x-cx, y-cy) - r
		c.light(i, t, strength*math.Exp(-d*d/(2*spread*spread)))
	})
}

func (c *trayCanvas) polyline(points [][2]float64, width float64, t trayTone, alpha float64) {
	for n := 0; n+1 < len(points); n++ {
		ax, ay, bx, by := points[n][0], points[n][1], points[n+1][0], points[n+1][1]
		dx, dy := bx-ax, by-ay
		length := dx*dx + dy*dy
		c.each(min(ax, bx)-width-1, min(ay, by)-width-1, max(ax, bx)+width+1, max(ay, by)+width+1, func(i int, x, y float64) {
			k := 0.0
			if length > 0 {
				k = min(1, max(0, ((x-ax)*dx+(y-ay)*dy)/length))
			}
			c.blend(i, t, alpha*c.cover(math.Hypot(x-ax-dx*k, y-ay-dy*k)-width/2))
		})
	}
}

// trayPress names the control under the pointer, the one with keyboard focus
// and the one held down; zero means none.
type trayPress struct{ hover, focus, pressed int }

// seal turns the finished picture into the premultiplied BGRA a layered window
// takes: the panel keeps anti-aliased round corners and casts a soft shadow.
func (c *trayCanvas) seal() {
	panel := trayBox{0, 0, trayPanelWidth, trayPanelHeight}
	for py := 0; py < c.h; py++ {
		y := (float64(py+c.origY) + .5) / c.scale
		for px := 0; px < c.w; px++ {
			x := (float64(px+c.originX) + .5) / c.scale
			i := (py*c.w + px) * 4
			a := c.cover(roundBoxDistance(x, y, panel, trayPanelRadius))
			d := max(0, roundBoxDistance(x, y-4, panel, trayPanelRadius))
			alpha := a + (1-a)*.36*math.Exp(-d*d/(2*4.5*4.5))
			c.pix[i] = byte(float64(c.pix[i])*a + .5)
			c.pix[i+1] = byte(float64(c.pix[i+1])*a + .5)
			c.pix[i+2] = byte(float64(c.pix[i+2])*a + .5)
			c.pix[i+3] = byte(alpha*255 + .5)
		}
	}
}

// paintTray draws the whole panel, controls included.
func paintTray(c *trayCanvas, v trayView, press trayPress) {
	th := trayThemeFor(v.Dark)
	violet := trayHex(0x5a46ff)
	panel := trayBox{0, 0, trayPanelWidth, trayPanelHeight}
	c.fillBox(trayBox{-2, -2, trayPanelWidth + 4, trayPanelHeight + 4}, 0, th.background, 1)
	if v.DPIOn {
		// The same violet air that surrounds the ring in the main window.
		if th.dark {
			c.glow(30, 34, 0, 62, violet, .3)
		} else {
			c.each(0, 0, trayPanelWidth, trayPanelHeight, func(i int, x, y float64) {
				d := math.Hypot(x-30, y-34)
				c.blend(i, violet, .2*math.Exp(-d*d/(2*62*62)))
			})
		}
	}
	c.strokeBox(panel, trayPanelRadius, 1, th.line, 1)

	// The mark: an E whose middle bar slips out of the bracket while the bypass runs.
	const mx, my = 30.0, 34.0
	c.fillBox(trayBox{mx - 16, my - 16, 32, 32}, 10, trayHex(0x000000), 1)
	ink, bar, slip := trayHex(0x8b8a96), trayHex(0x8b8a96), -3.0
	switch {
	case v.DPIOn:
		ink, bar, slip = trayHex(0xf1efff), trayHex(0xffffff), 0
		c.glow(mx+4, my, 0, 4.2, violet, .95)
	case v.DPIBusy:
		ink, bar, slip = trayHex(0xf1efff), trayHex(0xa79dff), -1.5
		c.glow(mx+2.5, my, 0, 3.6, violet, .55)
	}
	bracket := [][2]float64{{mx + 1.92, my - 6.24}}
	for _, corner := range [][3]float64{{my - 2.4, -1, 0}, {my + 2.4, 1, 1}} {
		for n := 0.0; n <= 6; n++ {
			a := math.Pi / 2 * (corner[2] + (1-2*corner[2])*n/6)
			bracket = append(bracket, [2]float64{mx - 3.68 - 3.84*math.Sin(a), corner[0] + corner[1]*3.84*math.Cos(a)})
		}
	}
	c.polyline(append(bracket, [2]float64{mx + 1.92, my + 6.24}), 3.2, ink, 1)
	c.polyline([][2]float64{{mx - .16 + slip, my}, {mx + 8.16 + slip, my}}, 3.2, bar, 1)

	// Status pill at the right of the header.
	pill := trayBox{trayPanelWidth - 12 - 98, 22, 98, 24}
	c.fillBox(pill, 12, th.tile, 1)
	c.strokeBox(pill, 12, 1, th.line, 1)
	dot := th.faint
	if v.DPIOn || v.DPIBusy {
		dot = th.accent
		if th.dark {
			c.glow(pill.X+13, pill.Y+12, 0, 3.2, violet, .7)
		}
	}
	c.disc(pill.X+13, pill.Y+12, 3, dot, 1)

	for _, id := range []int{trayDPIButton, trayTelegramButton} {
		b := trayBoxes[id]
		on, busy := v.DPIOn, v.DPIBusy
		if id == trayTelegramButton {
			on, busy = v.TelegramOn, v.TelegramBusy
		}
		fill := th.tile
		if press.hover == id || press.pressed == id {
			fill = th.raised
		}
		c.fillBox(b, 18, fill, 1)
		if on {
			c.fillBox(b, 18, th.accent, .12)
			c.strokeBox(b, 18, 1, th.accent, .5)
		} else {
			c.strokeBox(b, 18, 1, th.line, 1)
		}
		if press.focus == id || press.pressed == id {
			c.strokeBox(b, 18, 1.5, th.accent, 1)
		}
		track := trayBox{b.X + b.W - 14 - 44, b.Y + (b.H-26)/2, 44, 26}
		tone, knob, kx := th.track, th.knob, track.X+13
		if on {
			tone, knob, kx = th.accent, trayHex(0xffffff), track.X+31
			if th.dark {
				c.glow(track.X+22, track.Y+13, 6, 9, violet, .34)
			}
		}
		if busy {
			tone = th.track.mix(th.accent, .5)
		}
		c.fillBox(track, 13, tone, 1)
		c.disc(kx, track.Y+13, 10, knob, 1)
	}

	b := trayBoxes[trayDiagnoseButton]
	fill := th.tile
	well := th.raised
	if press.hover == trayDiagnoseButton || press.pressed == trayDiagnoseButton {
		fill, well = th.raised, th.raised.mix(th.accent, .22)
	}
	c.fillBox(b, 18, fill, 1)
	c.strokeBox(b, 18, 1, th.line, 1)
	if press.focus == trayDiagnoseButton || press.pressed == trayDiagnoseButton {
		c.strokeBox(b, 18, 1.5, th.accent, 1)
	}
	ix, iy := b.X+25, b.Y+b.H/2
	c.disc(ix, iy, 15, well, 1)
	pulse := th.muted
	if v.Diagnosing {
		pulse = th.accent
	}
	c.polyline([][2]float64{{ix - 8, iy}, {ix - 4.5, iy}, {ix - 2, iy - 6}, {ix + 2, iy + 6}, {ix + 4.5, iy}, {ix + 8, iy}}, 1.5, pulse, 1)

	b = trayBoxes[trayOpenButton]
	fill = th.solid
	switch trayOpenButton {
	case press.pressed:
		fill = th.solid.mix(th.accent, .48)
	case press.hover:
		fill = th.solid.mix(th.accent, .26)
	}
	c.fillBox(b, 20, fill, 1)
	if press.focus == trayOpenButton {
		c.strokeBox(trayBox{b.X + 3, b.Y + 3, b.W - 6, b.H - 6}, 17, 1.5, th.accent, 1)
	}

	b = trayBoxes[trayExitButton]
	fill = th.tile
	if press.hover == trayExitButton || press.pressed == trayExitButton {
		fill = th.raised
	}
	c.fillBox(b, 20, fill, 1)
	c.strokeBox(b, 20, 1, th.line, 1)
	if press.focus == trayExitButton || press.pressed == trayExitButton {
		c.strokeBox(b, 20, 1.5, th.accent, 1)
	}
}

// trayLabel is one run of system text placed in panel units; Font indexes the
// popup fonts (0 title, 1 label, 2 detail).
type trayLabel struct {
	Text       string
	X, Y, W, H float64
	Font       int
	Tone       trayTone
	Center     bool
}

// trayLabels lists the text for the panel itself (id 0) or for one button.
func trayLabels(v trayView, id int, disabled bool) []trayLabel {
	th := trayThemeFor(v.Dark)
	b := trayBoxes[id]
	ink := th.ink
	if disabled {
		ink = th.muted
	}
	switch id {
	case 0:
		status, tone := "Выключен", th.muted
		switch {
		case v.DPIOn:
			status, tone = "Работает", th.ink
		case v.DPIBusy:
			status, tone = "Секунду…", th.ink
		}
		return []trayLabel{
			{Text: "evasion", X: 56, Y: 22, W: 110, H: 24, Font: 0, Tone: th.ink},
			{Text: status, X: trayPanelWidth - 12 - 98 + 22, Y: 22, W: 72, H: 24, Font: 2, Tone: tone},
		}
	case trayDPIButton, trayTelegramButton:
		label, detail := "Обход", v.DPI
		if id == trayTelegramButton {
			label, detail = "Telegram", v.Telegram
		}
		return []trayLabel{
			{Text: label, X: b.X + 16, Y: b.Y + 13, W: b.W - 86, H: 18, Font: 1, Tone: ink},
			{Text: detail, X: b.X + 16, Y: b.Y + 33, W: b.W - 86, H: 16, Font: 2, Tone: th.muted},
		}
	case trayDiagnoseButton:
		label := "Проверить связь"
		switch {
		case v.Diagnosing:
			label = "Проверяем связь…"
		case v.Error != "":
			// Error also holds failed connection/Telegram actions, not just diagnostics.
			// Keep the action honest and show the reason instead of a generic retry label.
			return []trayLabel{
				{Text: label, X: b.X + 50, Y: b.Y + 6, W: b.W - 62, H: 17, Font: 1, Tone: ink},
				{Text: v.Error, X: b.X + 50, Y: b.Y + 24, W: b.W - 62, H: 15, Font: 2, Tone: th.warning},
			}
		case v.ResultsReady:
			label = "Проверить ещё раз"
		}
		return []trayLabel{{Text: label, X: b.X + 50, Y: b.Y, W: b.W - 62, H: b.H, Font: 1, Tone: ink}}
	case trayOpenButton:
		label := "Открыть Evasion"
		if v.ResultsReady {
			label = "Результаты проверки"
		}
		return []trayLabel{{Text: label, X: b.X, Y: b.Y, W: b.W, H: b.H, Font: 1, Tone: th.solidInk, Center: true}}
	case trayExitButton:
		return []trayLabel{{Text: "Выход", X: b.X, Y: b.Y, W: b.W, H: b.H, Font: 1, Tone: th.muted, Center: true}}
	}
	return nil
}
