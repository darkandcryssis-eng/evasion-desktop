package main

import (
	"bytes"
	_ "embed"
	"image"
	"image/draw"
	"image/png"
)

// The transparent mask is rendered from assets/mark.svg by generate_icons.py.
//
//go:embed assets/mark.png
var trayBrandPNG []byte

var trayBrandMask = func() *image.Alpha {
	src, err := png.Decode(bytes.NewReader(trayBrandPNG))
	if err != nil {
		panic("invalid embedded Evasion mark: " + err.Error())
	}
	mask := image.NewAlpha(src.Bounds())
	draw.Draw(mask, mask.Bounds(), src, src.Bounds().Min, draw.Src)
	return mask
}()

// brandMark uses the same outline as the app icon, including on high-DPI trays.
func (c *trayCanvas) brandMark(b trayBox, ink trayTone) {
	w, h := float64(trayBrandMask.Bounds().Dx()), float64(trayBrandMask.Bounds().Dy())
	c.each(b.X, b.Y, b.X+b.W, b.Y+b.H, func(i int, x, y float64) {
		// Average subpixel coverage rather than aliasing a large mask at 32 px.
		alpha := 0.0
		for sy := 0; sy < 4; sy++ {
			for sx := 0; sx < 4; sx++ {
				px := int((x - b.X + (float64(sx)/4-.375)/c.scale) * w / b.W)
				py := int((y - b.Y + (float64(sy)/4-.375)/c.scale) * h / b.H)
				alpha += float64(trayBrandMask.AlphaAt(px, py).A)
			}
		}
		c.blend(i, ink, alpha/(16*255))
	})
}
