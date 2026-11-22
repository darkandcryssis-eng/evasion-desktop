package main

import (
	"encoding/json"
	"image"
	"image/png"
	"os"
	"testing"
)

func trayPixel(c *trayCanvas, x, y float64) [3]byte {
	px, py := int(x*c.scale)-c.originX, int(y*c.scale)-c.origY
	i := (py*c.w + px) * 4
	return [3]byte{c.pix[i+2], c.pix[i+1], c.pix[i]}
}

func TestTrayPanelShowsState(t *testing.T) {
	off := newTrayCanvas(trayPanelWidth, trayPanelHeight, 0, 0, 1)
	paintTray(off, trayView{Dark: true}, trayPress{})
	on := newTrayCanvas(trayPanelWidth, trayPanelHeight, 0, 0, 1)
	paintTray(on, trayView{Dark: true, DPIOn: true}, trayPress{})

	// Toggle knob: left when off, right and white when on; Telegram stays off.
	b := trayBoxes[trayDPIButton]
	left, right, y := b.X+b.W-14-44+13, b.X+b.W-14-44+31, b.Y+b.H/2
	if got := trayPixel(on, right, y); got != [3]byte{255, 255, 255} {
		t.Fatalf("on knob = %v, want white", got)
	}
	if trayPixel(off, right, y) == trayPixel(on, right, y) || trayPixel(off, left, y) == trayPixel(on, left, y) {
		t.Fatal("toggle looks the same on and off")
	}
	tg := trayBoxes[trayTelegramButton]
	if trayPixel(off, right, tg.Y+tg.H/2) != trayPixel(on, right, tg.Y+tg.H/2) {
		t.Fatal("Telegram toggle changed with the bypass state")
	}
	// Connection state must not deform the selected ev ligature.
	for _, c := range []*trayCanvas{off, on} {
		if got := trayPixel(c, 23, 33); got != [3]byte{247, 247, 245} {
			t.Fatalf("ligature = %v, want off-white in both states", got)
		}
		if got := trayPixel(c, 23, 32); got != [3]byte{0, 0, 0} {
			t.Fatalf("ligature aperture = %v, want black", got)
		}
	}
}

// The layered surface: clear outside the round corners, opaque inside,
// partly covered on the curve, and a shadow below the panel at any scale.
func TestTraySurfaceEdges(t *testing.T) {
	for _, dpi := range []int{96, 120, 144, 192} {
		scale := float64(dpi) / 96
		m := (trayShadow*dpi + 48) / 96
		w, h := (trayPanelWidth*dpi+48)/96+2*m, (trayPanelHeight*dpi+48)/96+2*m
		c := newTrayCanvas(w, h, -m, -m, scale)
		paintTray(c, trayView{}, trayPress{})
		c.seal()
		alpha := func(x, y float64) byte {
			return c.pix[((int(y*scale)+m)*c.w+int(x*scale)+m)*4+3]
		}
		if a := alpha(-trayShadow+.5, -trayShadow+.5); a != 0 {
			t.Fatalf("dpi %d: window corner alpha = %d, want 0", dpi, a)
		}
		if a := alpha(1.5, 1.5); a > 40 {
			t.Fatalf("dpi %d: outside the round corner alpha = %d", dpi, a)
		}
		if a := alpha(trayPanelWidth/2, trayPanelHeight/2); a != 255 {
			t.Fatalf("dpi %d: panel alpha = %d, want 255", dpi, a)
		}
		if a := alpha(trayPanelWidth/2, trayPanelHeight+3); a < 30 || a > 140 {
			t.Fatalf("dpi %d: shadow alpha = %d", dpi, a)
		}
		soft := 0
		for i := 3; i < len(c.pix); i += 4 {
			if c.pix[i] > 100 && c.pix[i] < 250 {
				soft++
			}
			if c.pix[i-1] > c.pix[i] || c.pix[i-2] > c.pix[i] || c.pix[i-3] > c.pix[i] {
				t.Fatalf("dpi %d: colour above alpha at byte %d", dpi, i)
			}
		}
		if soft < 8 {
			t.Fatalf("dpi %d: no anti-aliased edge pixels", dpi)
		}
	}
}

// Every control answers the pointer, a press and keyboard focus with a visible change.
func TestTrayControlsShowFeedback(t *testing.T) {
	for _, dark := range []bool{true, false} {
		v := trayView{Dark: dark}
		paint := func(press trayPress) *trayCanvas {
			c := newTrayCanvas(trayPanelWidth, trayPanelHeight, 0, 0, 1)
			paintTray(c, v, press)
			return c
		}
		idle := string(paint(trayPress{}).pix)
		for id := range trayBoxes {
			for name, press := range map[string]trayPress{"hover": {hover: id}, "press": {hover: id, pressed: id}, "focus": {focus: id}} {
				if string(paint(press).pix) == idle {
					t.Fatalf("dark=%v control %d: %s looks idle", dark, id, name)
				}
			}
			if string(paint(trayPress{hover: id}).pix) == string(paint(trayPress{hover: id, pressed: id}).pix) {
				t.Fatalf("dark=%v control %d: press looks like hover", dark, id)
			}
		}
	}
}

func TestTrayLabelsFollowState(t *testing.T) {
	text := func(v trayView, id int) string { return trayLabels(v, id, false)[0].Text }
	if got := text(trayView{ResultsReady: true}, trayOpenButton); got != "Результаты проверки" {
		t.Fatalf("open label = %q", got)
	}
	if got := text(trayView{Diagnosing: true, Error: "x"}, trayDiagnoseButton); got != "Проверяем связь…" {
		t.Fatalf("diagnose label while busy = %q", got)
	}
	failed := trayLabels(trayView{Error: "Нет прав администратора"}, trayDiagnoseButton, false)
	if len(failed) != 2 || failed[0].Text != "Проверить связь" || failed[1].Text != "Нет прав администратора" {
		t.Fatalf("error labels = %+v", failed)
	}
	if got := trayLabels(trayView{DPIOn: true}, 0, false)[1].Text; got != "Работает" {
		t.Fatalf("status = %q", got)
	}
}

// Opt-in picture for design review: EVASION_TRAY_PNG=dir go test -run TestTrayPreviewPNG.
func TestTrayPreviewPNG(t *testing.T) {
	dir := os.Getenv("EVASION_TRAY_PNG")
	if dir == "" {
		t.Skip("opt-in tray picture")
	}
	views := map[string]trayView{
		"dark-off":  {Dark: true, DPI: "Подключение выключено", Telegram: "Прокси выключен"},
		"dark-on":   {Dark: true, DPIOn: true, TelegramOn: true, DPI: "Обход работает", Telegram: "Есть обмен данными", ResultsReady: true},
		"light-on":  {DPIOn: true, DPI: "Обход работает", Telegram: "Прокси выключен"},
		"dark-fail": {Dark: true, DPI: "Не удалось подключиться", Telegram: "Прокси выключен", Error: "WinDivert: драйвер не ответил"},
	}
	const scale = 2
	const m = trayShadow * scale
	for name, v := range views {
		c := newTrayCanvas(trayPanelWidth*scale+2*m, trayPanelHeight*scale+2*m, -m, -m, scale)
		press := trayPress{}
		if name == "dark-on" {
			press = trayPress{hover: trayExitButton, focus: trayTelegramButton}
		}
		paintTray(c, v, press)
		c.seal()
		img := image.NewRGBA(image.Rect(0, 0, c.w, c.h))
		for i := 0; i < len(c.pix); i += 4 {
			img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = c.pix[i+2], c.pix[i+1], c.pix[i], c.pix[i+3]
		}
		f, err := os.Create(dir + "/tray-" + name + ".png")
		if err != nil {
			t.Fatal(err)
		}
		if err := png.Encode(f, img); err != nil {
			t.Fatal(err)
		}
		f.Close()
		var labels []trayLabel
		for _, id := range []int{0, trayDPIButton, trayTelegramButton, trayDiagnoseButton, trayOpenButton, trayExitButton} {
			labels = append(labels, trayLabels(v, id, false)...)
		}
		data, _ := json.Marshal(labels)
		if err := os.WriteFile(dir+"/tray-"+name+".json", data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
