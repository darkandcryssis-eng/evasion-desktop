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
	// The mark holds its centre dot only while the bypass runs.
	if got := trayPixel(on, 30, 34); got != [3]byte{255, 255, 255} {
		t.Fatalf("lit mark centre = %v, want white", got)
	}
	if got := trayPixel(off, 30, 34); got != [3]byte{0, 0, 0} {
		t.Fatalf("idle mark centre = %v, want black", got)
	}
}

// A button canvas must show exactly its part of the panel at any scale,
// otherwise seams appear between the panel and its child windows.
func TestTrayButtonMatchesPanel(t *testing.T) {
	for _, dpi := range []int{96, 120, 144, 192} {
		scale := float64(dpi) / 96
		px := func(v float64) int { return (int(v)*dpi + 48) / 96 }
		v := trayView{Dark: true, DPIOn: true, TelegramBusy: true}
		panel := newTrayCanvas(px(trayPanelWidth), px(trayPanelHeight), 0, 0, scale)
		paintTray(panel, v, trayPress{})
		for id, b := range trayBoxes {
			x0, y0 := px(b.X), px(b.Y)
			w, h := px(b.X+b.W)-x0, px(b.Y+b.H)-y0
			button := newTrayCanvas(w, h, x0, y0, scale)
			paintTray(button, v, trayPress{})
			for y := 0; y < h; y++ {
				for x := 0; x < w; x++ {
					i, j := (y*w+x)*4, ((y+y0)*panel.w+x+x0)*4
					if button.pix[i] != panel.pix[j] || button.pix[i+1] != panel.pix[j+1] || button.pix[i+2] != panel.pix[j+2] {
						t.Fatalf("dpi %d button %d differs from the panel at %d,%d", dpi, id, x, y)
					}
				}
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
	for name, v := range views {
		c := newTrayCanvas(trayPanelWidth*scale, trayPanelHeight*scale, 0, 0, scale)
		paintTray(c, v, trayPress{})
		img := image.NewNRGBA(image.Rect(0, 0, c.w, c.h))
		for i := 0; i < len(c.pix); i += 4 {
			img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = c.pix[i+2], c.pix[i+1], c.pix[i], 255
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
