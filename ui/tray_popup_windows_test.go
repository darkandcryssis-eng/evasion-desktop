//go:build windows

package main

import (
	"os"
	"sync"
	"testing"
	"time"
)

func TestTrayPopupSkipsQueuedRefreshWhenHidden(t *testing.T) {
	var calls int
	p := trayPopup{view: func() trayView { calls++; return trayView{} }}
	p.update()
	if calls != 0 {
		t.Fatal("hidden popup queried its view")
	}
	p.visible = true
	p.update()
	if calls != 1 {
		t.Fatal("visible popup did not query its view")
	}
}

// Native preview uses isolated actions: never starts an engine, proxy or service probe.
func TestNativeTrayPreview(t *testing.T) {
	if os.Getenv("EVASION_TRAY_PREVIEW") != "1" {
		t.Skip("opt-in native UI preview")
	}
	var mu sync.Mutex
	v := trayView{Dark: true, DPI: "Подключение выключено", Telegram: "Прокси выключен", Diagnostic: "Telegram и Discord · без входа в аккаунт"}
	if os.Getenv("EVASION_TRAY_LIGHT") == "1" {
		v.Dark = false
	}
	var toggle, refresh, hide, quit func()
	ready := make(chan struct{})
	done := make(chan struct{})
	view := func() trayView { mu.Lock(); defer mu.Unlock(); return v }
	action := func(kind string) {
		mu.Lock()
		switch kind {
		case "dpi":
			v.DPIOn = !v.DPIOn
			v.DPI = "Подключение выключено"
			if v.DPIOn {
				v.DPI = "Обход работает"
			}
		case "telegram":
			v.TelegramOn = !v.TelegramOn
			v.Telegram = "Прокси выключен"
			if v.TelegramOn {
				v.Telegram = "Есть обмен данными"
			}
		case "diagnose":
			v.ResultsReady = true
			v.Diagnostic = "Telegram отвечает · Discord: TLS"
		}
		mu.Unlock()
		if kind == "quit" {
			quit()
		} else if kind == "open" {
			hide()
		} else {
			refresh()
		}
	}
	startTrayPopup(view, action, func(a, b, c, d func()) { toggle, refresh, hide, quit = a, b, c, d; close(ready) }, func() { close(done) }, true)
	select {
	case <-ready:
	case <-done:
		t.Fatal("native popup creation failed")
	case <-time.After(5 * time.Second):
		t.Fatal("native popup creation timeout")
	}
	defer quit()
	toggle()
	deadline := time.NewTimer(3 * time.Minute)
	defer deadline.Stop()
	select {
	case <-done:
	case <-deadline.C:
	}
}
