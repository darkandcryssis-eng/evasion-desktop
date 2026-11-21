package main

import (
	"strings"
	"testing"
)

func TestTrayPanelFitsMonitorWorkArea(t *testing.T) {
	for _, tt := range []struct {
		name string
		x, y int32
		work trayRect
	}{
		{"bottom-right", 1910, 1040, trayRect{0, 0, 1920, 1040}},
		{"left-monitor", -1910, 1040, trayRect{-1920, 0, 0, 1040}},
		{"top-taskbar", 950, 40, trayRect{0, 40, 1920, 1080}},
		{"small-display", 100, 200, trayRect{0, 0, 320, 400}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := placeTrayPanel(tt.x, tt.y, 352, 348, 10, tt.work)
			if r.Left < tt.work.Left || r.Top < tt.work.Top || r.Right > tt.work.Right || r.Bottom > tt.work.Bottom || r.Right <= r.Left || r.Bottom <= r.Top {
				t.Fatalf("invalid bounds %+v", r)
			}
		})
	}
}

func TestTrayPreferencesValidateAndRefresh(t *testing.T) {
	a := NewApp()
	refreshes := 0
	a.tray.refresh = func() { refreshes++ }
	opts := StartOptions{Voice: "off", Quic: "block", Observe: true}
	if err := a.SetTrayPreferences("black", opts, "sakura"); err != nil {
		t.Fatal(err)
	}
	if !a.tray.dark || a.tray.options != opts || refreshes != 1 {
		t.Fatal("preferences not applied")
	}
	if err := a.SetTrayPreferences("invalid", opts, ""); err == nil {
		t.Fatal("invalid theme accepted")
	}
	if err := a.SetTrayPreferences("light", StartOptions{}, ""); err == nil {
		t.Fatal("invalid options accepted")
	}
}

func TestTrayCloseBeforeNativeWindowIsReady(t *testing.T) {
	c := newTrayControl()
	c.close()
	closed := false
	c.attach(func() { t.Error("closed popup opened") }, func() {}, func() {}, func() { closed = true })
	if !closed || c.show() {
		t.Fatal("late native window did not close")
	}
	c.detach()
}

func TestTrayDiagnosticsKeepFailureStage(t *testing.T) {
	result := trayDiagnosticSummary([]ServiceDiagnostic{{ID: "telegram", Status: "ok"}, {ID: "discord-api", Status: "fail", Steps: []ServiceStep{{ID: "dns", Status: "ok"}, {ID: "tls", Status: "fail"}}}, {ID: "discord-gateway", Status: "ok"}})
	if !strings.Contains(result, "Telegram отвечает") || !strings.Contains(result, "Discord: TLS") {
		t.Fatal(result)
	}
}

func TestMissingTrayDiagnosticsAreNotReportedAsHealthy(t *testing.T) {
	if strings.Contains(trayDiagnosticSummary(nil), "отвечает") {
		t.Fatal("missing results reported as healthy")
	}
}
