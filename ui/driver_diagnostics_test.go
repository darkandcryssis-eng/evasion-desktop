package main

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestDriverDiagnosisDistinguishesLoadedFromDisabled(t *testing.T) {
	cases := []struct {
		name    string
		service driverService
		code    uint32
		status  string
		want    uint32
	}{
		{"loaded", driverService{ID: "windivert", State: "running", Start: "demand"}, 0, "ok", 0},
		{"loaded marked for cleanup is normal", driverService{ID: "windivert", State: "running", Start: "disabled", PendingDeletion: true}, 0, "ok", 0},
		{"stale deletion", driverService{ID: "windivert", State: "stopped", Start: "disabled", PendingDeletion: true}, 0, "warn", 1072},
		{"disabled", driverService{ID: "windivert", State: "stopped", Start: "disabled"}, 0, "warn", 1058},
		{"failure overrides files", driverService{ID: "windivert", State: "missing"}, 1058, "warn", 1058},
		{"bfe stopped", driverService{ID: "bfe", State: "stopped", Start: "demand"}, 0, "warn", 0},
		{"first launch", driverService{ID: "windivert", State: "missing"}, 0, "unknown", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := summarizeDriver([]driverService{tc.service}, tc.code)
			if d.Status != tc.status || d.Code != tc.want {
				t.Fatal(d)
			}
		})
	}
}
func TestDriverAndGameReportAllowlist(t *testing.T) {
	secret := "PRIVATE-TOKEN-42"
	d := driverDiagnostic{Status: secret, Summary: secret, Advice: secret, Code: 99999, Services: []driverService{{ID: secret, State: secret}, {ID: "windivert", State: secret, Start: secret, Code: 99999}, {ID: "battleye", State: "running", Start: "demand"}}}
	r := buildSafeReport("failed", TelegramState{}, nil, nil, d)
	r.Games = safeGameReport(GameFilterView{Error: secret, Settings: GameFilterSettings{Executables: []string{secret}}, ActiveMode: secret, ActiveProtocol: secret, Processes: []GameProcessState{{Family: secret}, {Family: "custom", Clients: -1}}})
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), secret) || strings.Contains(string(b), "99999") {
		t.Fatal(string(b))
	}
	if r.Driver.Services[1].ID != "battleye" || r.Games.Processes[0].Clients != 0 {
		t.Fatal(r)
	}
}
func TestDriverCodeOnlyUsesTypedMessage(t *testing.T) {
	for _, text := range []string{"WinDivert — код 1058.", "Движок: WinDivert — код 1058. Ошибка"} {
		if driverCode(text) != 1058 {
			t.Fatal(text)
		}
	}
	if driverCode("arbitrary/path/1058") != 0 {
		t.Fatal("arbitrary number classified as driver")
	}
}
func TestStartupFailureDoesNotReportReady(t *testing.T) {
	m := newEngineManager()
	m.phase = phaseFailed
	m.lastErr = "WinDivert — код 1058."
	m.ready = make(chan struct{})
	close(m.ready)
	if err := m.awaitStartup(); err == nil || !strings.Contains(err.Error(), "1058") {
		t.Fatal(err)
	}
	if m.snapshot().Phase == phaseRunning {
		t.Fatal("failed engine reported running")
	}
}
func TestStartupAcknowledgementSucceeds(t *testing.T) {
	m := newEngineManager()
	m.phase = phaseStarting
	m.ready = make(chan struct{})
	m.readStdout(strings.NewReader(`{"filter":"selected games","quic_mode":"off"}`))
	if err := m.awaitStartup(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeReadOnlyDriverFacts(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows service API")
	}
	facts := readDriverServices()
	seen := map[string]bool{}
	for _, s := range facts {
		seen[s.ID] = true
	}
	if !seen["windivert"] || !seen["bfe"] || !seen["battleye"] {
		t.Fatal("incomplete service diagnosis", facts)
	}
	d := summarizeDriver(facts, 0)
	b, _ := json.Marshal(safeDriverReport(d))
	t.Log(string(b))
}
