package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fitting-1c/evasion-ui/internal/tgproxy"
)

func TestLiveAppServiceReport(t *testing.T) {
	if os.Getenv("EVASION_SERVICES_LIVE") != "1" {
		t.Skip("opt-in public diagnostics")
	}
	a := NewApp()
	a.ctx = context.Background()
	results, err := a.RunServiceDiagnostics()
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 4 {
		t.Fatalf("got %d service results", len(results))
	}
	for _, result := range results {
		t.Logf("%s: %s", result.ID, result.Summary)
	}
	if path := os.Getenv("EVASION_REPORT_PATH"); path != "" {
		if err := writeReport(path, buildSafeReport("stopped", a.GetTelegramState(), results, a.GetTelegramRoutes())); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReportNeverCopiesSensitiveText(t *testing.T) {
	secret := "PRIVATE-TOKEN-42"
	r := buildSafeReport(secret, TelegramState{Link: "tg://proxy?secret=" + secret, Address: secret, Error: secret, Route: secret, Logs: []LogLine{{Msg: secret, Attrs: secret}}, Speeds: []SpeedSample{{At: secret, Up: 2, Down: 3}}}, []ServiceDiagnostic{{ID: "telegram", Name: secret, Summary: secret, Advice: secret, CheckedAt: secret, Status: secret, Steps: []ServiceStep{{ID: secret, Code: secret, Detail: secret, Advice: secret}}}}, []TelegramRoute{{ID: secret, Host: secret, Kind: secret, Status: secret, CheckedAt: secret}})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{secret, "tg://", "secret=", "logs", "configPath", "address", "link"} {
		if strings.Contains(string(b), value) {
			t.Fatalf("report contains %q", value)
		}
	}
}

func TestReportPreservesUsefulAllowlistedData(t *testing.T) {
	stamp := "2026-11-11T12:30:00Z"
	r := buildSafeReport("running", TelegramState{BytesDown: 4096}, []ServiceDiagnostic{{ID: "discord-api", Status: "fail", CheckedAt: stamp, Steps: []ServiceStep{{ID: "https", Status: "fail", Code: "http_403", MS: 82}}}}, []TelegramRoute{{Kind: "Резерв WSS", Status: "verified", LatencyMS: 123}})
	if r.EnginePhase != "running" || r.Telegram.BytesDown != 4096 || r.Services[0].Steps[0].Code != "http_403" || r.Routes[0].LatencyMS != 123 {
		t.Fatal("diagnostic data lost")
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := writeReport(path, r); err != nil {
		t.Fatal(err)
	}
	if err := writeReport(path, r); err != nil {
		t.Fatal("replace report:", err)
	}
	b, err := os.ReadFile(path)
	if err != nil || !json.Valid(b) {
		t.Fatal("invalid report", err)
	}
}

func TestReportPreservesMediaDeliveryWithoutRouteAddresses(t *testing.T) {
	r := buildSafeReport("running", TelegramState{Disconnects: []TelegramDisconnect{
		{DC: 2, Media: true, Stage: "relay_read", Transport: "relay_ws", BytesDown: 8192},
	}}, nil, routeViews([]tgproxy.RouteStatus{
		{ID: "private-host", Host: "private-host", DC: 2, Media: true, DownBPS: 524288, Kind: "Резерв WS · медиа"},
	}))
	if route := r.Routes[0]; route.DC != 2 || !route.Media || route.DownBPS != 524288 || route.Transport != "Резерв WS" {
		t.Fatalf("lost media route data: %+v", route)
	}
	if r.Telegram.Disconnects[0].BytesDown != 8192 {
		t.Fatal("lost disconnect delivery bytes")
	}
	b, err := json.Marshal(r)
	if err != nil || strings.Contains(string(b), "private-host") {
		t.Fatalf("unsafe diagnostic report: err=%v", err)
	}
}

func TestReportKeepsRecentDisconnectsAndSafeRecoveryReason(t *testing.T) {
	disconnects := make([]TelegramDisconnect, 51)
	disconnects[0].DC = 5
	disconnects[1].RecoveryFailure = "private-detail"
	disconnects[50] = TelegramDisconnect{DC: 2, RecoveryFailure: "partial_frame"}
	r := buildSafeReport("running", TelegramState{Disconnects: disconnects}, nil, nil)
	got := r.Telegram.Disconnects
	if len(got) != 50 || got[0].DC == 5 || got[0].RecoveryFailure != "" ||
		got[49].DC != 2 || got[49].RecoveryFailure != "partial_frame" {
		t.Fatalf("incorrect disconnect selection or sanitization: count=%d first=%+v last=%+v", len(got), got[0], got[len(got)-1])
	}
	if safeBuild("419EBC68ED30") != "419ebc68ed30" || safeBuild("private-data") != "" {
		t.Fatal("report build ID was not sanitized")
	}
}

func TestGameReportPreservesObservationAndSanitizesStage(t *testing.T) {
	v := GameFilterView{Adaptive: GameAdaptiveState{Stage: "balanced", Helping: 1, Responsive: 2}}
	r := safeGameReport(v)
	if r.Observation.Stage != "balanced" || r.Observation.Helping != 1 || r.Observation.Responsive != 2 {
		t.Fatal(r)
	}
	v.Adaptive = GameAdaptiveState{Stage: "PRIVATE-TOKEN", Watching: -1, Helping: 99999}
	r = safeGameReport(v)
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "PRIVATE-TOKEN") || r.Observation.Helping != 8192 || r.Observation.Watching != 0 {
		t.Fatal(string(b))
	}
}

func TestGameReportPreservesTransportWithoutFreeText(t *testing.T) {
	v := GameFilterView{Transport: GameTransportState{Stage: "tls_unanswered", NoTLSReply: 2}, Stats: GameFilterStats{Tunnel: true, TunnelReceived: 1234}}
	r := safeGameReport(v)
	if r.Transport.Stage != "tls_unanswered" || r.Transport.NoTLSReply != 2 || !r.Stats.Tunnel || r.Stats.TunnelReceived != 1234 {
		t.Fatal(r)
	}
	v.Transport = GameTransportState{Stage: "PRIVATE-TOKEN", Connecting: -1, NoTCPReply: 99999}
	r = safeGameReport(v)
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "PRIVATE-TOKEN") || r.Transport.Connecting != 0 || r.Transport.NoTCPReply != 8192 {
		t.Fatal("unsafe transport report")
	}
}

func TestReportContext(t *testing.T) {
	if v := safeVersion("v0.1.3"); v != "0.1.3" {
		t.Errorf("версия: %q", v)
	}
	if v := safeVersion("PRIVATE"); v != "dev" {
		t.Errorf("мусор в версии: %q", v)
	}
	e := safeEngineReport(EngineState{Options: StartOptions{Voice: "badsum", Quic: "PRIVATE"}, Restarts: 2, Hello: &HelloStats{Complete: 5, Skipped: 1, Reasons: "PRIVATE"}})
	if e.Voice != "badsum" || e.Quic != "unknown" || e.Restarts != 2 || e.Complete != 5 || e.Skipped != 1 {
		t.Errorf("движок: %+v", e)
	}
	c := safeConflicts(conflictReport{Stopped: []string{"служба zapret", "winws.exe", "устаревшая запись драйвера WinDivert", "служба PRIVATE"}, Failed: []string{"GoodbyeDPI.exe"}})
	want := []string{"service:zapret", "winws.exe", "windivert-stale", "service:other"}
	if !slices.Equal(c.Stopped, want) || !slices.Equal(c.Failed, []string{"goodbyedpi.exe"}) {
		t.Errorf("конфликты: %+v", c)
	}
}

func TestTelegramCallDiagnosticsAreSeparateFromProxyAndPrivate(t *testing.T) {
	engine := &engineManager{phase: phaseRunning}
	engine.consumeLogLine(`{"time":"2026-11-27T02:07:20Z","level":"INFO","msg":"telegram_call_diagnostics","stun":5,"dtls":2,"legacy":-1,"directReplies":0,"relayActive":true,"relayAttempts":2,"relayFailures":1,"relayTx":7,"relayRx":2,"peer":"203.0.113.9:443","error":"PRIVATE"}`)
	state := engine.snapshot()
	report := buildSafeReport(state.Phase, TelegramState{}, nil, nil)
	report.TelegramCalls = state.telegramCalls
	stats := report.TelegramCalls
	if stats == nil || stats.STUN != 5 || stats.DTLS != 2 || stats.Legacy != 0 || stats.DirectReplies != 0 ||
		stats.RelayAttempts != 2 || stats.RelayFailures != 1 || !stats.RelayActive || stats.RelayTX != 7 || stats.RelayRX != 2 ||
		stats.LastChange != "2026-11-27T02:07:20Z" || report.Telegram.Running {
		t.Fatalf("unexpected Telegram call report: %+v", stats)
	}
	b, err := json.Marshal(report)
	if err != nil || strings.Contains(string(b), "203.0.113.9") || strings.Contains(string(b), "PRIVATE") || len(state.Logs) != 0 {
		t.Fatalf("private telemetry leaked into report or journal: %s, %v", b, err)
	}
	engine.phase = phaseStopped
	if engine.snapshot().telegramCalls != nil {
		t.Fatal("stopped engine reported stale call statistics")
	}
}
