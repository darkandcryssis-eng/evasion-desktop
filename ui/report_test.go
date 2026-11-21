package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
