package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProfileCommitRollsBackOnFailureAndCancellation(t *testing.T) {
	network := strings.Repeat("a", 64)
	p := youtubeProfile{Schema: 1, Network: network, Profile: "split", QUIC: "block", Verified: true, At: time.Now()}
	for _, exists := range []bool{false, true} {
		dir := t.TempDir()
		path := profilePath(dir, network)
		old := []byte(`{"profile":"current"}`)
		if exists {
			os.WriteFile(path, old, 0600)
		}
		os.Mkdir(filepath.Join(dir, "network-settings.json"), 0700)
		if commitYouTubeProfile(context.Background(), dir, p) == nil {
			t.Fatal("write failure ignored")
		}
		b, err := os.ReadFile(path)
		if exists && (err != nil || !bytes.Equal(b, old)) {
			t.Fatal("previous profile not restored")
		}
		if !exists && !os.IsNotExist(err) {
			t.Fatal("failed new profile retained")
		}
	}
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if commitYouTubeProfile(ctx, dir, p) == nil {
		t.Fatal("cancel ignored")
	}
	if _, err := os.Stat(profilePath(dir, network)); !os.IsNotExist(err) {
		t.Fatal("canceled profile written")
	}
	os.WriteFile(filepath.Join(dir, "network-settings.json"), []byte(`{"telegram":false}`), 0600)
	if err := commitYouTubeProfile(context.Background(), dir, p); err != nil {
		t.Fatal(err)
	}
	s := readTuningSettings(dir)
	if !s.YouTube || s.Telegram {
		t.Fatal("settings not preserved", s)
	}
}

func TestProfileValidationAndExpiry(t *testing.T) {
	netkey, hash := strings.Repeat("a", 64), strings.Repeat("b", 64)
	now := time.Now()
	good := youtubeProfile{Schema: 1, Network: netkey, Config: hash, Profile: "split", QUIC: "desync", At: now, Verified: true}
	if !validYouTubeProfile(good, netkey, hash, now) {
		t.Fatal("valid profile rejected")
	}
	for _, tc := range []struct {
		name   string
		change func(*youtubeProfile)
	}{
		{"old", func(p *youtubeProfile) { p.At = now.Add(-7 * time.Hour) }},
		{"future", func(p *youtubeProfile) { p.At = now.Add(2 * time.Minute) }},
		{"network", func(p *youtubeProfile) { p.Network = strings.Repeat("c", 64) }},
		{"config", func(p *youtubeProfile) { p.Config = strings.Repeat("c", 64) }},
		{"unchecked", func(p *youtubeProfile) { p.Verified = false }},
		{"profile", func(p *youtubeProfile) { p.Profile = "../../other" }},
		{"mode", func(p *youtubeProfile) { p.QUIC = "unknown" }},
		{"schema", func(p *youtubeProfile) { p.Schema = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := good
			tc.change(&p)
			if validYouTubeProfile(p, netkey, hash, now) {
				t.Fatal("invalid profile accepted")
			}
		})
	}
	base := t.TempDir()
	b, _ := json.Marshal(good)
	os.WriteFile(profilePath(base, netkey), b, 0600)
	if _, ok := readYouTubeProfile(base, netkey, hash); !ok {
		t.Fatal("valid persisted profile rejected")
	}
	os.WriteFile(profilePath(base, netkey), []byte("{"), 0600)
	if _, ok := readYouTubeProfile(base, netkey, hash); ok {
		t.Fatal("corrupt profile accepted")
	}
}

func TestSettingsDefaultsAndConfigHash(t *testing.T) {
	dir := t.TempDir()
	if s := readTuningSettings(dir); s.YouTube || !s.Telegram {
		t.Fatal(s)
	}
	os.WriteFile(filepath.Join(dir, "network-settings.json"), []byte(`{"youtube":true,"telegram":false}`), 0600)
	if s := readTuningSettings(dir); !s.YouTube || s.Telegram {
		t.Fatal(s)
	}
	os.WriteFile(filepath.Join(dir, "network-settings.json"), []byte("{"), 0600)
	if s := readTuningSettings(dir); s.YouTube || !s.Telegram {
		t.Fatal(s)
	}
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{"groups":{}}`), 0600)
	a := tuningConfigHash(path, StartOptions{Quic: "off"})
	b := tuningConfigHash(path, StartOptions{Quic: "block"})
	if a == b || len(a) != 64 {
		t.Fatal("QUIC not included in identity")
	}
	os.WriteFile(path, []byte(`{"groups":{"video":[]}}`), 0600)
	if a == tuningConfigHash(path, StartOptions{Quic: "off"}) {
		t.Fatal("config change ignored")
	}
	if fingerprintParts([]string{"b", "a"}) != fingerprintParts([]string{"a", "b"}) || fingerprintParts(nil) != "" {
		t.Fatal("unstable network identity")
	}
}

func TestTuningLifecycleGuards(t *testing.T) {
	a := NewApp()
	a.tuner.busy = true
	opts := StartOptions{Voice: "off", Quic: "off"}
	if err := a.StartEngine(opts); err == nil || !strings.Contains(err.Error(), "подбора") {
		t.Fatal("start did not guard tuner", err)
	}
	if err := a.SetNetworkTuningSettings(true, true); err == nil {
		t.Fatal("settings changed during tuning")
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.tuner.cancel = cancel
	a.CancelYouTubeTuning()
	if ctx.Err() == nil {
		t.Fatal("cancel not delivered")
	}
	a.tuner.busy = false
	a.engine.phase = phaseRunning
	if err := a.RunYouTubeTuning(opts); err == nil {
		t.Fatal("tuned while running")
	}
	if a.tuner.busy {
		t.Fatal("failed guard left busy flag")
	}
}
