package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGameSettingsDefaultAndCorruptFallback(t *testing.T) {
	dir := t.TempDir()
	s, err := readGameSettings(dir)
	if err != nil || s.Mode != "off" || len(gameArgs(s)) != 0 {
		t.Fatal("games changed baseline by default", s, err)
	}
	path := filepath.Join(dir, "game-filter.json")
	for _, text := range []string{`{`, `{"mode":"bad"}`} {
		os.WriteFile(path, []byte(text), 0600)
		s, err = readGameSettings(dir)
		if err == nil || s.Mode != "off" {
			t.Fatal("invalid settings not isolated", text, s, err)
		}
	}
	os.WriteFile(path, []byte(`{"mode":"auto","albion":true,"ubisoft":true,"executables":[]}`), 0600)
	s, err = readGameSettings(dir)
	if err != nil || s.Mode != "off" {
		t.Fatal("settings with built-in games only must load switched off", s, err)
	}
	os.WriteFile(path, []byte(`{"executables":null}`), 0600)
	s, err = readGameSettings(dir)
	if err != nil || s.Executables == nil {
		t.Fatal("nullable paths break frontend", s, err)
	}
}
func TestGameSettingsRoundTripAndSafeArguments(t *testing.T) {
	dir := t.TempDir()
	s := defaultGameSettings()
	s.Mode = "strong"
	s.Protocol = "udp"
	s.Executables = []string{filepath.Join(dir, "Игра с пробелом & знаком.exe")}
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	os.WriteFile(filepath.Join(dir, "game-filter.json"), b, 0600)
	loaded, err := readGameSettings(dir)
	if err != nil || !reflect.DeepEqual(s, loaded) {
		t.Fatal("settings lost", loaded, err)
	}
	args := gameArgs(loaded)
	if args[len(args)-2] != "--game-exe" || args[len(args)-1] != s.Executables[0] {
		t.Fatal("executable path split or shell quoted", args)
	}
	loaded.Executables = []string{filepath.Join(dir, "svchost.exe")}
	if loaded.validate() == nil {
		t.Fatal("system process accepted")
	}
}
func TestGameApplyLifecycleGuards(t *testing.T) {
	for _, phase := range []string{phaseStarting, phaseStopping} {
		a := NewApp()
		a.games.phase = phase
		if a.ApplyGameFilter(StartOptions{Voice: "off", Quic: "off"}) == nil {
			t.Fatal("transition interrupted")
		}
	}
	a := NewApp()
	a.tuner.busy = true
	if a.ApplyGameFilter(StartOptions{Voice: "off", Quic: "off"}) == nil {
		t.Fatal("tuning interrupted")
	}
}

func TestGameAndGeneralManagersAreIndependent(t *testing.T) {
	a := NewApp()
	if a.games == a.engine {
		t.Fatal("shared manager")
	}
	a.games.phase = phaseRunning
	if a.engine.snapshot().Phase != phaseStopped {
		t.Fatal("game started general bypass")
	}
	a.engine.phase = phaseRunning
	a.games.phase = phaseStopped
	if a.engine.snapshot().Phase != phaseRunning {
		t.Fatal("stopping game stopped general bypass")
	}
}

func TestAutomaticModeSettingsAndArguments(t *testing.T) {
	s := defaultGameSettings()
	s.Mode = "auto"
	if s.validate() == nil {
		t.Fatal("game mode accepted without an added game")
	}
	s.Executables = []string{filepath.Join(t.TempDir(), "game.exe")}
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	args := gameArgs(s)
	found := false
	for i := range args {
		if args[i] == "--game-mode" && i+1 < len(args) && args[i+1] == "auto" {
			found = true
		}
	}
	if !found {
		t.Fatal(args)
	}
}
