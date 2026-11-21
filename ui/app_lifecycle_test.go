package main

import (
	"strings"
	"testing"
)

func TestStartRejectsActiveEngineBeforeCleanup(t *testing.T) {
	for _, phase := range []string{phaseStarting, phaseRunning, phaseStopping} {
		t.Run(phase, func(t *testing.T) {
			a := NewApp()
			a.engine.phase = phase
			err := a.StartEngine(StartOptions{Voice: "ttl", Quic: "off"})
			if err == nil || !strings.Contains(err.Error(), "уже запущен") {
				t.Fatalf("active engine should be rejected before system actions: %v", err)
			}
			if a.engine.snapshot().Phase != phase {
				t.Fatal("existing engine state changed")
			}
		})
	}
}

func TestStartRejectsInvalidOptionsBeforeSystemActions(t *testing.T) {
	a := NewApp()
	if err := a.StartEngine(StartOptions{Voice: "invalid", Quic: "off"}); err == nil || !strings.Contains(err.Error(), "режим голоса") {
		t.Fatalf("invalid voice should be rejected: %v", err)
	}
}
