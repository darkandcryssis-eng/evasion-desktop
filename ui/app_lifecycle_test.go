package main

import (
	"strings"
	"testing"
	"time"
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

func TestStartTimings(t *testing.T) {
	got := startTimings(1200*time.Millisecond, 300*time.Millisecond, 40*time.Millisecond, 2500*time.Millisecond, true)
	if want := "Запуск: очистка 1200 мс, распаковка 300 мс, подготовка 40 мс, движок готов через 2500 мс"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got = startTimings(0, 0, 0, 30*time.Second, false); !strings.Contains(got, "движок не поднялся за 30000 мс") {
		t.Fatalf("got %q", got)
	}
}

func TestNoteIsNotAnError(t *testing.T) {
	m := newEngineManager()
	m.note("Запуск: проверка")
	if st := m.snapshot(); st.Error != "" || len(st.Logs) != 1 || st.Logs[0].Level != "INFO" {
		t.Fatalf("unexpected state: %+v", st)
	}
}
