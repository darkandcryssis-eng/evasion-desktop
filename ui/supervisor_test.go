package main

import (
	"testing"
	"time"
)

func TestReviveDecision(t *testing.T) {
	now := time.Unix(100000, 0)
	if revive, wait, _ := reviveDecision(now, now.Add(-time.Second), nil); revive || !wait {
		t.Fatal("сразу после падения нужно подождать")
	}
	if revive, wait, _ := reviveDecision(now, now.Add(-reviveDelay), nil); !revive || wait {
		t.Fatal("после паузы движок нужно поднять")
	}
	hist := []time.Time{now.Add(-time.Minute), now.Add(-2 * time.Minute), now.Add(-3 * time.Minute)}
	if revive, wait, recent := reviveDecision(now, now.Add(-time.Minute), hist); revive || wait || len(recent) != 3 {
		t.Fatal("при трёх подъёмах за окно сторож должен остановиться")
	}
	old := []time.Time{now.Add(-reviveWindow - time.Second), now.Add(-time.Minute)}
	if revive, _, recent := reviveDecision(now, now.Add(-time.Minute), old); !revive || len(recent) != 1 {
		t.Fatal("старые подъёмы не должны учитываться")
	}
}

func TestEngineManagerCrashBookkeeping(t *testing.T) {
	m := newEngineManager()
	if _, _, ok := m.crashInfo(); ok {
		t.Fatal("остановленный движок не ждёт подъёма")
	}
	m.phase, m.crashedAt = phaseFailed, time.Now()
	if _, _, ok := m.crashInfo(); !ok {
		t.Fatal("упавший во время работы движок должен ждать подъёма")
	}
	m.noteRevived()
	if st := m.snapshot(); st.Restarts != 1 || st.Guard == "" {
		t.Fatalf("snapshot=%+v", st)
	}
	_ = m.stop()
	if _, _, ok := m.crashInfo(); ok {
		t.Fatal("ручная остановка отменяет автоподъём")
	}
	m.crashedAt = time.Now()
	m.giveUp("стоп")
	if _, _, ok := m.crashInfo(); ok || m.snapshot().Guard != "стоп" {
		t.Fatal("giveUp должен снимать ожидание")
	}
}
