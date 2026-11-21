package quicwatch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestQUICOnlyDetection — ядро эвристики: подозрителен тот, у кого сбросов
// хватает и TCP-отката после них не было (нет вовсе либо он раньше сброса).
func TestQUICOnlyDetection(t *testing.T) {
	p := DefaultParams() // MinDrops=3, FallbackGrace=2с
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

	rep := Report{SNIs: []SNIStat{
		// Откат не наблюдался вовсе — подозрителен.
		{SNI: "quiconly.example", Drops: 5, LastDrop: t0},
		// Откат состоялся (TCP-хелло позже сброса на зазор) — не подозрителен.
		{SNI: "fallback.example", Drops: 5, LastDrop: t0, LastTCPHello: t0.Add(3 * time.Second)},
		// Сбросов мало — судить рано, не подозрителен.
		{SNI: "rare.example", Drops: 1, LastDrop: t0},
		// TCP-хелло раньше последнего сброса — откат не состоялся, подозрителен.
		{SNI: "regressed.example", Drops: 4, LastDrop: t0, LastTCPHello: t0.Add(-time.Minute)},
	}}

	got := rep.QUICOnly(p)
	want := []string{"quiconly.example", "regressed.example"}
	if len(got) != len(want) {
		t.Fatalf("ожидалось %v, получено %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] { // результат обязан быть отсортирован
			t.Errorf("позиция %d: ожидалось %q, получено %q", i, want[i], got[i])
		}
	}
}

// TestFallbackGraceBoundary — TCP-хелло в пределах зазора откатом не считается,
// строго за зазором — считается.
func TestFallbackGraceBoundary(t *testing.T) {
	p := Params{MinDrops: 1, FallbackGrace: 2 * time.Second}
	drop := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

	within := Report{SNIs: []SNIStat{{SNI: "a", Drops: 1, LastDrop: drop, LastTCPHello: drop.Add(2 * time.Second)}}}
	if len(within.QUICOnly(p)) != 1 {
		t.Errorf("хелло ровно на границе зазора откатом считаться не должен")
	}
	beyond := Report{SNIs: []SNIStat{{SNI: "a", Drops: 1, LastDrop: drop, LastTCPHello: drop.Add(2*time.Second + time.Millisecond)}}}
	if len(beyond.QUICOnly(p)) != 0 {
		t.Errorf("хелло строго за зазором — откат состоялся, подозрения быть не должно")
	}
}

// TestTrackerAccumulatesAndFallback — счётчик копит сбросы, а TCP-хелло снимает
// подозрение.
func TestTrackerAccumulatesAndFallback(t *testing.T) {
	tr := NewTracker()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

	tr.BlockedQUIC("youtube.com", t0)
	tr.BlockedQUIC("youtube.com", t0.Add(time.Second))
	tr.BlockedQUIC("youtube.com", t0.Add(2*time.Second))

	rep := tr.Snapshot(t0.Add(3 * time.Second))
	if only := rep.QUICOnly(DefaultParams()); len(only) != 1 || only[0] != "youtube.com" {
		t.Fatalf("после трёх сбросов без отката ожидался QUIC-only youtube.com, получено %v", only)
	}

	// TCP-откат после сбросов снимает подозрение.
	tr.SawTCPHello("youtube.com", t0.Add(5*time.Second))
	rep = tr.Snapshot(t0.Add(6 * time.Second))
	if only := rep.QUICOnly(DefaultParams()); len(only) != 0 {
		t.Errorf("после TCP-отката подозрения быть не должно, получено %v", only)
	}
}

// TestSawTCPHelloIgnoresUnknown — TCP-хелло по имени без сброса QUIC записи не
// заводит: память ограничена именами, к которым QUIC блокировался.
func TestSawTCPHelloIgnoresUnknown(t *testing.T) {
	tr := NewTracker()
	t0 := time.Now()
	tr.SawTCPHello("example.com", t0)
	if rep := tr.Snapshot(t0); len(rep.SNIs) != 0 {
		t.Errorf("имя без сброса QUIC в снимок попадать не должно, получено %v", rep.SNIs)
	}
}

// TestSnapshotPrunesStale — запись без активности дольше pruneTTL удаляется.
func TestSnapshotPrunesStale(t *testing.T) {
	tr := NewTracker()
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	tr.BlockedQUIC("old.example", t0)

	if rep := tr.Snapshot(t0.Add(pruneTTL + time.Minute)); len(rep.SNIs) != 0 {
		t.Errorf("стухшая запись должна удаляться, получено %v", rep.SNIs)
	}
	// И повторный снимок её уже не видит.
	if rep := tr.Snapshot(t0.Add(pruneTTL + 2*time.Minute)); len(rep.SNIs) != 0 {
		t.Errorf("удалённая запись не должна возвращаться")
	}
}

// TestWriteReadRoundTrip — снимок переживает запись и строгое чтение.
func TestWriteReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quic.json")
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

	want := Report{SNIs: []SNIStat{{SNI: "a.example", Drops: 2, LastDrop: t0, LastTCPHello: t0.Add(time.Second)}}}
	if err := WriteFile(path, want); err != nil {
		t.Fatalf("запись: %v", err)
	}
	got, err := ReadFile(path)
	if err != nil {
		t.Fatalf("чтение: %v", err)
	}
	if len(got.SNIs) != 1 || got.SNIs[0].SNI != "a.example" || got.SNIs[0].Drops != 2 {
		t.Fatalf("прочитано не то: %+v", got)
	}
	if !got.SNIs[0].LastDrop.Equal(t0) {
		t.Errorf("время сброса исказилось: %v", got.SNIs[0].LastDrop)
	}
}

// TestReadFileMissing — отсутствие файла отдаётся как os.IsNotExist, чтобы
// вызывающий отличил «блокировка выключена» от сбоя чтения.
func TestReadFileMissing(t *testing.T) {
	_, err := ReadFile(filepath.Join(t.TempDir(), "нет.json"))
	if !os.IsNotExist(err) {
		t.Fatalf("ожидалась ошибка «файла нет», получено %v", err)
	}
}

// TestRunWritesAndStopsOnCancel — Run пишет первый снимок сразу и финальный на
// отмене.
func TestRunWritesAndStopsOnCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quic.json")
	tr := NewTracker()
	t0 := time.Now()
	tr.BlockedQUIC("youtube.com", t0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); tr.Run(ctx, path, time.Hour, func() time.Time { return t0.Add(time.Second) }) }()

	// Первый снимок пишется сразу — дождёмся появления файла.
	deadline := time.After(2 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("первый снимок не записан в срок")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	rep, err := ReadFile(path)
	if err != nil {
		t.Fatalf("чтение после Run: %v", err)
	}
	if len(rep.SNIs) != 1 || rep.SNIs[0].SNI != "youtube.com" {
		t.Fatalf("ожидался youtube.com в снимке, получено %+v", rep)
	}
}
