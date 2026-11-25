package rtctrack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadBoundsLegacySnapshotByLastActivity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rtctrack.json")
	file := snapshotFile{Version: snapshotVersion}
	for i := maxTrackedPairs; i >= 0; i-- {
		file.Entries = append(file.Entries, snapshotEntry{Port: uint16(i), Observed: 1, LastAt: time.Unix(int64(i), 0)})
	}
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	tr, err := Load(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Len() != maxTrackedPairs {
		t.Fatalf("loaded %d pairs, want %d", tr.Len(), maxTrackedPairs)
	}
	if _, ok := tr.Snapshot()[Pair{Port: 0}]; ok {
		t.Fatal("loaded oldest pair from oversized snapshot")
	}
	tr.Observe(Pair{Port: maxTrackedPairs + 1})
	if _, ok := tr.Snapshot()[Pair{Port: 1}]; ok {
		t.Fatal("oldest retained pair was not evicted")
	}
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rtctrack.json")

	// Populate tracker.
	tr := NewTracker(fixedNow(time.Unix(1000, 0)))
	p1 := Pair{SNI: "a.discord.media", Port: 443}
	p2 := Pair{SNI: "b.discord.media", Port: 2096}
	for i := 0; i < 10; i++ {
		tr.Observe(p1)
	}
	tr.Settled(p1)
	tr.Settled(p1)
	tr.Elapsed(p1, 30*time.Second)
	tr.Observe(p2)
	tr.Reset(p2)

	if err := tr.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load into new tracker.
	tr2, err := Load(path, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	snap := tr2.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("после Load пар %d, ожидали 2", len(snap))
	}
	s1 := snap[p1]
	if s1.Observed != 10 || s1.Settled != 2 || s1.Elapsed != 1 || s1.TotalDwell != 30*time.Second {
		t.Fatalf("p1 потерял данные: %+v", s1)
	}
	s2 := snap[p2]
	if s2.Observed != 1 || s2.Reset != 1 {
		t.Fatalf("p2 потерял данные: %+v", s2)
	}
}

func TestLoadMissingFileIsCleanStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.json")
	tr, err := Load(path, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if tr.Len() != 0 {
		t.Fatalf("пустой трекер, Len = %d", tr.Len())
	}
}

func TestLoadCorruptedFailsLoudly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corrupted.json")
	_ = os.WriteFile(path, []byte("{сломано"), 0o644)
	if _, err := Load(path, nil); err == nil {
		t.Fatal("Load на сломанном JSON должен вернуть ошибку")
	}
}

func TestLoadWrongVersionFailsLoudly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wrongver.json")
	_ = os.WriteFile(path, []byte(`{"version":99,"saved_at":"2026-01-01T00:00:00Z","entries":[]}`), 0o644)
	if _, err := Load(path, nil); err == nil {
		t.Fatal("Load с чужой версией должен вернуть ошибку")
	}
}

func TestSaveEmptyPathFails(t *testing.T) {
	tr := NewTracker(nil)
	if err := tr.Save(""); err == nil {
		t.Fatal("Save с пустым путём должен падать")
	}
}

func TestAutoSaverStopFlushes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rtctrack.json")
	tr := NewTracker(nil)
	p := Pair{SNI: "x.discord.media", Port: 443}
	tr.Observe(p)
	tr.Settled(p)

	saver := StartAutoSaver(tr, path, time.Hour) // не сработает по таймеру, но Stop должен сохранить
	saver.Stop()
	saver.Stop() // идемпотентно

	tr2, err := Load(path, nil)
	if err != nil {
		t.Fatalf("Load после Stop: %v", err)
	}
	if tr2.Snapshot()[p].Settled != 1 {
		t.Fatal("AutoSaver.Stop не сохранил снимок")
	}
}

func TestAutoSaverPeriodicSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rtctrack.json")
	tr := NewTracker(nil)

	saver := StartAutoSaver(tr, path, 20*time.Millisecond)
	defer saver.Stop()

	p := Pair{SNI: "p.discord.media", Port: 443}
	tr.Observe(p)
	time.Sleep(80 * time.Millisecond)

	tr2, _ := Load(path, nil)
	if tr2.Snapshot()[p].Observed != 1 {
		t.Fatal("AutoSaver не записал Observe по таймеру")
	}
}
