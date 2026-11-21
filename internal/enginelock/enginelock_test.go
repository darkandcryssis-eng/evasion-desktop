package enginelock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// aliveMock — подконтрольная тесту проверка живости по множеству живых PID.
func aliveMock(live map[int]bool) AliveFunc {
	return func(pid int) bool { return live[pid] }
}

// Первый Acquire на чистом месте создаёт файл с одной записью.
func TestAcquireFirstTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.lock")
	l, err := Acquire(Options{Path: path, Filter: "tcp 443", SelfPID: 100, Alive: aliveMock(nil)})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer l.Release()
	if l.Entry().PID != 100 {
		t.Fatalf("Entry.PID = %d, ожидали 100", l.Entry().PID)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("lock-файл не создан: %v", err)
	}
}

// Второй Acquire с живым первым и тем же фильтром — ErrConflict.
func TestAcquireSameFilterConflicts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.lock")
	live := map[int]bool{100: true}
	l1, err := Acquire(Options{Path: path, Filter: "tcp 443", SelfPID: 100, Alive: aliveMock(live)})
	if err != nil {
		t.Fatalf("Acquire 1: %v", err)
	}
	defer l1.Release()

	_, err = Acquire(Options{Path: path, Filter: "tcp 443", SelfPID: 200, Alive: aliveMock(live)})
	if err == nil {
		t.Fatal("ожидали ErrConflict, получили nil")
	}
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("ожидали ErrConflict, получили %v", err)
	}
}

// Второй Acquire с другим фильтром — проходит (у `--auto` два фильтра).
func TestAcquireDifferentFilterAllowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.lock")
	live := map[int]bool{100: true}
	l1, err := Acquire(Options{Path: path, Filter: "tcp 443", SelfPID: 100, Alive: aliveMock(live)})
	if err != nil {
		t.Fatalf("Acquire 1: %v", err)
	}
	defer l1.Release()

	live[200] = true
	l2, err := Acquire(Options{Path: path, Filter: "udp 443", SelfPID: 200, Alive: aliveMock(live)})
	if err != nil {
		t.Fatalf("Acquire 2 с другим фильтром: %v", err)
	}
	defer l2.Release()
}

// Мёртвая запись (PID не жив) не блокирует: Acquire перезаписывает её.
func TestAcquireIgnoresDeadRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.lock")
	// Подкладываем файл с «мёртвой» записью (PID 999, не в live).
	dead := Entry{PID: 999, Filter: "tcp 443"}
	if err := saveEntries(path, []Entry{dead}); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	l, err := Acquire(Options{Path: path, Filter: "tcp 443", SelfPID: 100, Alive: aliveMock(nil)})
	if err != nil {
		t.Fatalf("Acquire после мёртвого: %v", err)
	}
	defer l.Release()
	// В файле должна остаться только наша запись.
	entries, _ := loadEntries(path)
	if len(entries) != 1 {
		t.Fatalf("после Acquire записей %d, ожидали 1", len(entries))
	}
	if entries[0].PID != 100 {
		t.Fatalf("осталась мёртвая запись PID %d", entries[0].PID)
	}
}

// Release убирает нашу запись; файл с единственной нашей записью удаляется.
func TestReleaseRemovesEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.lock")
	l, _ := Acquire(Options{Path: path, Filter: "tcp 443", SelfPID: 100, Alive: aliveMock(nil)})
	if err := l.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("файл не удалён после Release последнего: %v", err)
	}
}

// Release при наличии других запущенных — файл остаётся с их записями.
func TestReleaseKeepsOthers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.lock")
	live := map[int]bool{100: true, 200: true}
	l1, _ := Acquire(Options{Path: path, Filter: "tcp 443", SelfPID: 100, Alive: aliveMock(live)})
	l2, _ := Acquire(Options{Path: path, Filter: "udp 443", SelfPID: 200, Alive: aliveMock(live)})
	if err := l1.Release(); err != nil {
		t.Fatalf("Release l1: %v", err)
	}
	entries, _ := loadEntries(path)
	if len(entries) != 1 {
		t.Fatalf("после Release l1 записей %d, ожидали 1", len(entries))
	}
	if entries[0].PID != 200 {
		t.Fatalf("осталась не та запись: %+v", entries[0])
	}
	_ = l2.Release()
}

// Повторный Release — идемпотентный no-op.
func TestReleaseIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.lock")
	l, _ := Acquire(Options{Path: path, Filter: "tcp 443", SelfPID: 100, Alive: aliveMock(nil)})
	if err := l.Release(); err != nil {
		t.Fatalf("Release 1: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("Release 2 (идемпотентный): %v", err)
	}
}

// ListLive возвращает только живые записи.
func TestListLive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.lock")
	// Два живых + один мёртвый.
	live := map[int]bool{100: true, 200: true}
	_ = saveEntries(path, []Entry{
		{PID: 100, Filter: "tcp"},
		{PID: 999, Filter: "udp"},
		{PID: 200, Filter: "any"},
	})
	out, err := ListLive(path, aliveMock(live))
	if err != nil {
		t.Fatalf("ListLive: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("ListLive вернул %d, ожидали 2", len(out))
	}
}

// Пустой путь — ошибка на Acquire.
func TestAcquireEmptyPathFails(t *testing.T) {
	if _, err := Acquire(Options{Filter: "x"}); err == nil {
		t.Fatal("Acquire без пути должен падать")
	}
}

// Пустой фильтр — ошибка.
func TestAcquireEmptyFilterFails(t *testing.T) {
	if _, err := Acquire(Options{Path: filepath.Join(t.TempDir(), "l"), Filter: ""}); err == nil {
		t.Fatal("Acquire без фильтра должен падать")
	}
}

// Старая наша запись (тот же PID) выкидывается и перезаписывается — не плодит
// дубль. Нужно для случая Acquire после паники перед Release.
func TestAcquireReplacesOwnStaleRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.lock")
	_ = saveEntries(path, []Entry{
		{PID: 100, Filter: "old"},
	})
	l, err := Acquire(Options{Path: path, Filter: "new", SelfPID: 100, Alive: aliveMock(map[int]bool{100: true})})
	if err != nil {
		t.Fatalf("Acquire с устаревшей своей записью: %v", err)
	}
	entries, _ := loadEntries(path)
	if len(entries) != 1 {
		t.Fatalf("записей %d, ожидали 1", len(entries))
	}
	if entries[0].Filter != "new" {
		t.Fatalf("старая запись не замещена: %+v", entries[0])
	}
	_ = l.Release()
}

// defaultAlive на текущем pid возвращает true, на заведомо несуществующем — false.
// Проверяет OS-ветку, не мок.
func TestDefaultAliveSelf(t *testing.T) {
	if !defaultAlive(os.Getpid()) {
		t.Fatal("defaultAlive(self) = false, ожидали true")
	}
	// PID 1<<30 заведомо не существует в типичной системе.
	if defaultAlive(1 << 30) {
		t.Fatal("defaultAlive(1<<30) = true, ожидали false")
	}
}
