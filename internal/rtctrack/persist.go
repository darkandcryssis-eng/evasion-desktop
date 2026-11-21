package rtctrack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// snapshotFile — на-диске форма Tracker: массив записей, каждая несёт пару и
// статистику. JSON намеренно: читается глазами, легко grep'ать, не бьёт при
// частичной записи (сравнимо с sysmanifest).
type snapshotFile struct {
	Version int               `json:"version"`
	SavedAt time.Time         `json:"saved_at"`
	Entries []snapshotEntry   `json:"entries"`
}

// snapshotEntry — одна строка снимка.
type snapshotEntry struct {
	SNI        string        `json:"sni"`
	Port       uint16        `json:"port"`
	Observed   int           `json:"observed"`
	Settled    int           `json:"settled"`
	Reset      int           `json:"reset"`
	TotalDwell time.Duration `json:"total_dwell"`
	Elapsed    int           `json:"elapsed"`
	LastAt     time.Time     `json:"last_at"`
}

const snapshotVersion = 1

// Save атомарно записывает текущие статистики в файл. tmp + rename, как у
// sysmanifest — прерывание посреди записи не оставит полуфайл.
//
// Безопасно вызывать параллельно с Observe/Settled/... — Snapshot внутри
// возьмёт мьютекс и получит консистентную копию.
func (t *Tracker) Save(path string) error {
	if path == "" {
		return fmt.Errorf("rtctrack: пустой путь для Save")
	}
	snap := t.Snapshot()
	file := snapshotFile{
		Version: snapshotVersion,
		SavedAt: time.Now().UTC(),
		Entries: make([]snapshotEntry, 0, len(snap)),
	}
	for p, s := range snap {
		file.Entries = append(file.Entries, snapshotEntry{
			SNI:        p.SNI,
			Port:       p.Port,
			Observed:   s.Observed,
			Settled:    s.Settled,
			Reset:      s.Reset,
			TotalDwell: s.TotalDwell,
			Elapsed:    s.Elapsed,
			LastAt:     s.LastAt,
		})
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("rtctrack: каталог %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("rtctrack: сериализация: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("rtctrack: запись %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rtctrack: атомарная замена %s: %w", path, err)
	}
	return nil
}

// Load восстанавливает Tracker из файла. Отсутствие файла — не ошибка (чистый
// старт, в журнал пустая).
//
// Если файл есть, но версия чужая — вернём ошибку: несовместимость лучше
// явного отказа, чем молчаливой потери данных.
func Load(path string, now func() time.Time) (*Tracker, error) {
	if path == "" {
		return nil, fmt.Errorf("rtctrack: пустой путь для Load")
	}
	t := NewTracker(now)
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var file snapshotFile
		if err := json.Unmarshal(data, &file); err != nil {
			return nil, fmt.Errorf("rtctrack: разбор %s: %w", path, err)
		}
		if file.Version != snapshotVersion {
			return nil, fmt.Errorf("rtctrack: несовместимая версия %d (ожидаем %d)", file.Version, snapshotVersion)
		}
		t.mu.Lock()
		for _, e := range file.Entries {
			t.stats[Pair{SNI: e.SNI, Port: e.Port}] = &Stat{
				Observed:   e.Observed,
				Settled:    e.Settled,
				Reset:      e.Reset,
				TotalDwell: e.TotalDwell,
				Elapsed:    e.Elapsed,
				LastAt:     e.LastAt,
			}
		}
		t.mu.Unlock()
	case os.IsNotExist(err):
		// Чистый старт — таблица пуста.
	default:
		return nil, fmt.Errorf("rtctrack: чтение %s: %w", path, err)
	}
	return t, nil
}

// AutoSaver периодически вызывает Save. Нужен, чтобы при аварийном
// завершении не терять свежую статистику: Save на graceful shutdown
// недостаточен — крэш случается в самый неподходящий момент.
type AutoSaver struct {
	tracker  *Tracker
	path     string
	interval time.Duration
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
}

// StartAutoSaver запускает фоновую горутину периодической записи.
// Возвращает AutoSaver, у которого можно вызвать Stop для graceful shutdown.
func StartAutoSaver(tracker *Tracker, path string, interval time.Duration) *AutoSaver {
	if interval <= 0 {
		interval = time.Minute
	}
	a := &AutoSaver{
		tracker:  tracker,
		path:     path,
		interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go a.run()
	return a
}

func (a *AutoSaver) run() {
	defer close(a.done)
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = a.tracker.Save(a.path) // ошибка не фатал — просто пропускаем цикл
		case <-a.stop:
			_ = a.tracker.Save(a.path) // финальная запись при остановке
			return
		}
	}
}

// Stop останавливает AutoSaver и дожидается завершения последнего Save.
// Идемпотентен.
func (a *AutoSaver) Stop() {
	a.once.Do(func() {
		close(a.stop)
		<-a.done
	})
}
