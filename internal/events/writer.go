package events

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Config — настройки приёмника. Нулевые значения заполняются дефолтами в Open.
type Config struct {
	// Path — путь к активному файлу `events.jsonl`.
	Path string
	// QueueSize — ёмкость очереди событий между вызывающим и горутиной
	// записи. При переполнении — отбрасывание (как в store.Writer).
	QueueSize int
	// MaxFileBytes — предельный размер активного файла перед ротацией.
	// 0 означает MaxFileBytesDefault.
	MaxFileBytes int64
	// MaxRotated — сколько старых файлов хранить при ротации.
	// 0 означает MaxRotatedDefault.
	MaxRotated int
	// FlushInterval — через сколько сбрасывать буфер на диск, если
	// событий меньше BatchSize.
	FlushInterval time.Duration
	// BatchSize — сколько событий писать одной пачкой.
	BatchSize int
}

const (
	QueueSizeDefault     = 4096
	BatchSizeDefault     = 128
	FlushIntervalDefault = 200 * time.Millisecond
	MaxFileBytesDefault  = 10 << 20 // 10 МиБ
	MaxRotatedDefault    = 5
)

// Writer — асинхронный приёмник событий. Пишет JSON Lines в активный файл,
// при превышении размера ротирует.
type Writer struct {
	cfg       Config
	queue     chan Event
	closed    chan struct{}
	done      chan struct{}
	dropped   atomic.Int64
	accepted  atomic.Int64
	closeOnce sync.Once
	closeErr  error

	mu       sync.Mutex
	file     *os.File
	fileSize int64
}

// Open открывает приёмник событий, создаёт/дописывает активный файл и
// запускает фоновую горутину записи.
func Open(cfg Config) (*Writer, error) {
	if cfg.Path == "" {
		return nil, errors.New("events: пустой путь")
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = QueueSizeDefault
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = BatchSizeDefault
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = FlushIntervalDefault
	}
	if cfg.MaxFileBytes <= 0 {
		cfg.MaxFileBytes = MaxFileBytesDefault
	}
	if cfg.MaxRotated <= 0 {
		cfg.MaxRotated = MaxRotatedDefault
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o755); err != nil {
		return nil, fmt.Errorf("events: создание каталога: %w", err)
	}
	f, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("events: открытие %s: %w", cfg.Path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("events: stat %s: %w", cfg.Path, err)
	}
	w := &Writer{
		cfg:      cfg,
		queue:    make(chan Event, cfg.QueueSize),
		closed:   make(chan struct{}),
		done:     make(chan struct{}),
		file:     f,
		fileSize: info.Size(),
	}
	go w.run()
	return w, nil
}

// Enqueue кладёт событие в очередь. Не блокирует: при переполнении событие
// отбрасывается, dropped инкрементируется.
func (w *Writer) Enqueue(e Event) {
	select {
	case <-w.closed:
		w.dropped.Add(1)
		return
	default:
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	select {
	case w.queue <- e:
		w.accepted.Add(1)
	default:
		w.dropped.Add(1)
	}
}

// Dropped — число событий, отброшенных из-за переполнения или закрытия.
func (w *Writer) Dropped() int64 { return w.dropped.Load() }

// Accepted — число принятых в очередь событий (не обязательно записанных).
func (w *Writer) Accepted() int64 { return w.accepted.Load() }

// Close останавливает приёмник: закрывает очередь, ждёт слива буфера, закрывает
// файл. Идемпотентна.
func (w *Writer) Close() error {
	w.closeOnce.Do(func() {
		close(w.closed)
		<-w.done
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.file != nil {
			w.closeErr = w.file.Close()
			w.file = nil
		}
	})
	return w.closeErr
}

// run — горутина записи. Собирает события пачками и пишет в активный файл.
func (w *Writer) run() {
	defer close(w.done)
	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()
	batch := make([]Event, 0, w.cfg.BatchSize)
	for {
		select {
		case e := <-w.queue:
			batch = append(batch, e)
			if len(batch) >= w.cfg.BatchSize {
				batch = w.flush(batch)
			}
		case <-ticker.C:
			batch = w.flush(batch)
		case <-w.closed:
			// Дописываем всё из очереди перед выходом.
			for {
				select {
				case e := <-w.queue:
					batch = append(batch, e)
					if len(batch) >= w.cfg.BatchSize {
						batch = w.flush(batch)
					}
				default:
					_ = w.flush(batch)
					return
				}
			}
		}
	}
}

// flush пишет пачку в активный файл, при необходимости ротирует.
// Возвращает срез нулевой длины той же ёмкости (для повторного использования).
func (w *Writer) flush(batch []Event) []Event {
	if len(batch) == 0 {
		return batch
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return batch[:0]
	}
	for _, e := range batch {
		data, err := json.Marshal(e)
		if err != nil {
			// Невозможная ситуация (MarshalJSON у Event безошибочен), но
			// если что-то — пропускаем событие, не ломаем поток.
			continue
		}
		data = append(data, '\n')
		n, err := w.file.Write(data)
		if err != nil {
			// Ошибка диска: прекращаем попытки до следующего flush, но
			// батч тем не менее очищаем — иначе он будет пухнуть при
			// длительном сбое.
			return batch[:0]
		}
		w.fileSize += int64(n)
		if w.fileSize >= w.cfg.MaxFileBytes {
			if err := w.rotateLocked(); err != nil {
				// Ротация не удалась — продолжаем писать в тот же файл;
				// он просто станет больше MaxFileBytes. Это лучше, чем
				// остановить писатель.
				continue
			}
		}
	}
	return batch[:0]
}

// rotateLocked переименовывает активный файл в rotated-слот, закрывает,
// открывает новый. w.mu должен быть зажат.
func (w *Writer) rotateLocked() error {
	oldPath := w.cfg.Path
	// Сдвигаем rotated-слоты: events.4 → events.5 (с удалением events.5).
	for i := w.cfg.MaxRotated; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", oldPath, i)
		dst := fmt.Sprintf("%s.%d", oldPath, i+1)
		if i == w.cfg.MaxRotated {
			_ = os.Remove(src)
			continue
		}
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
		}
	}
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("events: закрытие активного файла при ротации: %w", err)
	}
	w.file = nil
	if err := os.Rename(oldPath, oldPath+".1"); err != nil {
		return fmt.Errorf("events: переименование активного файла при ротации: %w", err)
	}
	f, err := os.OpenFile(oldPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("events: открытие нового активного файла при ротации: %w", err)
	}
	w.file = f
	w.fileSize = 0
	return nil
}
