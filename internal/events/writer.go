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
	writeBufferSize      = 64 << 10
	rotationRetryDelay   = 5 * time.Second
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

	mu          sync.Mutex
	file        *os.File
	fileSize    int64
	rotateAfter time.Time
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
	w := &Writer{
		cfg:    cfg,
		queue:  make(chan Event, cfg.QueueSize),
		closed: make(chan struct{}),
		done:   make(chan struct{}),
	}
	if err := w.openActive(); err != nil {
		return nil, err
	}
	go w.run()
	return w, nil
}

func (w *Writer) openActive() error {
	f, err := os.OpenFile(w.cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("events: открытие %s: %w", w.cfg.Path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("events: stat %s: %w", w.cfg.Path, err)
	}
	w.file = f
	w.fileSize = info.Size()
	return nil
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
	buffer := make([]byte, 0, writeBufferSize)
	for {
		select {
		case e := <-w.queue:
			batch = append(batch, e)
			if len(batch) >= w.cfg.BatchSize {
				batch = w.flush(batch, buffer)
			}
		case <-ticker.C:
			batch = w.flush(batch, buffer)
		case <-w.closed:
			// Дописываем всё из очереди перед выходом.
			for {
				select {
				case e := <-w.queue:
					batch = append(batch, e)
					if len(batch) >= w.cfg.BatchSize {
						batch = w.flush(batch, buffer)
					}
				default:
					_ = w.flush(batch, buffer)
					return
				}
			}
		}
	}
}

// flush пишет пачку в активный файл, при необходимости ротирует.
// Возвращает срез нулевой длины той же ёмкости (для повторного использования).
func (w *Writer) flush(batch []Event, buffer []byte) []Event {
	if len(batch) == 0 {
		return batch
	}
	defer clear(batch)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil && w.openActive() != nil {
		return batch[:0]
	}
	write := func(data []byte) bool {
		n, err := w.file.Write(data)
		w.fileSize += int64(n)
		return err == nil
	}
	flushBuffer := func() bool {
		if len(buffer) == 0 {
			return true
		}
		ok := write(buffer)
		buffer = buffer[:0]
		return ok
	}
	rotate := w.rotateAfter.IsZero() || !time.Now().Before(w.rotateAfter)
	for _, e := range batch {
		data, err := json.Marshal(e)
		if err != nil {
			// Невозможная ситуация (MarshalJSON у Event безошибочен), но
			// если что-то — пропускаем событие, не ломаем поток.
			continue
		}
		size := len(data) + 1
		if size > cap(buffer)-len(buffer) && !flushBuffer() {
			return batch[:0]
		}
		if size > cap(buffer) {
			if !write(append(data, '\n')) {
				return batch[:0]
			}
		} else {
			buffer = append(append(buffer, data...), '\n')
		}
		if rotate && w.fileSize+int64(len(buffer)) >= w.cfg.MaxFileBytes {
			if !flushBuffer() {
				return batch[:0]
			}
			if err := w.rotateLocked(); err != nil {
				w.rotateAfter = time.Now().Add(rotationRetryDelay)
				rotate = false
			} else {
				w.rotateAfter = time.Time{}
			}
			if w.file == nil && w.openActive() != nil {
				return batch[:0]
			}
		}
	}
	flushBuffer()
	return batch[:0]
}

// rotateLocked сначала убирает активный файл из-под записи, затем сдвигает архивы.
func (w *Writer) rotateLocked() (err error) {
	oldPath := w.cfg.Path
	staged := oldPath + ".rotating"
	retiring := oldPath + ".retiring"
	for _, path := range []string{staged, retiring} {
		if err := requireVacant(path); err != nil {
			return err
		}
	}
	err = w.file.Close()
	w.file = nil
	if err != nil {
		return fmt.Errorf("events: закрытие активного файла при ротации: %w", err)
	}

	type rename struct{ from, to string }
	var moves []rename
	defer func() {
		if err == nil {
			return
		}
		for i := len(moves) - 1; i >= 0; i-- {
			m := moves[i]
			if undoErr := requireVacant(m.from); undoErr != nil {
				err = errors.Join(err, undoErr)
				return
			}
			if undoErr := os.Rename(m.to, m.from); undoErr != nil {
				err = errors.Join(err, undoErr)
				return
			}
		}
	}()
	move := func(from, to string, optional bool) error {
		info, err := os.Lstat(from)
		if optional && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("events: не файл: %s", from)
		}
		if err := requireVacant(to); err != nil {
			return err
		}
		if err := os.Rename(from, to); err != nil {
			return err
		}
		moves = append(moves, rename{from, to})
		return nil
	}
	if err := move(oldPath, staged, false); err != nil {
		return err
	}
	if err := move(fmt.Sprintf("%s.%d", oldPath, w.cfg.MaxRotated), retiring, true); err != nil {
		return err
	}
	retired := len(moves) == 2
	for i := w.cfg.MaxRotated - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", oldPath, i)
		dst := fmt.Sprintf("%s.%d", oldPath, i+1)
		if err := move(src, dst, true); err != nil {
			return err
		}
	}
	if err := move(staged, oldPath+".1", false); err != nil {
		return err
	}
	moves = nil
	if retired {
		return os.Remove(retiring)
	}
	return nil
}

func requireVacant(path string) error {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("events: файл уже существует: %s", path)
	}
	return err
}
