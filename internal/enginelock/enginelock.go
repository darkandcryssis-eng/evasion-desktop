package enginelock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry — одна запись о запущенном экземпляре движка.
type Entry struct {
	PID       int       `json:"pid"`
	Filter    string    `json:"filter"`
	StartedAt time.Time `json:"started_at"`
}

// Lock — захваченный замок одного экземпляра.
//
// Нулевое значение бесполезно: Lock приобретается через Acquire. Повторный
// Release безопасен (идемпотентен), чтобы defer-ы в тестах и в cmd не падали
// на двойной очистке.
type Lock struct {
	path   string
	entry  Entry
	mu     sync.Mutex
	closed bool
}

// AliveFunc — проверка «жив ли процесс с таким PID». Внедряется, чтобы ядро
// пакета не зависело от OS-ветки `syscall.Kill`/`OpenProcess` и чтобы тесты
// могли подкладывать детерминированное поведение.
type AliveFunc func(pid int) bool

// Options — опции захвата. Пути файла, своя PID (0 означает os.Getpid), своя
// проверка живости (nil означает defaultAlive — реальный syscall).
type Options struct {
	// Path — путь к lock-файлу. Пустой — ошибка.
	Path string
	// Filter — фильтр WinDivert текущего экземпляра. Пустой — ошибка.
	Filter string
	// SelfPID — PID текущего процесса. 0 означает os.Getpid().
	SelfPID int
	// Alive — проверка живости. nil означает defaultAlive.
	Alive AliveFunc
}

// Acquire пытается захватить замок.
//
// Если никто живой на пересекающемся фильтре не висит, пишет свою запись и
// возвращает Lock. Если висит — возвращает ошибку `ErrConflict`, в тексте
// которой указаны PID и фильтр конкурента.
func Acquire(opts Options) (*Lock, error) {
	if opts.Path == "" {
		return nil, errors.New("enginelock: пустой путь к lock-файлу")
	}
	if opts.Filter == "" {
		return nil, errors.New("enginelock: пустой фильтр")
	}
	pid := opts.SelfPID
	if pid == 0 {
		pid = os.Getpid()
	}
	alive := opts.Alive
	if alive == nil {
		alive = defaultAlive
	}

	// Читаем существующие записи, фильтруем мёртвые.
	entries, err := loadEntries(opts.Path)
	if err != nil {
		return nil, err
	}
	live := make([]Entry, 0, len(entries))
	for _, e := range entries {
		if e.PID == pid {
			// Старая наша запись (например, после краха без Release или
			// после ошибки раньше в этом же процессе). Её выбросим и
			// заменим свежей.
			continue
		}
		if !alive(e.PID) {
			continue
		}
		live = append(live, e)
	}

	// Проверка конфликта фильтра.
	for _, e := range live {
		if filtersConflict(e.Filter, opts.Filter) {
			return nil, fmt.Errorf("%w: уже запущен pid %d на фильтре %q", ErrConflict, e.PID, e.Filter)
		}
	}

	// Пишем свою запись.
	self := Entry{PID: pid, Filter: opts.Filter, StartedAt: time.Now().UTC()}
	all := append(live, self)
	if err := saveEntries(opts.Path, all); err != nil {
		return nil, err
	}
	return &Lock{path: opts.Path, entry: self}, nil
}

// ErrConflict возвращается Acquire, когда уже работает экземпляр с
// пересекающимся фильтром. Отдельная переменная, чтобы вызывающий мог
// обработать именно её (например, предложить `evasion cleanup`), а не
// любую ошибку.
var ErrConflict = errors.New("enginelock: конфликт запуска")

// Release убирает свою запись из lock-файла.
//
// Безопасно вызывать повторно — вторая Release возвращает nil без действий.
// Это нужно, чтобы defer-паттерн в вызывающем коде был идиоматичным.
//
// На ошибку чтения/записи возвращает её, но свой флаг closed всё равно
// взводит: следующий Release не должен пытаться писать повторно.
func (l *Lock) Release() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true

	entries, err := loadEntries(l.path)
	if err != nil {
		return err
	}
	out := entries[:0]
	for _, e := range entries {
		if e.PID == l.entry.PID && e.Filter == l.entry.Filter {
			continue
		}
		out = append(out, e)
	}
	// Если никого не осталось, удаляем файл — чище, чем держать пустой.
	if len(out) == 0 {
		if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("enginelock: удаление %s: %w", l.path, err)
		}
		return nil
	}
	return saveEntries(l.path, out)
}

// Entry — текущая зарегистрированная запись (нужно тестам и диагностике).
func (l *Lock) Entry() Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.entry
}

// ListLive возвращает записи живых процессов из lock-файла без изменения
// файла. Нужна команде doctor для показа «кто запущен» и команде cleanup,
// чтобы вывести предупреждение. Мёртвые записи отфильтровываются.
func ListLive(path string, alive AliveFunc) ([]Entry, error) {
	if alive == nil {
		alive = defaultAlive
	}
	entries, err := loadEntries(path)
	if err != nil {
		return nil, err
	}
	out := entries[:0]
	for _, e := range entries {
		if alive(e.PID) {
			out = append(out, e)
		}
	}
	return out, nil
}

// filtersConflict отвечает на вопрос «могут ли эти два фильтра одновременно
// работать безопасно».
//
// Упрощение: совпадающие фильтры (включая равенство строк) — конфликт. Все
// остальные пары считаем безопасными. Это соответствует фактическому делению:
// у `--auto` продуктовый и песочный фильтры различаются условием порта, и
// пересечения по пакетам у них нет.
//
// Это умышленно консервативно по полезности и либерально по безопасности:
// фильтры WinDivert — выражения с AND/OR, их пересечение алгоритмически
// нетривиально разобрать. Пропуск одного-другого случая вида «один фильтр —
// подмножество другого, но строки разные» лишь означает, что мы разрешаем
// запуск, который МОГ бы быть опасен. На практике владелец запускает
// `start-discord.bat` или `--auto`, оба используют одни и те же известные
// фильтры, которые эта функция ловит точно.
func filtersConflict(a, b string) bool {
	return a == b
}

// loadEntries читает записи из lock-файла. Отсутствующий файл — не ошибка
// (чистый старт).
func loadEntries(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(data) == 0 {
			return nil, nil
		}
		var out []Entry
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("enginelock: разбор %s: %w", path, err)
		}
		return out, nil
	case os.IsNotExist(err):
		return nil, nil
	default:
		return nil, fmt.Errorf("enginelock: чтение %s: %w", path, err)
	}
}

// saveEntries атомарно пишет записи в lock-файл: tmp + rename.
func saveEntries(path string, entries []Entry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("enginelock: создание каталога: %w", err)
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("enginelock: сериализация: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("enginelock: запись %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("enginelock: атомарная замена %s: %w", path, err)
	}
	return nil
}
