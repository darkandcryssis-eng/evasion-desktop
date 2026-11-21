package sysmanifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ChangeKind — вид системного изменения. Строковый тип, чтобы будущие виды
// добавлялись дополнением константы, а не правкой перечисления.
type ChangeKind string

// Виды изменений, которые умеет регистрировать движок. Добавить новый вид —
// расширить этот блок И реализатор отмены (у каждого вида свой — в cmd/evasion
// cleanup или в соответствующем пакете).
const (
	// KindFirewallRule — правило `netsh advfirewall firewall`. ID — имя
	// правила (`movok-discord-bad-rtc`), UndoData обычно пустая: отмена
	// делается по имени.
	KindFirewallRule ChangeKind = "firewall_rule"
	// KindHostsEntry — одна запись в системном hosts (IP + имя). ID — пара
	// `ip\tname`, UndoData — часть записи, которую надо найти и удалить
	// (пакет hosts знает её формат).
	KindHostsEntry ChangeKind = "hosts_entry"
)

// Record — одно зарегистрированное изменение.
//
// Хранится в журнале как есть, читается как есть. Поля именованы коротко,
// чтобы файл был терпимым для чтения глазами (sysmanifest — не только для
// кода, но и для оператора, разбирающегося руками).
type Record struct {
	Kind      ChangeKind      `json:"kind"`
	ID        string          `json:"id"`
	AppliedAt time.Time       `json:"applied_at"`
	UndoData  json.RawMessage `json:"undo_data,omitempty"`
}

// Manifest — журнал изменений с атомарной записью на диск.
//
// Потокобезопасен: допускает параллельные Record/Remove/Pending. Весь API —
// под внутренним мьютексом, в hot path не вызывается, поэтому стоимость
// синхронизации не имеет значения.
type Manifest struct {
	path string
	mu   sync.Mutex
	recs []Record
}

// Open открывает журнал по заданному пути. Создаёт пустой журнал, если файла
// нет. Возвращает ошибку только на реально сломанном файле (не JSON, не
// читается) — её нельзя игнорировать, иначе отмена пойдёт по памяти, которой
// в новом процессе нет.
func Open(path string) (*Manifest, error) {
	if path == "" {
		return nil, errors.New("sysmanifest: пустой путь к журналу")
	}
	m := &Manifest{path: path}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(data) == 0 {
			return m, nil
		}
		if err := json.Unmarshal(data, &m.recs); err != nil {
			return nil, fmt.Errorf("sysmanifest: разбор %s: %w", path, err)
		}
	case os.IsNotExist(err):
		// Чистый старт.
	default:
		return nil, fmt.Errorf("sysmanifest: чтение %s: %w", path, err)
	}
	return m, nil
}

// Path — путь, по которому пишется журнал. Нужен тестам и команде cleanup
// (для дружелюбного сообщения оператору «вот файл»).
func (m *Manifest) Path() string { return m.path }

// Record регистрирует применённое изменение.
//
// Контракт: вызывается ПОСЛЕ успешного применения, с id, которого ещё нет в
// журнале под этим Kind (или с идентичной записью, если идемпотентность
// нужна вызывающему). Если запись с (kind, id) уже существует, она
// замещается с новыми applied_at и undo_data: это облегчает «применить
// дважды» (например, при перезапуске движка на уже применённом правиле).
//
// undo может быть nil (отмена не требует параметров — достаточно (kind, id))
// или произвольной структурой, которую пакет-исполнитель отмены понимает.
// Сериализация — JSON, поэтому структура должна быть json-дружелюбной.
func (m *Manifest) Record(kind ChangeKind, id string, undo any) error {
	if kind == "" {
		return errors.New("sysmanifest: пустой Kind")
	}
	if id == "" {
		return errors.New("sysmanifest: пустой ID")
	}
	var undoRaw json.RawMessage
	if undo != nil {
		b, err := json.Marshal(undo)
		if err != nil {
			return fmt.Errorf("sysmanifest: сериализация undo_data для %s/%s: %w", kind, id, err)
		}
		undoRaw = b
	}
	rec := Record{
		Kind:      kind,
		ID:        id,
		AppliedAt: time.Now().UTC(),
		UndoData:  undoRaw,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Замещаем существующую запись (kind, id), если есть.
	for i := range m.recs {
		if m.recs[i].Kind == kind && m.recs[i].ID == id {
			m.recs[i] = rec
			return m.persistLocked()
		}
	}
	m.recs = append(m.recs, rec)
	return m.persistLocked()
}

// Remove вычёркивает запись из журнала — означает «изменение отменено, помнить
// о нём больше не нужно». Безопасно вызывать на несуществующей записи:
// идемпотентна по построению, иначе отмена пришлось бы координировать с
// журналом в двух местах.
func (m *Manifest) Remove(kind ChangeKind, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.recs {
		if m.recs[i].Kind == kind && m.recs[i].ID == id {
			m.recs = append(m.recs[:i], m.recs[i+1:]...)
			return m.persistLocked()
		}
	}
	return nil
}

// Pending возвращает копию текущих записей, отсортированных по порядку
// применения (`applied_at` возрастанию).
//
// Копия, а не ссылка: вызывающий — отмена — не должен править журнал напрямую;
// то, что он удалил, он убирает через Remove. Сортировка — чтобы оператор,
// читающий файл глазами, видел хронологию.
func (m *Manifest) Pending() []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Record, len(m.recs))
	copy(out, m.recs)
	sort.Slice(out, func(i, j int) bool { return out[i].AppliedAt.Before(out[j].AppliedAt) })
	return out
}

// Len — число записей в журнале. Выделено отдельно для тестов и для
// дешёвой проверки «есть ли что отменять» без выделения памяти под Pending.
func (m *Manifest) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.recs)
}

// Clear удаляет все записи и файл. Нужна в тестах и в редком случае, когда
// оператор решил «я вручную всё почистил, забудь». Отдельная команда, чтобы
// случайное пустое Pending не стирало файл: Pending — это чтение, Clear —
// явное действие.
func (m *Manifest) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs = nil
	if err := os.Remove(m.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("sysmanifest: удаление %s: %w", m.path, err)
	}
	return nil
}

// persistLocked атомарно пишет текущее состояние в m.path.
//
// Через временный файл + rename: это гарантирует, что процесс, читающий файл в
// момент записи, либо получит старую полную копию, либо новую полную — но
// никогда не половину. На Windows rename заменяет файл по тому же тому
// (все наши пути под `state/` этому удовлетворяют).
//
// m.mu должен быть зажат вызывающим.
func (m *Manifest) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return fmt.Errorf("sysmanifest: создание каталога %s: %w", filepath.Dir(m.path), err)
	}
	// Сортируем перед записью: файл должен быть стабильным между двумя записями
	// одних и тех же данных (помогает в diff'ах и tests).
	sort.Slice(m.recs, func(i, j int) bool { return m.recs[i].AppliedAt.Before(m.recs[j].AppliedAt) })
	data, err := json.MarshalIndent(m.recs, "", "  ")
	if err != nil {
		return fmt.Errorf("sysmanifest: сериализация: %w", err)
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("sysmanifest: запись %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, m.path); err != nil {
		// На Windows rename может не удаться, если целевой файл заблокирован
		// другим процессом (например, антивирус читает). Чистим tmp — он нам
		// больше не нужен, оставить его = накапливать мусор.
		_ = os.Remove(tmp)
		return fmt.Errorf("sysmanifest: атомарная замена %s: %w", m.path, err)
	}
	return nil
}
