package quicwatch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Params — пороги эвристики «только QUIC».
//
// Магических чисел в коде быть не должно (10.1), поэтому значения по умолчанию
// вынесены в DefaultParams и могут быть переопределены вызывающим; в конфиг
// пока не вынесены — это диагностический порог без второго потребителя, и его
// перенос в config отложен сознательно (см. журнал).
type Params struct {
	// MinDrops — минимум сброшенных QUIC Initial по имени, прежде чем судить.
	// Один сброс — не признак: приложение могло попробовать QUIC однократно и
	// спокойно уйти на TCP. QUIC-only виден по упорному повторению без отката.
	MinDrops int
	// FallbackGrace — насколько позже сброса должен быть виден TCP ClientHello,
	// чтобы счесть откат состоявшимся. Небольшой зазор гасит дрожание часов:
	// TCP-хелло ровно той же миллисекунды мы откатом не считаем ошибочно.
	FallbackGrace time.Duration
}

// DefaultParams — пороги по умолчанию: три сброса подряд без отката и зазор в
// две секунды на дрожание часов.
func DefaultParams() Params {
	return Params{MinDrops: 3, FallbackGrace: 2 * time.Second}
}

// SNIStat — накопленное по одному имени сервера. Экспортируемые поля: структура
// сериализуется в файл состояния и читается doctor в другом процессе.
type SNIStat struct {
	SNI   string `json:"sni"`
	Drops int    `json:"drops"`
	// LastDrop — время последнего сброшенного QUIC Initial.
	LastDrop time.Time `json:"last_drop"`
	// LastTCPHello — время последнего виденного TCP ClientHello с тем же
	// именем; нулевое, если TCP-хелло не видели ни разу (отката не было вовсе).
	LastTCPHello time.Time `json:"last_tcp_hello"`
}

// Report — снимок накопленного, то, что пишется в файл и читается doctor.
type Report struct {
	SNIs []SNIStat `json:"snis"`
}

// QUICOnly возвращает имена, работающие по признакам только по QUIC: сброшено
// не меньше MinDrops и TCP-откат после последнего сброса так и не наблюдался.
//
// Нулевое LastTCPHello раньше любого LastDrop по определению — имя, у которого
// отката не было вовсе, подозрительно сразу по достижении порога сбросов.
// Результат отсортирован: интерфейс и тест вправе на порядок опереться.
func (r Report) QUICOnly(p Params) []string {
	var out []string
	for _, s := range r.SNIs {
		if s.Drops < p.MinDrops {
			continue
		}
		// Откат состоялся, если TCP-хелло строго позже сброса на зазор. Иначе
		// (хелло нет, или оно раньше/одновременно сбросу) отката не было.
		if s.LastTCPHello.After(s.LastDrop.Add(p.FallbackGrace)) {
			continue
		}
		out = append(out, s.SNI)
	}
	sort.Strings(out)
	return out
}

// pruneTTL — после какого простоя запись удаляется при снятии снимка.
//
// Без удаления файл копил бы имена всех когда-либо посещённых QUIC-целей, и
// старое подозрение висело бы в doctor после того, как приложение давно
// исправилось или сеть сменилась. Десять минут — компромисс: достаточно, чтобы
// пережить короткую паузу в трафике, и мало, чтобы подозрение не было стухшим.
const pruneTTL = 10 * time.Minute

// Tracker копит наблюдения по именам. Потокобезопасен: BlockedQUIC зовётся из
// цикла блокировки QUIC, SawTCPHello — из цикла перехвата, снимок пишется из
// третьей горутины. Это не горячий путь на пакет: события редки (одно на
// соединение), поэтому мьютекс здесь дешевле безопасности от гонок.
type Tracker struct {
	mu    sync.Mutex
	stats map[string]*SNIStat
	dirty bool
}

// NewTracker создаёт пустой трекер.
func NewTracker() *Tracker {
	return &Tracker{stats: make(map[string]*SNIStat)}
}

// BlockedQUIC отмечает сброшенный QUIC Initial к имени sni.
func (t *Tracker) BlockedQUIC(sni string, at time.Time) {
	if sni == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.stats[sni]
	if s == nil {
		s = &SNIStat{SNI: sni}
		t.stats[sni] = s
	}
	s.Drops++
	s.LastDrop = at
	t.dirty = true
}

// SawTCPHello отмечает виденный TCP ClientHello с именем sni.
//
// Запись заводится только из сброса QUIC (BlockedQUIC): TCP-хелло по имени, к
// которому QUIC не блокировался, нас не интересует и память под него не
// выделяется. Поэтому здесь — только обновление существующей записи.
func (t *Tracker) SawTCPHello(sni string, at time.Time) {
	if sni == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.stats[sni]
	if s == nil {
		return // имя без сброса QUIC для признака «только QUIC» несущественно
	}
	s.LastTCPHello = at
	t.dirty = true
}

// Snapshot снимает отсортированную копию накопленного, попутно удаляя стухшие
// записи. now передаётся параметром: удаление по возрасту должно быть
// проверяемым без обращения к системным часам (тот же приём, что в control).
func (t *Tracker) Snapshot(now time.Time) Report {
	t.mu.Lock()
	defer t.mu.Unlock()
	rep := Report{}
	for sni, s := range t.stats {
		if now.Sub(s.LastDrop) > pruneTTL {
			delete(t.stats, sni)
			t.dirty = true
			continue
		}
		rep.SNIs = append(rep.SNIs, *s)
	}
	sort.Slice(rep.SNIs, func(i, j int) bool { return rep.SNIs[i].SNI < rep.SNIs[j].SNI })
	return rep
}

// Run периодически пишет снимок в path до отмены контекста.
//
// Пишет только при изменениях (как файл состояния control): в покое диск не
// трогается. Первый снимок пишется сразу, чтобы файл появился и doctor увидел
// «блокировка активна» без ожидания первого тика. На отмене пишется финальный
// снимок — последнее накопленное не теряется.
func (t *Tracker) Run(ctx context.Context, path string, interval time.Duration, now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	// Первый снимок — сразу: присутствие файла само по себе сигнал doctor.
	_ = WriteFile(path, t.Snapshot(now()))
	t.clearDirty()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Финальный снимок независимо от флага: на завершении лучше
			// записать лишний раз, чем потерять последнее накопленное.
			_ = WriteFile(path, t.Snapshot(now()))
			return
		case <-ticker.C:
			if !t.takeDirty() {
				continue
			}
			_ = WriteFile(path, t.Snapshot(now()))
		}
	}
}

// takeDirty сбрасывает и возвращает флаг изменений.
func (t *Tracker) takeDirty() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	d := t.dirty
	t.dirty = false
	return d
}

// clearDirty снимает флаг изменений (после внеочередной записи).
func (t *Tracker) clearDirty() {
	t.mu.Lock()
	t.dirty = false
	t.mu.Unlock()
}

// WriteFile атомарно записывает снимок в path: сначала во временный файл рядом,
// затем переименование. Атомарность нужна по той же причине, что у файла
// состояния: иначе doctor однажды прочитал бы половину JSON.
//
// Цена, названная честно: в отличие от файла состояния, здесь нет повторов на
// случай гонки замены при открытом читателе на Windows. Данные совещательные и
// редкие, разовый промах чтения doctor безвреден (следующий запуск прочитает),
// а усложнять ради этого не стоит.
func WriteFile(path string, r Report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("quicwatch: сериализация: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("quicwatch: каталог %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".quic-*")
	if err != nil {
		return fmt.Errorf("quicwatch: временный файл: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // при успехе файла уже нет, ошибка здесь не важна

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("quicwatch: запись: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("quicwatch: закрытие: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("quicwatch: замена файла: %w", err)
	}
	return nil
}

// ReadFile читает снимок из path. Разбор строгий: неизвестное поле — ошибка,
// чтобы CLI другой версии не принял неполные данные за полные (как у control).
func ReadFile(path string) (Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Report{}, err // «файла нет» вызывающий различает сам (os.IsNotExist)
	}
	var r Report
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Report{}, fmt.Errorf("quicwatch: разбор %s: %w", path, err)
	}
	return r, nil
}
