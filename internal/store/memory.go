package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
)

// Memory — хранилище в памяти.
//
// Нужно для двух дел. Во-первых, тестам: логика приёма, срезов и удаления по
// сроку проверяется без файлов и без внешних зависимостей, а значит быстро и
// на любой платформе. Во-вторых, запуску без хранилища на диске — движок
// работоспособен и так, просто теряет историю при остановке.
//
// Не предназначено для долгой работы: объём растёт, пока не вызовут Purge.
type Memory struct {
	mu     sync.RWMutex
	obs    []Observation
	events []StrategyEvent
}

// NewMemory создаёт пустое хранилище в памяти.
func NewMemory() *Memory { return &Memory{} }

// AppendObservations добавляет наблюдения, проверяя каждое.
//
// Непригодное наблюдение отвергает всю пачку. Это намеренно: пропустить
// частично значило бы молча потерять часть измерений, а узнать о потере
// вызывающему было бы нечем.
func (m *Memory) AppendObservations(_ context.Context, obs []Observation) error {
	for i := range obs {
		if err := obs[i].validate(); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.obs = append(m.obs, obs...)
	m.mu.Unlock()
	return nil
}

// AppendStrategyEvents добавляет события жизненного цикла.
func (m *Memory) AppendStrategyEvents(_ context.Context, events []StrategyEvent) error {
	for i := range events {
		if err := events[i].validate(); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.events = append(m.events, events...)
	m.mu.Unlock()
	return nil
}

// Tallies собирает срезы наблюдений по запросу.
func (m *Memory) Tallies(_ context.Context, q Query) ([]Tally, error) {
	if err := q.validate(); err != nil {
		return nil, err
	}
	until := q.Until
	if until.IsZero() {
		until = time.Now()
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Ключ среза — пара «стратегия, цель». Точка наблюдения в ключ не входит,
	// потому что запрос уже ограничен одной точкой: держать её в ключе значило
	// бы допускать смешивание, против которого ключ из 6.1 и устроен.
	type key struct {
		strategy core.StrategyID
		target   string
	}
	acc := make(map[key]*Tally)

	for i := range m.obs {
		o := m.obs[i]
		if o.VantageID != q.VantageID {
			continue
		}
		if q.Target != "" && o.Target != q.Target {
			continue
		}
		if q.StrategyID != "" && o.StrategyID != q.StrategyID {
			continue
		}
		if !q.IncludeAllPhases && o.Phase != q.Phase {
			continue
		}
		// Окно по времени: начало включительно, конец включительно. Иначе
		// наблюдение на самой границе терялось бы при склейке соседних окон.
		if o.At.Before(q.Since) || o.At.After(until) {
			continue
		}

		k := key{o.StrategyID, o.Target}
		t := acc[k]
		if t == nil {
			t = &Tally{
				StrategyID:     o.StrategyID,
				Target:         o.Target,
				Counts:         make(map[core.Outcome]int64, 4),
				WeightedCounts: make(map[core.Outcome]int64, 4),
				First:          o.At,
				Last:           o.At,
			}
			acc[k] = t
		}
		t.Counts[o.Outcome]++
		t.WeightedCounts[o.Outcome] += WeightPermille(o.Source)
		t.Total++
		if o.At.Before(t.First) {
			t.First = o.At
		}
		if o.At.After(t.Last) {
			t.Last = o.At
		}
	}

	out := make([]Tally, 0, len(acc))
	for _, t := range acc {
		out = append(out, *t)
	}
	// Устойчивый порядок: иначе вывод CLI и тесты менялись бы от запуска к
	// запуску, потому что обход карты в Go намеренно случаен.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].StrategyID < out[j].StrategyID
	})
	return out, nil
}

// Observations возвращает сырые наблюдения по запросу, от старых к новым.
//
// Фильтр повторяет Tallies, но вместо группировки отдаёт сами записи:
// прогреву оценок нужен порядок исходов, который срез теряет.
func (m *Memory) Observations(_ context.Context, q Query) ([]Observation, error) {
	if err := q.validate(); err != nil {
		return nil, err
	}
	until := q.Until
	if until.IsZero() {
		until = time.Now()
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []Observation
	for i := range m.obs {
		o := m.obs[i]
		if o.VantageID != q.VantageID {
			continue
		}
		if q.Target != "" && o.Target != q.Target {
			continue
		}
		if q.StrategyID != "" && o.StrategyID != q.StrategyID {
			continue
		}
		if !q.IncludeAllPhases && o.Phase != q.Phase {
			continue
		}
		// Окно по времени включительно с обоих концов, как у Tallies: иначе
		// наблюдение на границе терялось бы при склейке соседних окон.
		if o.At.Before(q.Since) || o.At.After(until) {
			continue
		}
		out = append(out, o)
	}

	// Устойчивая сортировка по времени: наблюдения, равные по времени,
	// сохраняют порядок вставки — он и есть порядок наступления, от которого
	// зависят серия провалов и чередование в scoring.
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

// StrategyEvents возвращает события стратегии от новых к старым.
func (m *Memory) StrategyEvents(_ context.Context, id core.StrategyID, limit int) ([]StrategyEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []StrategyEvent
	for i := len(m.events) - 1; i >= 0; i-- {
		if m.events[i].StrategyID != id {
			continue
		}
		out = append(out, m.events[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

// Purge удаляет устаревшее согласно сроку хранения.
//
// Нулевой срок означает «бессрочно» и ничего не удаляет: так задано для
// событий стратегий (6.4), объём которых мал, а история решений нужна.
func (m *Memory) Purge(_ context.Context, now time.Time, policy RetentionPolicy) (PurgeStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var stats PurgeStats

	if policy.Observations > 0 {
		cutoff := now.Add(-policy.Observations)
		kept := m.obs[:0]
		for _, o := range m.obs {
			if o.At.Before(cutoff) {
				stats.Observations++
				continue
			}
			kept = append(kept, o)
		}
		m.obs = kept
	}

	if policy.Events > 0 {
		cutoff := now.Add(-policy.Events)
		kept := m.events[:0]
		for _, e := range m.events {
			if e.At.Before(cutoff) {
				stats.Events++
				continue
			}
			kept = append(kept, e)
		}
		m.events = kept
	}

	return stats, nil
}

// Close ничего не делает: хранилище в памяти нечего закрывать.
func (m *Memory) Close() error { return nil }

// статическая проверка соответствия интерфейсу.
var _ Store = (*Memory)(nil)
