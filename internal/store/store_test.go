package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
)

const (
	testVantage = core.VantageID("v1")
	testTarget  = "www.example.com"
)

// obs собирает годное наблюдение, меняя только то, что нужно тесту.
func obs(at time.Time, mods ...func(*Observation)) Observation {
	o := Observation{
		At:         at,
		StrategyID: core.StrategyID("s1"),
		Target:     testTarget,
		VantageID:  testVantage,
		Phase:      core.PhaseFast,
		Outcome:    core.OutcomeOK,
		Reason:     core.ReasonHandshakeDone,
		Source:     SourceProbe,
	}
	for _, m := range mods {
		m(&o)
	}
	return o
}

func TestObservationValidationRejectsMissingKey(t *testing.T) {
	// Наблюдение без части ключа не ошибочно по форме, но бессмысленно по
	// сути: попав в хранилище, оно навсегда испортит срезы, и починить это
	// нечем — утраченный контекст не восстановить.
	now := time.Now()
	cases := []struct {
		name   string
		mod    func(*Observation)
		errHas string
	}{
		{"без времени", func(o *Observation) { o.At = time.Time{} }, "без времени"},
		{"без цели", func(o *Observation) { o.Target = "" }, "без цели"},
		{"без точки наблюдения", func(o *Observation) { o.VantageID = "" }, "без точки наблюдения"},
		{"без источника", func(o *Observation) { o.Source = SourceUnknown }, "без источника"},
	}
	m := NewMemory()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := m.AppendObservations(context.Background(), []Observation{obs(now, c.mod)})
			if err == nil {
				t.Fatalf("ожидалась ошибка с %q", c.errHas)
			}
			if !strings.Contains(err.Error(), c.errHas) {
				t.Fatalf("ошибка %q не содержит %q", err, c.errHas)
			}
		})
	}
}

func TestAppendRejectsWholeBatchOnBadRecord(t *testing.T) {
	// Частичный приём означал бы молчаливую потерю части измерений, о которой
	// вызывающему нечем узнать.
	now := time.Now()
	m := NewMemory()
	err := m.AppendObservations(context.Background(), []Observation{
		obs(now),
		obs(now, func(o *Observation) { o.VantageID = "" }),
	})
	if err == nil {
		t.Fatal("пачка с непригодной записью должна отвергаться целиком")
	}
	tallies, err := m.Tallies(context.Background(), Query{VantageID: testVantage, Since: now.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("Tallies: %v", err)
	}
	if len(tallies) != 0 {
		t.Fatalf("после отвергнутой пачки в хранилище %d срезов", len(tallies))
	}
}

func TestTalliesGroupAndWeight(t *testing.T) {
	now := time.Now()
	m := NewMemory()

	// Три наблюдения одной стратегии: два активных успеха и один пассивный.
	err := m.AppendObservations(context.Background(), []Observation{
		obs(now.Add(-3 * time.Minute)),
		obs(now.Add(-2 * time.Minute)),
		obs(now.Add(-time.Minute), func(o *Observation) {
			o.Source = SourcePassive
			o.Outcome = core.OutcomeFail
			o.Reason = core.ReasonTimeout
		}),
	})
	if err != nil {
		t.Fatalf("AppendObservations: %v", err)
	}

	tallies, err := m.Tallies(context.Background(), Query{
		VantageID: testVantage,
		Since:     now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("Tallies: %v", err)
	}
	if len(tallies) != 1 {
		t.Fatalf("срезов %d, ожидался один", len(tallies))
	}
	tl := tallies[0]
	if tl.Total != 3 {
		t.Fatalf("всего наблюдений %d", tl.Total)
	}
	if tl.Counts[core.OutcomeOK] != 2 || tl.Counts[core.OutcomeFail] != 1 {
		t.Fatalf("количества по исходам %v", tl.Counts)
	}
	// Вес активного наблюдения — единица, пассивного — 0.3 (5.7). В тысячных
	// это 1000 и 300.
	if got := tl.WeightedCounts[core.OutcomeOK]; got != 2000 {
		t.Fatalf("взвешенные успехи %d, ожидалось 2000", got)
	}
	if got := tl.WeightedCounts[core.OutcomeFail]; got != 300 {
		t.Fatalf("взвешенные провалы %d, ожидалось 300 (пассивное наблюдение)", got)
	}
	// Время первого и последнего нужно признаку свежести (4.5).
	if !tl.First.Equal(now.Add(-3 * time.Minute)) {
		t.Fatalf("первое наблюдение %v", tl.First)
	}
	if !tl.Last.Equal(now.Add(-time.Minute)) {
		t.Fatalf("последнее наблюдение %v", tl.Last)
	}
}

func TestTalliesSeparateByVantage(t *testing.T) {
	// Главное свойство ключа из 6.1: наблюдения разных точек наблюдения не
	// смешиваются. Иначе оценки чужой сети применялись бы как свои.
	now := time.Now()
	m := NewMemory()
	_ = m.AppendObservations(context.Background(), []Observation{
		obs(now),
		obs(now, func(o *Observation) { o.VantageID = "v2" }),
		obs(now, func(o *Observation) { o.VantageID = "v2" }),
	})

	first, _ := m.Tallies(context.Background(), Query{VantageID: testVantage, Since: now.Add(-time.Hour)})
	if len(first) != 1 || first[0].Total != 1 {
		t.Fatalf("срез первой точки: %+v", first)
	}
	second, _ := m.Tallies(context.Background(), Query{VantageID: "v2", Since: now.Add(-time.Hour)})
	if len(second) != 1 || second[0].Total != 2 {
		t.Fatalf("срез второй точки: %+v", second)
	}
}

func TestTalliesSeparateByTargetAndStrategy(t *testing.T) {
	now := time.Now()
	m := NewMemory()
	_ = m.AppendObservations(context.Background(), []Observation{
		obs(now),
		obs(now, func(o *Observation) { o.Target = "other.example.com" }),
		obs(now, func(o *Observation) { o.StrategyID = "s2" }),
	})

	all, err := m.Tallies(context.Background(), Query{VantageID: testVantage, Since: now.Add(-time.Hour)})
	if err != nil {
		t.Fatalf("Tallies: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("срезов %d, ожидалось три разных ключа: %+v", len(all), all)
	}
	// Порядок устойчив: обход карты в Go случаен, и без сортировки вывод CLI
	// и тесты менялись бы от запуска к запуску.
	if all[0].Target != "other.example.com" {
		t.Fatalf("порядок срезов неустойчив: %+v", all)
	}
}

func TestTalliesPhaseFilter(t *testing.T) {
	now := time.Now()
	m := NewMemory()
	_ = m.AppendObservations(context.Background(), []Observation{
		obs(now),
		obs(now, func(o *Observation) { o.Phase = core.PhaseSlow }),
	})

	fast, _ := m.Tallies(context.Background(), Query{VantageID: testVantage, Since: now.Add(-time.Hour)})
	if len(fast) != 1 || fast[0].Total != 1 {
		t.Fatalf("быстрый уровень: %+v", fast)
	}
	both, _ := m.Tallies(context.Background(), Query{
		VantageID: testVantage, Since: now.Add(-time.Hour), IncludeAllPhases: true,
	})
	if len(both) != 1 || both[0].Total != 2 {
		t.Fatalf("оба уровня: %+v", both)
	}
}

func TestTalliesTimeWindowInclusive(t *testing.T) {
	// Границы окна включительны: иначе наблюдение ровно на границе терялось бы
	// при склейке соседних окон.
	now := time.Now().Truncate(time.Second)
	m := NewMemory()
	_ = m.AppendObservations(context.Background(), []Observation{
		obs(now.Add(-time.Hour)),
		obs(now),
		obs(now.Add(time.Hour)),
	})

	got, err := m.Tallies(context.Background(), Query{
		VantageID: testVantage, Since: now.Add(-time.Hour), Until: now,
	})
	if err != nil {
		t.Fatalf("Tallies: %v", err)
	}
	if len(got) != 1 || got[0].Total != 2 {
		t.Fatalf("в окно попало %+v, ожидались обе границы", got)
	}
}

func TestQueryValidation(t *testing.T) {
	m := NewMemory()
	now := time.Now()
	if _, err := m.Tallies(context.Background(), Query{}); err == nil {
		t.Fatal("запрос без точки наблюдения должен отвергаться")
	}
	_, err := m.Tallies(context.Background(), Query{
		VantageID: testVantage, Since: now, Until: now.Add(-time.Hour),
	})
	if err == nil {
		t.Fatal("вывернутое окно времени должно отвергаться")
	}
}

func TestStrategyEventsNewestFirst(t *testing.T) {
	now := time.Now()
	m := NewMemory()
	err := m.AppendStrategyEvents(context.Background(), []StrategyEvent{
		{At: now.Add(-2 * time.Hour), StrategyID: "s1", Kind: EventCreated},
		{At: now.Add(-time.Hour), StrategyID: "s1", Kind: EventStatusChanged, From: "candidate", To: "testing"},
		{At: now, StrategyID: "s2", Kind: EventCreated},
	})
	if err != nil {
		t.Fatalf("AppendStrategyEvents: %v", err)
	}

	got, err := m.StrategyEvents(context.Background(), "s1", 0)
	if err != nil {
		t.Fatalf("StrategyEvents: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("событий %d, ожидалось два", len(got))
	}
	if got[0].Kind != EventStatusChanged {
		t.Fatalf("первым пришло %v, ожидалось новейшее", got[0].Kind)
	}

	limited, _ := m.StrategyEvents(context.Background(), "s1", 1)
	if len(limited) != 1 {
		t.Fatalf("при пределе 1 получено %d", len(limited))
	}
}

func TestStrategyEventValidation(t *testing.T) {
	m := NewMemory()
	now := time.Now()
	cases := []StrategyEvent{
		{StrategyID: "s1", Kind: EventCreated},          // без времени
		{At: now, Kind: EventCreated},                   // без стратегии
		{At: now, StrategyID: "s1", Kind: EventUnknown}, // без вида
	}
	for i, e := range cases {
		if err := m.AppendStrategyEvents(context.Background(), []StrategyEvent{e}); err == nil {
			t.Fatalf("случай %d: ожидалась ошибка", i)
		}
	}
}

func TestPurgeRespectsPolicy(t *testing.T) {
	now := time.Now()
	m := NewMemory()
	_ = m.AppendObservations(context.Background(), []Observation{
		obs(now.Add(-40 * 24 * time.Hour)),
		obs(now.Add(-10 * 24 * time.Hour)),
	})
	_ = m.AppendStrategyEvents(context.Background(), []StrategyEvent{
		{At: now.Add(-400 * 24 * time.Hour), StrategyID: "s1", Kind: EventCreated},
	})

	// Срок наблюдений 30 суток, событий — бессрочно (ноль). Старое наблюдение
	// удаляется, событие остаётся: история решений нужна, чтобы разобрать
	// прошлое поведение автопилота (6.4).
	stats, err := m.Purge(context.Background(), now, RetentionPolicy{Observations: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if stats.Observations != 1 {
		t.Fatalf("удалено наблюдений %d, ожидалось одно", stats.Observations)
	}
	if stats.Events != 0 {
		t.Fatalf("удалено событий %d при бессрочном хранении", stats.Events)
	}

	left, _ := m.Tallies(context.Background(), Query{VantageID: testVantage, Since: now.Add(-100 * 24 * time.Hour)})
	if len(left) != 1 || left[0].Total != 1 {
		t.Fatalf("после удаления осталось %+v", left)
	}
	events, _ := m.StrategyEvents(context.Background(), "s1", 0)
	if len(events) != 1 {
		t.Fatalf("события стратегии удалены вопреки бессрочному хранению")
	}
}

func TestSourceTokensRoundTrip(t *testing.T) {
	for _, s := range []Source{SourceProbe, SourcePassive, SourceLiveTraffic} {
		text, err := s.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%v): %v", s, err)
		}
		var back Source
		if err := back.UnmarshalText(text); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", text, err)
		}
		if back != s {
			t.Fatalf("круговой перенос %v дал %v", s, back)
		}
	}
	var s Source
	if err := s.UnmarshalText([]byte("не-такой-источник")); err == nil {
		t.Fatal("неизвестное обозначение источника должно отвергаться")
	} else {
		var ute *core.UnknownTokenError
		if !errors.As(err, &ute) {
			t.Fatalf("ожидалась UnknownTokenError, получено %T", err)
		}
	}
}

// failingStore — хранилище, которое всегда отказывает. Нужно, чтобы проверить:
// ошибка асинхронной записи не теряется молча.
type failingStore struct{ err error }

func (f failingStore) AppendObservations(context.Context, []Observation) error { return f.err }
func (f failingStore) AppendStrategyEvents(context.Context, []StrategyEvent) error {
	return f.err
}
func (f failingStore) Tallies(context.Context, Query) ([]Tally, error) { return nil, f.err }
func (f failingStore) Observations(context.Context, Query) ([]Observation, error) {
	return nil, f.err
}
func (f failingStore) StrategyEvents(context.Context, core.StrategyID, int) ([]StrategyEvent, error) {
	return nil, f.err
}
func (f failingStore) Purge(context.Context, time.Time, RetentionPolicy) (PurgeStats, error) {
	return PurgeStats{}, f.err
}
func (f failingStore) Close() error { return nil }

func TestWriterFlushesOnClose(t *testing.T) {
	// Принятое при остановке терять нельзя: вызывающий считает эти наблюдения
	// сохранёнными.
	now := time.Now()
	m := NewMemory()
	w, err := NewWriter(m, WriterConfig{BatchSize: 1000, FlushInterval: time.Hour})
	if err != nil { t.Fatalf("NewWriter: %v", err) }

	for range 5 {
		if !w.Enqueue(obs(now)) {
			t.Fatal("наблюдение отброшено при свободной очереди")
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, _ := m.Tallies(context.Background(), Query{VantageID: testVantage, Since: now.Add(-time.Hour)})
	if len(got) != 1 || got[0].Total != 5 {
		t.Fatalf("после остановки сохранено %+v, ожидалось пять наблюдений", got)
	}
}

func TestWriterBatchesByCount(t *testing.T) {
	now := time.Now()
	m := NewMemory()
	w, err := NewWriter(m, WriterConfig{BatchSize: 3, FlushInterval: time.Hour})
	if err != nil { t.Fatalf("NewWriter: %v", err) }
	defer w.Close()

	for range 3 {
		w.Enqueue(obs(now))
	}

	// Ждём, пока горутина записи дойдёт до полной пачки. Опрос, а не сон на
	// фиксированный срок: иначе тест был бы плавающим на загруженной машине.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := m.Tallies(context.Background(), Query{VantageID: testVantage, Since: now.Add(-time.Hour)})
		if len(got) == 1 && got[0].Total == 3 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("полная пачка не записана за отведённое время")
}

// TestWriterDropsInsteadOfBlocking — главное свойство приёмника.
//
// При переполнении наблюдения отбрасываются, а не ждут записи. Ожидание на
// горячем пути означало бы, что замедление диска замедляет сам обход, то есть
// наблюдение портит наблюдаемое. Потери при этом считаются: измерению с
// потерями верить можно только зная о них.
func TestWriterDropsInsteadOfBlocking(t *testing.T) {
	now := time.Now()

	// Хранилище, которое держит запись, пока тест не разрешит: так очередь
	// гарантированно переполняется.
	blocked := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(blocked) }) }
	defer release()

	var droppedCalls atomic.Int64
	w, err := NewWriter(blockingStore{gate: blocked}, WriterConfig{
		QueueSize:     2,
		BatchSize:     1,
		FlushInterval: time.Hour,
		OnDropped:     func() { droppedCalls.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// Кладём заметно больше, чем вмещает очередь — в отдельной горутине и под
	// сроком. Если приёмник вздумает ждать, тест обязан провалиться быстро и
	// внятно, а не зависнуть до общего предела: зависший тест в чужом прогоне
	// выглядит поломкой окружения, а не нарушением свойства.
	accepted := 0
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for range 50 {
			if w.Enqueue(obs(now)) {
				accepted++
			}
		}
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Enqueue заблокировался при полной очереди вместо отбрасывания")
	}

	if w.Dropped() == 0 {
		t.Fatalf("при очереди на 2 места принято %d наблюдений без потерь", accepted)
	}
	if droppedCalls.Load() != w.Dropped() {
		t.Fatalf("обратный вызов сработал %d раз при %d потерях",
			droppedCalls.Load(), w.Dropped())
	}
	release()
	_ = w.Close()
}

// blockingStore держит запись до открытия затвора.
type blockingStore struct{ gate chan struct{} }

func (b blockingStore) AppendObservations(ctx context.Context, _ []Observation) error {
	select {
	case <-b.gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (b blockingStore) AppendStrategyEvents(context.Context, []StrategyEvent) error { return nil }
func (b blockingStore) Tallies(context.Context, Query) ([]Tally, error)             { return nil, nil }
func (b blockingStore) Observations(context.Context, Query) ([]Observation, error) {
	return nil, nil
}
func (b blockingStore) StrategyEvents(context.Context, core.StrategyID, int) ([]StrategyEvent, error) {
	return nil, nil
}
func (b blockingStore) Purge(context.Context, time.Time, RetentionPolicy) (PurgeStats, error) {
	return PurgeStats{}, nil
}
func (b blockingStore) Close() error { return nil }

func TestWriterReportsWriteError(t *testing.T) {
	// Ошибку асинхронной записи нельзя вернуть вызывающему: к моменту сбоя он
	// давно продолжил работу. Молча терять её тоже нельзя — иначе движок
	// считал бы наблюдения сохранёнными, а оценки опирались бы на данные,
	// которых нет.
	want := errors.New("диск отказал")
	got := make(chan error, 1)
	w, werr := NewWriter(failingStore{err: want}, WriterConfig{
		BatchSize:     1,
		FlushInterval: time.Hour,
		OnError: func(err error) {
			select {
			case got <- err:
			default:
			}
		},
	})
	if werr != nil {
		t.Fatalf("NewWriter: %v", werr)
	}

	w.Enqueue(obs(time.Now()))

	select {
	case err := <-got:
		if !errors.Is(err, want) {
			t.Fatalf("сообщена ошибка %v, ожидалась %v", err, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ошибка записи не сообщена наружу")
	}
	_ = w.Close()
}

func TestWriterEnqueueAfterCloseIsSafe(t *testing.T) {
	// Close может быть вызван из обработчика сигнала, пока горячий путь ещё
	// кладёт наблюдения. Запись в закрытый канал вызвала бы панику, а паника
	// на горячем пути уронила бы движок.
	w, err := NewWriter(NewMemory(), WriterConfig{})
	if err != nil { t.Fatalf("NewWriter: %v", err) }
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if w.Enqueue(obs(time.Now())) {
		t.Fatal("закрытый приёмник принял наблюдение")
	}
	if w.EnqueueEvent(StrategyEvent{At: time.Now(), StrategyID: "s1", Kind: EventCreated}) {
		t.Fatal("закрытый приёмник принял событие")
	}
	// Повторное закрытие не должно паниковать.
	if err := w.Close(); err != nil {
		t.Fatalf("повторный Close: %v", err)
	}
}

func TestWriterConcurrentEnqueue(t *testing.T) {
	// Наблюдения кладутся из многих горутин: воркеры проб и путь соединений
	// работают одновременно (5.4).
	now := time.Now()
	m := NewMemory()
	w, err := NewWriter(m, WriterConfig{QueueSize: 4096, BatchSize: 64, FlushInterval: 10 * time.Millisecond})
	if err != nil { t.Fatalf("NewWriter: %v", err) }

	var wg sync.WaitGroup
	const goroutines, perGoroutine = 8, 100
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range perGoroutine {
				w.Enqueue(obs(now))
			}
		}()
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, _ := m.Tallies(context.Background(), Query{VantageID: testVantage, Since: now.Add(-time.Hour)})
	accepted := int64(goroutines*perGoroutine) - w.Dropped()
	if len(got) != 1 || got[0].Total != accepted {
		t.Fatalf("сохранено %+v, принято %d, отброшено %d", got, accepted, w.Dropped())
	}
}

type writerCloseCountingStore struct {
	*Memory
	closes int
	err    error
}

func (s *writerCloseCountingStore) Close() error {
	s.closes++
	return s.err
}

func TestWriterCloseClosesUnderlyingStoreOnce(t *testing.T) {
	want := errors.New("close failed")
	s := &writerCloseCountingStore{Memory: NewMemory(), err: want}
	w, err := NewWriter(s, WriterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := w.Close(); !errors.Is(err, want) {
			t.Fatalf("Close: got %v, want %v", err, want)
		}
	}
	if s.closes != 1 {
		t.Fatalf("underlying store closed %d times, want 1", s.closes)
	}
}

// TestMemoryObservationsOrderAndFilter: хранилище в памяти отдаёт сырые
// наблюдения по возрастанию времени и уважает фильтры запроса. Нужно прогреву
// оценок и тестам, которые проверяют его без диска.
func TestMemoryObservationsOrderAndFilter(t *testing.T) {
	m := NewMemory()
	base := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

	batch := []Observation{
		obs(base.Add(2*time.Second), func(o *Observation) { o.Outcome = core.OutcomeFail }),
		obs(base, func(o *Observation) { o.Outcome = core.OutcomeOK }),
		obs(base.Add(time.Second), func(o *Observation) {
			o.Outcome = core.OutcomeOK
			o.StrategyID = "s2"
		}),
	}
	if err := m.AppendObservations(context.Background(), batch); err != nil {
		t.Fatalf("запись: %v", err)
	}

	// Без фильтра стратегии — все три, по возрастанию времени.
	all, err := m.Observations(context.Background(), Query{
		VantageID: testVantage, Since: base.Add(-time.Hour), IncludeAllPhases: true,
	})
	if err != nil {
		t.Fatalf("Observations: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("прочитано %d, ожидалось 3", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].At.Before(all[i-1].At) {
			t.Fatalf("порядок времени нарушен: %v до %v", all[i-1].At, all[i].At)
		}
	}

	// Фильтр по стратегии оставляет только её наблюдения.
	s2, err := m.Observations(context.Background(), Query{
		VantageID: testVantage, StrategyID: "s2", Since: base.Add(-time.Hour), IncludeAllPhases: true,
	})
	if err != nil {
		t.Fatalf("Observations: %v", err)
	}
	if len(s2) != 1 || s2[0].StrategyID != "s2" {
		t.Fatalf("фильтр по стратегии вернул %+v", s2)
	}
}

// TestMemoryObservationsRejectsQueryWithoutVantage: запрос без точки наблюдения
// отвергается — смешивать наблюдения из разных сетей нельзя (6.1).
func TestMemoryObservationsRejectsQueryWithoutVantage(t *testing.T) {
	m := NewMemory()
	if _, err := m.Observations(context.Background(), Query{Since: time.Now().Add(-time.Hour)}); err == nil {
		t.Fatal("запрос без точки наблюдения должен отвергаться")
	}
}
