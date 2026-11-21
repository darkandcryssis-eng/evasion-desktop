package probe

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
)

var schedBase = time.Date(2026, 10, 17, 4, 0, 0, 0, time.UTC)

// fakePlanner отдаёт заранее заданный план.
type fakePlanner struct {
	plan Plan
	err  error
}

func (p fakePlanner) ProbePlan(context.Context) (Plan, error) { return p.plan, p.err }

// recordingSink запоминает выполненные пробы.
type recordingSink struct {
	mu    sync.Mutex
	items []PlanItem
}

func (s *recordingSink) ProbeDone(item PlanItem, _ Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, item)
}

func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// testClock — время, которым управляет тест: расписание нельзя проверять
// ожиданием настоящих двенадцати минут.
type testClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func schedulerConfig(planner Planner, sink Sink, clock *testClock) SchedulerConfig {
	return SchedulerConfig{
		Interval:         12 * time.Minute,
		DegradedInterval: 45 * time.Second,
		Jitter:           0.4,
		Workers:          8,
		PerTarget:        2,
		Planner:          planner,
		Sink:             sink,
		Probe: func(context.Context, Request) Result {
			return Result{Outcome: core.OutcomeOK, Reason: core.ReasonHandshakeDone}
		},
		Now: clock.now,
	}
}

func TestSchedulerProbesEveryPlanItem(t *testing.T) {
	clock := &testClock{at: schedBase}
	sink := &recordingSink{}
	planner := fakePlanner{plan: Plan{Items: []PlanItem{
		{Target: "youtube.com", Host: "www.youtube.com", StrategyID: "aaaa"},
		{Target: "youtube.com", Host: "www.youtube.com", StrategyID: "bbbb"},
		{Target: "discord.com", StrategyID: "aaaa"},
	}}}

	s, err := NewScheduler(schedulerConfig(planner, sink, clock))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	done, err := s.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if done != 3 || sink.count() != 3 {
		t.Fatalf("выполнено %d проб, приёмник получил %d, ожидалось по 3", done, sink.count())
	}
}

// TestSchedulerRespectsInterval закрепляет смысл расписания: пара, проверенная
// только что, второй раз не проверяется. Без этого планировщик жёг бы живые
// прогоны — самый дорогой ресурс движка (2.5).
func TestSchedulerRespectsInterval(t *testing.T) {
	clock := &testClock{at: schedBase}
	sink := &recordingSink{}
	planner := fakePlanner{plan: Plan{Items: []PlanItem{
		{Target: "youtube.com", StrategyID: "aaaa"},
	}}}

	s, err := NewScheduler(schedulerConfig(planner, sink, clock))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	if done, _ := s.RunOnce(context.Background()); done != 1 {
		t.Fatalf("первый круг: выполнено %d, ожидалась 1", done)
	}
	// Срок не истёк — пробы быть не должно.
	clock.advance(time.Minute)
	if done, _ := s.RunOnce(context.Background()); done != 0 {
		t.Fatalf("до истечения интервала выполнено %d проб, ожидалось 0", done)
	}
	// Срок истёк.
	clock.advance(12 * time.Minute)
	if done, _ := s.RunOnce(context.Background()); done != 1 {
		t.Fatalf("после интервала выполнено %d проб, ожидалась 1", done)
	}
}

// TestSchedulerProbesDegradedTargetSooner — 5.7: по деградированной цели замену
// надо искать быстро, поэтому её интервал короче обычного.
func TestSchedulerProbesDegradedTargetSooner(t *testing.T) {
	clock := &testClock{at: schedBase}
	sink := &recordingSink{}
	planner := fakePlanner{plan: Plan{Items: []PlanItem{
		{Target: "youtube.com", StrategyID: "aaaa", Degraded: true},
		{Target: "discord.com", StrategyID: "aaaa"},
	}}}

	s, err := NewScheduler(schedulerConfig(planner, sink, clock))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	if done, _ := s.RunOnce(context.Background()); done != 2 {
		t.Fatalf("первый круг: выполнено %d, ожидалось 2", done)
	}

	// Минута: деградированной цели пора (45 с), обычной — нет (12 мин).
	clock.advance(time.Minute)
	sink.items = nil
	done, _ := s.RunOnce(context.Background())
	if done != 1 {
		t.Fatalf("выполнено %d проб, ожидалась 1 — только по деградированной цели", done)
	}
	if sink.items[0].Target != "youtube.com" {
		t.Fatalf("проверена цель %q, ожидалась деградированная youtube.com", sink.items[0].Target)
	}
}

// TestSchedulerLimitsConcurrencyPerTarget — 5.4: если DPI держит состояние по
// адресу источника, параллельные пробы к одной цели коррелируют, и вместо N
// независимых наблюдений получается одно, размазанное на N. Предел нужен для
// достоверности, а не для скорости.
func TestSchedulerLimitsConcurrencyPerTarget(t *testing.T) {
	clock := &testClock{at: schedBase}
	sink := &recordingSink{}

	var items []PlanItem
	for i := range 10 {
		items = append(items, PlanItem{
			Target:     "youtube.com",
			StrategyID: core.StrategyID(string(rune('a' + i))),
		})
	}

	var inFlight, maxInFlight atomic.Int64
	cfg := schedulerConfig(fakePlanner{plan: Plan{Items: items}}, sink, clock)
	cfg.PerTarget = 2
	cfg.Workers = 8
	cfg.Probe = func(context.Context, Request) Result {
		cur := inFlight.Add(1)
		for {
			old := maxInFlight.Load()
			if cur <= old || maxInFlight.CompareAndSwap(old, cur) {
				break
			}
		}
		// Задержка нужна, чтобы пробы действительно пересеклись: без неё
		// каждая успевала бы завершиться до запуска следующей, и предел
		// остался бы непроверенным — тест был бы декоративным.
		time.Sleep(20 * time.Millisecond)
		inFlight.Add(-1)
		return Result{Outcome: core.OutcomeOK}
	}

	s, err := NewScheduler(cfg)
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	if done, _ := s.RunOnce(context.Background()); done != 10 {
		t.Fatalf("выполнено %d проб, ожидалось 10", done)
	}
	if got := maxInFlight.Load(); got > 2 {
		t.Fatalf("одновременных проб на цель %d, предел 2", got)
	}
	if got := maxInFlight.Load(); got < 2 {
		t.Fatalf("одновременных проб на цель всего %d: пробы не пересеклись, предел не проверен", got)
	}
}

// TestSchedulerUsesHostForRequest: цель радиуса — суффикс («youtube.com»), а
// ходить надо к работающему имени («www.youtube.com»). Иначе проба либо не
// получит ответа вовсе, либо наблюдение припишется не той цели.
func TestSchedulerUsesHostForRequest(t *testing.T) {
	clock := &testClock{at: schedBase}
	sink := &recordingSink{}

	var gotTarget, gotSNI string
	cfg := schedulerConfig(fakePlanner{plan: Plan{Items: []PlanItem{
		{Target: "youtube.com", Host: "www.youtube.com", StrategyID: "aaaa"},
	}}}, sink, clock)
	cfg.Probe = func(_ context.Context, req Request) Result {
		gotTarget, gotSNI = req.Target, req.SNI
		return Result{Outcome: core.OutcomeOK}
	}

	s, err := NewScheduler(cfg)
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if gotTarget != "www.youtube.com:443" || gotSNI != "www.youtube.com" {
		t.Fatalf("проба шла к %q (SNI %q), ожидалось www.youtube.com:443", gotTarget, gotSNI)
	}

	// Без Host проба идёт к самой цели: это законно для целей, которые
	// отвечают по своему имени.
	sink.items = nil
	cfg.Planner = fakePlanner{plan: Plan{Items: []PlanItem{{Target: "example.com", StrategyID: "aaaa"}}}}
	s2, err := NewScheduler(cfg)
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	if _, err := s2.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if gotTarget != "example.com:443" {
		t.Fatalf("проба шла к %q, ожидалось example.com:443", gotTarget)
	}
}

// TestSchedulerJitterStaysInBounds: разброс обязателен (5.7), но он не должен
// превращать интервал в произвольный — расписание осталось бы без смысла.
func TestSchedulerJitterStaysInBounds(t *testing.T) {
	clock := &testClock{at: schedBase}
	s, err := NewScheduler(schedulerConfig(fakePlanner{}, &recordingSink{}, clock))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	const base = time.Minute
	lo := time.Duration(float64(base) * 0.6)
	hi := time.Duration(float64(base) * 1.4)

	var sawShorter, sawLonger bool
	for range 200 {
		d := s.jittered(base)
		if d < lo || d > hi {
			t.Fatalf("интервал %v вне границ разброса [%v, %v]", d, lo, hi)
		}
		if d < base {
			sawShorter = true
		}
		if d > base {
			sawLonger = true
		}
	}
	// Разброс обязан быть симметричным: иначе среднее расписание уехало бы в
	// одну сторону от заданного.
	if !sawShorter || !sawLonger {
		t.Fatal("разброс односторонний: интервал обязан быть и короче, и длиннее заданного")
	}
}

func TestNewSchedulerRejectsBadConfig(t *testing.T) {
	clock := &testClock{at: schedBase}
	good := schedulerConfig(fakePlanner{}, &recordingSink{}, clock)

	for _, tc := range []struct {
		name  string
		spoil func(*SchedulerConfig)
	}{
		{"интервал ноль", func(c *SchedulerConfig) { c.Interval = 0 }},
		{"интервал деградации ноль", func(c *SchedulerConfig) { c.DegradedInterval = 0 }},
		{"деградация реже нормы", func(c *SchedulerConfig) { c.DegradedInterval = 2 * c.Interval }},
		{"разброс ноль", func(c *SchedulerConfig) { c.Jitter = 0 }},
		{"разброс больше единицы", func(c *SchedulerConfig) { c.Jitter = 1.5 }},
		{"воркеров ноль", func(c *SchedulerConfig) { c.Workers = 0 }},
		{"проб на цель больше воркеров", func(c *SchedulerConfig) { c.PerTarget = c.Workers + 1 }},
		{"нет плана", func(c *SchedulerConfig) { c.Planner = nil }},
		{"нет приёмника", func(c *SchedulerConfig) { c.Sink = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := good
			tc.spoil(&cfg)
			if _, err := NewScheduler(cfg); err == nil {
				t.Fatal("негодное расписание должно быть отвергнуто")
			}
		})
	}
}

// TestSchedulerRunStopsWithContext: остановка движка не должна превращаться в
// зависание расписания.
func TestSchedulerRunStopsWithContext(t *testing.T) {
	clock := &testClock{at: schedBase}
	sink := &recordingSink{}
	cfg := schedulerConfig(fakePlanner{plan: Plan{Items: []PlanItem{
		{Target: "example.com", StrategyID: "aaaa"},
	}}}, sink, clock)

	s, err := NewScheduler(cfg)
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	// Первый круг идёт сразу — ждать интервал на старте нельзя, иначе движок
	// остался бы без доказательств на первые двенадцать минут.
	deadline := time.Now().Add(2 * time.Second)
	for sink.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if sink.count() == 0 {
		t.Fatal("первый круг проб не состоялся сразу после запуска")
	}

	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run обязан вернуть причину остановки")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("расписание не остановилось по отмене контекста")
	}
}
