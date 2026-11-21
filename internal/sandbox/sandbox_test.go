package sandbox

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// Две заведомо валидных стратегии с разными деревьями — значит разными ID.
const (
	stratSend     = `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"send"}}]}`
	stratDisorder = `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"reverse"},"left":{"kind":"send"},"right":{"kind":"send"}}}]}`
)

func mustStrategy(t *testing.T, js string) *strategy.Strategy {
	t.Helper()
	s, err := strategy.Unmarshal([]byte(js), strategy.DefaultLimits())
	if err != nil {
		t.Fatalf("разбор стратегии: %v", err)
	}
	return s
}

func testCandidates(t *testing.T) []Candidate {
	return []Candidate{
		{Name: "send", Strategy: mustStrategy(t, stratSend)},
		{Name: "disorder", Strategy: mustStrategy(t, stratDisorder)},
	}
}

// probeCall — что видела проба в момент вызова.
type probeCall struct {
	target   string
	port     uint16
	boundID  core.StrategyID
	baseline bool
}

// fakeProber читает провайдер песочницы в момент пробы и записывает, какая
// стратегия была привязана к порту. Так проверяется главное свойство: на момент
// ClientHello пробы к её порту привязан именно её кандидат (а базовая линия —
// без привязки).
type fakeProber struct {
	provider proxy.StrategyProvider
	outcome  core.Outcome
	mu       sync.Mutex
	calls    []probeCall
}

func (f *fakeProber) Probe(_ context.Context, target string, port uint16) core.Outcome {
	sel := f.provider.Select(proxy.ConnMeta{LocalPort: port})
	f.mu.Lock()
	f.calls = append(f.calls, probeCall{
		target:   target,
		port:     port,
		boundID:  sel.ID,
		baseline: sel.Strategy == nil,
	})
	f.mu.Unlock()
	return f.outcome
}

type fakeReporter struct {
	mu  sync.Mutex
	obs []Observation
}

func (r *fakeReporter) Report(o Observation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.obs = append(r.obs, o)
}

func testConfig() Config {
	c := DefaultConfig()
	c.Jitter = 0 // детерминизм теста
	c.Round = time.Millisecond
	return c
}

func TestRunRoundEmitsBaselineAndCandidates(t *testing.T) {
	cands := testCandidates(t)
	rep := &fakeReporter{}
	fixed := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

	prober := &fakeProber{outcome: core.OutcomeOK}
	s, err := New(Options{
		Config:     testConfig(),
		Candidates: cands,
		Targets:    []string{"youtube.com"},
		Prober:     prober,
		Reporter:   rep,
		Now:        func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatal(err)
	}
	prober.provider = s.Provider()

	s.RunRound(context.Background())

	// Одна цель: базовая линия + два кандидата = три наблюдения.
	if len(rep.obs) != 3 {
		t.Fatalf("ожидалось 3 наблюдения, получено %d", len(rep.obs))
	}

	var baselines int
	seen := map[core.StrategyID]bool{}
	for _, o := range rep.obs {
		if o.Target != "youtube.com" {
			t.Fatalf("чужая цель в наблюдении: %q", o.Target)
		}
		if o.Outcome != core.OutcomeOK {
			t.Fatalf("исход не передан: %v", o.Outcome)
		}
		if !o.At.Equal(fixed) {
			t.Fatalf("время не из инъекции Now: %v", o.At)
		}
		if o.Baseline {
			baselines++
			if o.StrategyID != "" {
				t.Fatal("у базовой линии не должно быть стратегии")
			}
		} else {
			if o.StrategyID == "" {
				t.Fatal("у кандидата должна быть стратегия")
			}
			seen[o.StrategyID] = true
		}
	}
	if baselines != 1 {
		t.Fatalf("ожидалась ровно одна базовая линия, получено %d", baselines)
	}
	if len(seen) != 2 {
		t.Fatalf("ожидались наблюдения по двум разным кандидатам, получено %d", len(seen))
	}

	// Главное свойство: на момент пробы к её порту привязан именно её кандидат.
	for _, c := range prober.calls {
		if c.baseline {
			if c.boundID != "" {
				t.Fatal("базовая линия шла с привязанной стратегией")
			}
			continue
		}
		if c.boundID == "" {
			t.Fatalf("проба кандидата шла без привязки к порту %d", c.port)
		}
	}

	// Порты полностью возвращены в пул после обхода.
	if s.ports.available() != s.ports.size() {
		t.Fatalf("порты не возвращены: свободно %d из %d", s.ports.available(), s.ports.size())
	}
}

// TestPerTargetConcurrencyRespected проверяет предел одновременных проб на одну
// цель (5.4): сколько бы кандидатов ни было, к цели одновременно идёт не больше
// PerTarget проб.
func TestPerTargetConcurrencyRespected(t *testing.T) {
	// Много кандидатов, чтобы было что ограничивать.
	cands := make([]Candidate, 0, 8)
	for i := 0; i < 8; i++ {
		cands = append(cands, Candidate{Name: "s", Strategy: mustStrategy(t, stratSend)})
	}

	cfg := testConfig()
	cfg.Workers = 8
	cfg.PerTarget = 2

	cp := &concurrentProber{}
	s, err := New(Options{
		Config:     cfg,
		Candidates: cands,
		Targets:    []string{"youtube.com"},
		Prober:     cp,
		Reporter:   &fakeReporter{},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.RunRound(context.Background())

	if got := cp.max.Load(); got > int32(cfg.PerTarget) {
		t.Fatalf("предел на цель нарушен: наблюдалось %d одновременных проб при пределе %d", got, cfg.PerTarget)
	}
	if got := cp.max.Load(); got < 2 {
		t.Fatalf("параллельности не было вовсе (max=%d) — тест ничего не проверил", got)
	}
}

// concurrentProber считает пиковое число одновременных проб.
type concurrentProber struct {
	cur atomic.Int32
	max atomic.Int32
}

func (c *concurrentProber) Probe(_ context.Context, _ string, _ uint16) core.Outcome {
	n := c.cur.Add(1)
	for {
		m := c.max.Load()
		if n <= m || c.max.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(10 * time.Millisecond) // держим пробу, чтобы пики пересеклись
	c.cur.Add(-1)
	return core.OutcomeOK
}

// TestEvaluateOnDemand — оценка по требованию: привязывает стратегию к порту,
// гоняет пробы, возвращает число удач; на момент пробы к её порту привязан
// именно оцениваемый кандидат. Портфель и приёмник не нужны (режим генератора).
func TestEvaluateOnDemand(t *testing.T) {
	cand := mustStrategy(t, stratDisorder)
	cfg := testConfig()

	prober := &fakeProber{outcome: core.OutcomeOK}
	s, err := New(Options{
		Config:  cfg,
		Targets: []string{"youtube.com"},
		Prober:  prober,
		// Candidates и Reporter намеренно не заданы — Evaluate без них работает.
	})
	if err != nil {
		t.Fatal(err)
	}
	prober.provider = s.Provider()

	success, total := s.Evaluate(context.Background(), cand, "youtube.com", 5)
	if total != 5 || success != 5 {
		t.Fatalf("ожидалось 5/5 удач, получено %d/%d", success, total)
	}
	// На каждой пробе кандидат был привязан к её порту.
	for _, c := range prober.calls {
		if c.boundID != cand.ID {
			t.Fatalf("проба шла без привязки оцениваемого кандидата (порт %d, id %q)", c.port, c.boundID)
		}
	}
	// После оценки порты возвращены в пул.
	if s.ports.available() != s.ports.size() {
		t.Fatalf("порты не возвращены: свободно %d из %d", s.ports.available(), s.ports.size())
	}
}

// TestEvaluateBaseline — базовая линия (nil-стратегия) идёт без привязки порта.
func TestEvaluateBaseline(t *testing.T) {
	prober := &fakeProber{outcome: core.OutcomeFail}
	s, err := New(Options{
		Config:  testConfig(),
		Targets: []string{"youtube.com"},
		Prober:  prober,
	})
	if err != nil {
		t.Fatal(err)
	}
	prober.provider = s.Provider()

	success, total := s.Evaluate(context.Background(), nil, "youtube.com", 3)
	if total != 3 || success != 0 {
		t.Fatalf("базовая линия с провалами: ожидалось 0/3, получено %d/%d", success, total)
	}
	for _, c := range prober.calls {
		if !c.baseline {
			t.Fatal("базовая линия не должна привязывать стратегию к порту")
		}
	}
}

// TestRunWithoutPortfolioIsNoop — Run без портфеля/приёмника завершается сразу,
// не паникуя (режим «только Evaluate»).
func TestRunWithoutPortfolioIsNoop(t *testing.T) {
	s, err := New(Options{
		Config:  testConfig(),
		Targets: []string{"youtube.com"},
		Prober:  &fakeProber{outcome: core.OutcomeOK},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { s.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run без портфеля должен сразу завершиться")
	}
}

func TestNewValidation(t *testing.T) {
	good := Options{
		Config:     testConfig(),
		Candidates: []Candidate{{Name: "s", Strategy: mustStrategy(t, stratSend)}},
		Targets:    []string{"youtube.com"},
		Prober:     &fakeProber{},
		Reporter:   &fakeReporter{},
	}
	if _, err := New(good); err != nil {
		t.Fatalf("валидные опции отвергнуты: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Options)
	}{
		{"плохой конфиг", func(o *Options) { o.Config.Workers = 0 }},
		{"кандидат без стратегии", func(o *Options) { o.Candidates = []Candidate{{Name: "x"}} }},
		{"нет целей", func(o *Options) { o.Targets = nil }},
		{"нет пробера", func(o *Options) { o.Prober = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := good
			tc.mutate(&o)
			if _, err := New(o); err == nil {
				t.Fatalf("ожидалась ошибка для %q", tc.name)
			}
		})
	}

	// Пустой портфель и отсутствие приёмника теперь законны — режим «только
	// Evaluate» (генератор): New не должен их отвергать.
	evalOnly := good
	evalOnly.Candidates = nil
	evalOnly.Reporter = nil
	if _, err := New(evalOnly); err != nil {
		t.Fatalf("режим только Evaluate должен быть законен: %v", err)
	}
}

// TestRunStopsOnContext проверяет, что непрерывный цикл завершается по отмене.
func TestRunStopsOnContext(t *testing.T) {
	prober := &fakeProber{outcome: core.OutcomeOK}
	s, err := New(Options{
		Config:     testConfig(),
		Candidates: testCandidates(t),
		Targets:    []string{"youtube.com"},
		Prober:     prober,
		Reporter:   &fakeReporter{},
	})
	if err != nil {
		t.Fatal(err)
	}
	prober.provider = s.Provider()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run не завершился по отмене контекста")
	}
}

// TestCancelledProbeNotReported: исход пробы, отменённой во время измерения, не
// учитывается — он получен на оборванном измерении. Отмену вызывает сам пробер
// (середина пробы), чтобы проверить именно проверку ctx.Err() после Probe, а
// не ранний выход на семафоре.
func TestCancelledProbeNotReported(t *testing.T) {
	rep := &fakeReporter{}
	cp := &midCancelProber{}
	s, err := New(Options{
		Config:     testConfig(),
		Candidates: []Candidate{{Name: "s", Strategy: mustStrategy(t, stratSend)}},
		Targets:    []string{"youtube.com"},
		Prober:     cp,
		Reporter:   rep,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cp.cancel = cancel
	s.RunRound(ctx)
	if len(rep.obs) != 0 {
		t.Fatalf("исход отменённой во время пробы не должен учитываться, получено %d", len(rep.obs))
	}
}

// midCancelProber отменяет контекст в середине пробы и всё равно возвращает
// исход: так проверяется, что runJob отбрасывает исход по ctx.Err() после Probe.
type midCancelProber struct{ cancel context.CancelFunc }

func (m *midCancelProber) Probe(_ context.Context, _ string, _ uint16) core.Outcome {
	m.cancel()
	return core.OutcomeOK
}
