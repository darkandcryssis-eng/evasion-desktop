package main

import (
	"context"
	"io"
	"log/slog"
	"math/rand/v2"
	"testing"

	"github.com/fitting-1c/evasion/internal/control"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/generator"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/sandbox"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// discardLog — журнал в никуда для тестов оценщика.
func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// bypassProber имитирует цель, заблокированную без десинка и доступную с ним:
// проба успешна, только если к её порту привязана стратегия (кандидат), и
// проваливается без привязки (базовая линия). На этом видно превосходство.
type bypassProber struct{ provider proxy.StrategyProvider }

func (p bypassProber) Probe(_ context.Context, _ string, port uint16) core.Outcome {
	if p.provider.Select(proxy.ConnMeta{LocalPort: port}).Strategy != nil {
		return core.OutcomeOK
	}
	return core.OutcomeFail
}

func TestSandboxEvaluatorFitness(t *testing.T) {
	prober := &bypassProber{}
	sb, err := sandbox.New(sandbox.Options{
		Config:  sandbox.DefaultConfig(),
		Targets: []string{"youtube.com", "discord.com"},
		Prober:  prober,
	})
	if err != nil {
		t.Fatal(err)
	}
	prober.provider = sb.Provider()
	ev := &sandboxEvaluator{sb: sb, targets: []string{"youtube.com", "discord.com"}, probes: 3, log: discardLog()}

	s, err := strategy.Unmarshal([]byte(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"send"}}]}`), strategy.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	fit, err := ev.Fitness(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	// Кандидат обходит (успех), базовая линия нет → превосходство 1.0.
	if fit != 1.0 {
		t.Fatalf("ожидалось превосходство 1.0, получено %v", fit)
	}
}

// TestSandboxEvaluatorNoAdvantage — если цель доступна и без десинка (проба
// всегда успешна), превосходство нулевое: неприменившаяся/бесполезная стратегия
// не выглядит находкой. Это и есть защита от ложных 100%.
func TestSandboxEvaluatorNoAdvantage(t *testing.T) {
	sb, err := sandbox.New(sandbox.Options{
		Config:  sandbox.DefaultConfig(),
		Targets: []string{"youtube.com"},
		Prober:  okProber{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ev := &sandboxEvaluator{sb: sb, targets: []string{"youtube.com"}, probes: 3, log: discardLog()}
	s, _ := strategy.Unmarshal([]byte(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"send"}}]}`), strategy.DefaultLimits())
	fit, err := ev.Fitness(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if fit != 0 {
		t.Fatalf("при доступной без десинка цели превосходство должно быть 0, получено %v", fit)
	}
}

// okProber — проба, всегда сообщающая успех (цель доступна и без десинка).
type okProber struct{}

func (okProber) Probe(context.Context, string, uint16) core.Outcome { return core.OutcomeOK }

func TestSandboxEvaluatorCancelled(t *testing.T) {
	sb, err := sandbox.New(sandbox.Options{
		Config:  sandbox.DefaultConfig(),
		Targets: []string{"youtube.com"},
		Prober:  okProber{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ev := &sandboxEvaluator{sb: sb, targets: []string{"youtube.com"}, probes: 3, log: discardLog()}
	s, _ := strategy.Unmarshal([]byte(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"send"}}]}`), strategy.DefaultLimits())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ev.Fitness(ctx, s); err == nil {
		t.Fatal("отменённый контекст должен дать ошибку, чтобы поиск остановился")
	}
}

func TestBuildSearchResultTopAndSerialization(t *testing.T) {
	mk := func(js string, fit float64) generator.Individual {
		s, err := strategy.Unmarshal([]byte(js), strategy.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		return generator.Individual{Strategy: s, Fitness: fit}
	}
	pop := []generator.Individual{
		mk(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"send"}}]}`, 0.9),
		mk(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"drop"}}]}`, 0.5),
		mk(`{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"duplicate","left":{"kind":"send"},"right":{"kind":"send"}}}]}`, 0.1),
	}

	r := buildSearchResult(pop, 2, 0, 5, 3, 42, []string{"youtube.com"})
	if len(r.Found) != 2 {
		t.Fatalf("ожидалось 2 лучших, получено %d", len(r.Found))
	}
	if r.Found[0].Fitness != 0.9 {
		t.Fatalf("первый не лучший: доля %v", r.Found[0].Fitness)
	}
	// Сериализованное дерево должно разбираться обратно (контракт 10.2).
	if _, err := strategy.Unmarshal(r.Found[0].Strategy, strategy.DefaultLimits()); err != nil {
		t.Fatalf("дерево найденной стратегии не разбирается: %v", err)
	}
	// top больше популяции — берём сколько есть, без паники.
	r2 := buildSearchResult(pop, 10, 0, 5, 3, 42, nil)
	if len(r2.Found) != 3 {
		t.Fatalf("при top>len ожидалось 3, получено %d", len(r2.Found))
	}
}

// mkStrat разбирает дерево стратегии для тестов фонового генератора.
func mkStrat(t *testing.T, js string) *strategy.Strategy {
	t.Helper()
	s, err := strategy.Unmarshal([]byte(js), strategy.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestBgParentsSelectsByEvidenceAndScore проверяет отбор родителей: берутся
// только стратегии из пула с надёжной оценкой (Have ≥ bgMinEvidence), по
// убыванию нижней границы, а действующая стратегия — заведомо сильный родитель.
func TestBgParentsSelectsByEvidenceAndScore(t *testing.T) {
	active := mkStrat(t, `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"send"}}]}`)
	strong := mkStrat(t, `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"drop"}}]}`)
	weak := mkStrat(t, `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"duplicate","left":{"kind":"send"},"right":{"kind":"send"}}}]}`)
	// thin — надёжной оценки нет (Have < bgMinEvidence): в родители не идёт.
	thin := mkStrat(t, `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"duplicate","left":{"kind":"drop"},"right":{"kind":"send"}}}]}`)

	pool := map[core.StrategyID]*strategy.Strategy{
		active.ID: active, strong.ID: strong, weak.ID: weak, thin.ID: thin,
	}
	st := control.Status{Targets: []control.TargetStatus{{
		Target: "youtube.com",
		Active: active.ID,
		Candidates: []control.CandidateStatus{
			{StrategyID: strong.ID, Have: 10, LowerPermille: 800},
			{StrategyID: weak.ID, Have: 10, LowerPermille: 500},
			{StrategyID: thin.ID, Have: 2, LowerPermille: 999},
		},
	}}}

	parents := bgParents(pool, st)
	// active (1000) > strong (800) > weak (500); thin отброшен по объёму.
	if len(parents) != 3 {
		t.Fatalf("ожидалось 3 родителя, получено %d", len(parents))
	}
	if parents[0].ID != active.ID {
		t.Fatalf("действующая стратегия должна быть первым родителем, получено %s", short(parents[0].ID.String()))
	}
	if parents[1].ID != strong.ID || parents[2].ID != weak.ID {
		t.Fatal("родители не отсортированы по убыванию оценки")
	}
	for _, p := range parents {
		if p.ID == thin.ID {
			t.Fatal("стратегия без надёжной оценки не должна попадать в родители")
		}
	}
}

// TestBgParentsSkipsUnknownAndZero: кандидат не из пула или с нулевой оценкой
// (и не действующий) в родители не идёт — плодить не от чего.
func TestBgParentsSkipsUnknownAndZero(t *testing.T) {
	known := mkStrat(t, `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"send"}}]}`)
	unknown := mkStrat(t, `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"drop"}}]}`)
	zero := mkStrat(t, `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"duplicate","left":{"kind":"send"},"right":{"kind":"send"}}}]}`)

	pool := map[core.StrategyID]*strategy.Strategy{known.ID: known, zero.ID: zero}
	st := control.Status{Targets: []control.TargetStatus{{
		Target: "youtube.com",
		Candidates: []control.CandidateStatus{
			{StrategyID: known.ID, Have: 10, LowerPermille: 700},
			{StrategyID: unknown.ID, Have: 10, LowerPermille: 900}, // не в пуле
			{StrategyID: zero.ID, Have: 10, LowerPermille: 0},      // нулевая оценка
		},
	}}}

	parents := bgParents(pool, st)
	if len(parents) != 1 || parents[0].ID != known.ID {
		t.Fatalf("ожидался единственный родитель known, получено %d", len(parents))
	}
}

// TestBgBreed проверяет порождение потомка: мутация при одном родителе,
// скрещивание при двух, мутация при двух одинаковых.
func TestBgBreed(t *testing.T) {
	gen, err := generator.New(generator.Config{
		Caps:   packetexec.New().Capabilities(),
		Limits: strategy.DefaultLimits(),
		Rand:   rand.New(rand.NewPCG(1, 1)),
	})
	if err != nil {
		t.Fatal(err)
	}
	a := mkStrat(t, `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"send"}}]}`)
	b := mkStrat(t, `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"drop"}}]}`)

	for _, tc := range []struct {
		name    string
		parents []*strategy.Strategy
	}{
		{"один родитель — мутация", []*strategy.Strategy{a}},
		{"два разных — скрещивание", []*strategy.Strategy{a, b}},
		{"два одинаковых — мутация", []*strategy.Strategy{a, a}},
	} {
		child, err := bgBreed(gen, tc.parents)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if child == nil {
			t.Fatalf("%s: потомок пуст", tc.name)
		}
	}
}
