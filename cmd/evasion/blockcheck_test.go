package main

import (
	"context"
	"testing"

	"github.com/fitting-1c/evasion/internal/executor"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// TestStarterCandidatesValidAndExecutable — встроенный портфель разбирается и
// исполним пакетным исполнителем. Если кандидат невалиден или требует
// возможности, которой у packetexec нет, это дефект кода, а не ввода.
func TestStarterCandidatesValidAndExecutable(t *testing.T) {
	cands, err := starterCandidates()
	if err != nil {
		t.Fatalf("портфель не разобрался: %v", err)
	}
	if len(cands) != len(candidateDefs) {
		t.Fatalf("ожидалось %d кандидатов, получено %d", len(candidateDefs), len(cands))
	}
	caps := packetexec.Capabilities()
	seen := map[string]bool{}
	for _, c := range cands {
		if seen[c.Name] {
			t.Errorf("дубликат имени кандидата: %s", c.Name)
		}
		seen[c.Name] = true
		if c.Strategy == nil {
			t.Fatalf("%s: пустая стратегия", c.Name)
		}
		if err := executor.EnsureExecutable(caps, c.Strategy); err != nil {
			t.Errorf("%s: неисполним пакетным исполнителем: %v", c.Name, err)
		}
	}
}

// fakeMeasurer отдаёт заранее заданные исходы по имени (через идентификатор
// стратегии) — для проверки оркестровки без сети.
type fakeMeasurer struct {
	// byID — исход по StrategyID; базовая линия (nil) под ключом "".
	byID map[string]struct {
		success, total int
		err            error
	}
}

func (f *fakeMeasurer) Measure(_ context.Context, cand *strategy.Strategy, _ string, probes int) (int, int, error) {
	id := ""
	if cand != nil {
		id = cand.ID.String()
	}
	r, ok := f.byID[id]
	if !ok {
		return 0, probes, nil
	}
	return r.success, r.total, r.err
}

// TestRunBlockcheckMeasuresBaselineAndAll — оркестровка меряет базовую линию и
// каждого кандидата ровно один раз.
func TestRunBlockcheckMeasuresBaselineAndAll(t *testing.T) {
	cands, err := starterCandidates()
	if err != nil {
		t.Fatal(err)
	}
	m := &fakeMeasurer{byID: map[string]struct {
		success, total int
		err            error
	}{}}

	results := runBlockcheck(context.Background(), m, cands, "youtube.com", 4, discardLogger())
	if len(results) != len(cands)+1 {
		t.Fatalf("ожидалось %d исходов (база + кандидаты), получено %d", len(cands)+1, len(results))
	}
	if results[0].Name != "base" {
		t.Errorf("первым должен идти base, получено %q", results[0].Name)
	}
	// Все кандидаты представлены, с заполненным StrategyID.
	for _, r := range results[1:] {
		if r.StrategyID == "" {
			t.Errorf("%s: пустой StrategyID", r.Name)
		}
	}
}

// TestRankCandidatesByRate — ранжирование по доле успеха, база исключена,
// ошибочные/неизмеренные уходят вниз.
func TestRankCandidatesByRate(t *testing.T) {
	results := []blockResult{
		{Name: "base", Success: 0, Total: 4},
		{Name: "low", Success: 1, Total: 4},
		{Name: "high", Success: 4, Total: 4},
		{Name: "mid", Success: 2, Total: 4},
		{Name: "broken", Err: "boom"},
	}
	ranked := rankCandidates(results)

	if len(ranked) != 4 {
		t.Fatalf("база должна быть исключена: получено %d", len(ranked))
	}
	order := []string{ranked[0].Name, ranked[1].Name, ranked[2].Name}
	want := []string{"high", "mid", "low"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("порядок %v, ожидался %v...", order, want)
		}
	}
	// Ошибочный (не измерен) — последним.
	if ranked[3].Name != "broken" {
		t.Errorf("неизмеренный кандидат должен быть внизу, получено %q", ranked[3].Name)
	}
}

// TestBlockResultRate — доля: ошибка и ноль проб дают -1 (не притворяется нулём).
func TestBlockResultRate(t *testing.T) {
	if r := (blockResult{Success: 3, Total: 4}); r.rate() != 0.75 {
		t.Errorf("3/4 должно быть 0.75, получено %v", r.rate())
	}
	if r := (blockResult{Err: "x", Total: 4}); r.rate() != -1 {
		t.Errorf("ошибка должна давать -1, получено %v", r.rate())
	}
	if r := (blockResult{Total: 0}); r.rate() != -1 {
		t.Errorf("ноль проб должен давать -1, получено %v", r.rate())
	}
}

// TestMatchHost — радиус из одной цели совпадает по имени и поддомену, но не по
// постороннему.
func TestMatchHost(t *testing.T) {
	cases := []struct {
		name, target string
		want         bool
	}{
		{"youtube.com", "youtube.com", true},
		{"www.youtube.com", "youtube.com", true},
		{"youtube.com.", "youtube.com", true},
		{"notyoutube.com", "youtube.com", false},
		{"example.com", "youtube.com", false},
	}
	for _, c := range cases {
		if got := matchHost(c.name, c.target); got != c.want {
			t.Errorf("matchHost(%q,%q)=%v, ожидалось %v", c.name, c.target, got, c.want)
		}
	}
}
