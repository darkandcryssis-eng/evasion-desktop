package generator

import (
	"context"
	"errors"
	"testing"

	"github.com/fitting-1c/evasion/internal/strategy"
)

// nodeCountEval — синтетическая приспособленность: число узлов в дереве.
// Награждает «богатые» стратегии, поэтому под давлением отбора средняя и лучшая
// приспособленность должны расти. Сети не касается — цикл поиска проверяется
// офлайн.
type nodeCountEval struct{}

func (nodeCountEval) Fitness(_ context.Context, s *strategy.Strategy) (float64, error) {
	n := 0
	walkActions(s, func(*strategy.Action) { n++ })
	return float64(n), nil
}

func newSearcher(t *testing.T, p SearchParams, seed uint64) *Searcher {
	t.Helper()
	g := newGen(t, fullCaps(), seed)
	s, err := NewSearcher(g, nodeCountEval{}, p)
	if err != nil {
		t.Fatalf("NewSearcher: %v", err)
	}
	return s
}

func TestSearchImprovesUnderSelection(t *testing.T) {
	params := SearchParams{Population: 20, Elite: 2, CrossoverRate: 0.6, TournamentK: 3, Generations: 1}

	// Поколение 0 (seed) против результата после нескольких поколений.
	s0 := newSearcher(t, params, 1)
	seed0, err := s0.seed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	bestSeed := seed0[0].Fitness

	params.Generations = 15
	s := newSearcher(t, params, 1)
	pop, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	bestFinal := pop[0].Fitness

	if bestFinal < bestSeed {
		t.Fatalf("лучшая приспособленность упала: было %.0f, стало %.0f", bestSeed, bestFinal)
	}
	// Отбор по числу узлов обязан хоть немного нарастить лучшее за 15 поколений.
	if bestFinal <= bestSeed {
		t.Fatalf("отбор не улучшил лучшее за 15 поколений: %.0f → %.0f", bestSeed, bestFinal)
	}
	// Популяция сохраняет размер и соундность.
	if len(pop) != params.Population {
		t.Fatalf("размер популяции %d, ожидался %d", len(pop), params.Population)
	}
	for _, ind := range pop {
		assertSound(t, ind.Strategy, fullCaps())
	}
}

// TestSearchElitismNeverRegresses — лучшая приспособленность не убывает от
// поколения к поколению (гарантия элитизма).
func TestSearchElitismNeverRegresses(t *testing.T) {
	params := SearchParams{Population: 16, Elite: 2, CrossoverRate: 0.5, TournamentK: 3}
	s := newSearcher(t, params, 5)

	pop, err := s.seed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	prevBest := pop[0].Fitness
	for g := 0; g < 10; g++ {
		pop, err = s.evolve(context.Background(), pop)
		if err != nil {
			t.Fatal(err)
		}
		if pop[0].Fitness < prevBest {
			t.Fatalf("поколение %d: лучшее упало %.0f → %.0f", g, prevBest, pop[0].Fitness)
		}
		prevBest = pop[0].Fitness
		if len(pop) != params.Population {
			t.Fatalf("поколение %d: размер %d, ожидался %d", g, len(pop), params.Population)
		}
	}
}

func TestSearchDeterministic(t *testing.T) {
	params := SearchParams{Population: 12, Elite: 2, CrossoverRate: 0.5, TournamentK: 3, Generations: 8}
	a, err := newSearcher(t, params, 77).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := newSearcher(t, params, 77).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatalf("размеры разошлись: %d != %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Strategy.ID != b[i].Strategy.ID || a[i].Fitness != b[i].Fitness {
			t.Fatalf("на позиции %d расхождение: %s/%.0f != %s/%.0f",
				i, a[i].Strategy.ID, a[i].Fitness, b[i].Strategy.ID, b[i].Fitness)
		}
	}
}

// TestSearchSeedsInitialPopulation — засев из портфеля попадает в начальную
// популяцию; негодный засев отбрасывается, место добирается случайными.
func TestSearchSeedsInitialPopulation(t *testing.T) {
	g := newGen(t, fullCaps(), 1)
	// Годный засев: валидная исполнимая стратегия.
	good := mustStrat(t, `{"rules":[{"direction":"outbound","trigger":{"match":"client_hello"},"action":{"kind":"fragment","params":{"proto":"tcp","at":"inside_sni","order":"reverse"},"left":{"kind":"send"},"right":{"kind":"send"}}}]}`)
	// Негодный засев: нулевой указатель — должен быть отброшен.
	params := SearchParams{Population: 6, Elite: 1, CrossoverRate: 0.5, TournamentK: 2, Generations: 1, Seeds: []*strategy.Strategy{good, nil}}
	s, err := NewSearcher(g, nodeCountEval{}, params)
	if err != nil {
		t.Fatal(err)
	}
	pop, err := s.seed(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pop) != params.Population {
		t.Fatalf("размер популяции %d, ожидался %d", len(pop), params.Population)
	}
	found := false
	for _, ind := range pop {
		if ind.Strategy.ID == good.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("годный засев должен попасть в начальную популяцию")
	}
}

func mustStrat(t *testing.T, js string) *strategy.Strategy {
	t.Helper()
	s, err := strategy.Unmarshal([]byte(js), strategy.DefaultLimits())
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return s
}

// TestSearchOnGenerationCalled — наблюдатель поколений вызывается после засева
// и после каждого поколения; через него фоновый режим забирает находки.
func TestSearchOnGenerationCalled(t *testing.T) {
	g := newGen(t, fullCaps(), 2)
	var gens []int
	var lastLen int
	params := SearchParams{
		Population: 6, Elite: 1, CrossoverRate: 0.5, TournamentK: 2, Generations: 3,
		OnGeneration: func(generation int, pop []Individual) {
			gens = append(gens, generation)
			lastLen = len(pop)
		},
	}
	s, err := NewSearcher(g, nodeCountEval{}, params)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Засев (0) плюс три поколения (1,2,3).
	want := []int{0, 1, 2, 3}
	if len(gens) != len(want) {
		t.Fatalf("наблюдатель вызван %d раз, ожидалось %d: %v", len(gens), len(want), gens)
	}
	for i := range want {
		if gens[i] != want[i] {
			t.Fatalf("номера поколений %v, ожидались %v", gens, want)
		}
	}
	if lastLen != params.Population {
		t.Fatalf("в наблюдатель пришла популяция %d, ожидалась %d", lastLen, params.Population)
	}
}

// TestSearchStopsOnContext — отмена контекста (бюджет) завершает поиск штатно,
// без ошибки, и возвращает уже найденное.
func TestSearchStopsOnContext(t *testing.T) {
	params := SearchParams{Population: 10, Elite: 1, CrossoverRate: 0.5, TournamentK: 2, Generations: 0} // без предела поколений
	s := newSearcher(t, params, 3)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // отменён заранее — seed должен прерваться, Run вернуть без ошибки

	pop, err := s.Run(ctx)
	if err != nil {
		t.Fatalf("отмена должна быть штатной, получена ошибка: %v", err)
	}
	_ = pop
}

// failEval возвращает фатальную ошибку (не отмену) — поиск обязан её поднять.
type failEval struct{}

func (failEval) Fitness(_ context.Context, _ *strategy.Strategy) (float64, error) {
	return 0, errors.New("мерить нечем")
}

func TestSearchPropagatesEvalError(t *testing.T) {
	g := newGen(t, fullCaps(), 1)
	s, err := NewSearcher(g, failEval{}, SearchParams{Population: 5, Elite: 1, CrossoverRate: 0.5, TournamentK: 2, Generations: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(context.Background()); err == nil {
		t.Fatal("фатальная ошибка оценки должна подниматься наверх")
	}
}

func TestNewSearcherValidation(t *testing.T) {
	g := newGen(t, fullCaps(), 1)
	bad := []SearchParams{
		{Population: 1, Elite: 0, CrossoverRate: 0.5, TournamentK: 2},
		{Population: 10, Elite: 10, CrossoverRate: 0.5, TournamentK: 2},
		{Population: 10, Elite: 1, CrossoverRate: 2, TournamentK: 2},
		{Population: 10, Elite: 1, CrossoverRate: 0.5, TournamentK: 0},
	}
	for i, p := range bad {
		if _, err := NewSearcher(g, nodeCountEval{}, p); err == nil {
			t.Fatalf("случай %d: ожидалась ошибка валидации", i)
		}
	}
	if _, err := NewSearcher(nil, nodeCountEval{}, bad[0]); err == nil {
		t.Fatal("ожидалась ошибка: поиск без генератора")
	}
	if _, err := NewSearcher(g, nil, SearchParams{Population: 10, Elite: 1, CrossoverRate: 0.5, TournamentK: 2}); err == nil {
		t.Fatal("ожидалась ошибка: поиск без оценщика")
	}
}

