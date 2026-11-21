package generator

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/fitting-1c/evasion/internal/strategy"
)

// Evaluator измеряет приспособленность стратегии — насколько хорошо она
// обходит DPI.
//
// Реализацию даёт песочница (слайс 3): кандидат гоняется на выделенных
// соединениях быстрым уровнем (5.3), и доля удач становится числом. Генетика
// сама мерить не умеет и не должна — она лишь сравнивает числа. В тестах сюда
// подаётся синтетическая оценка, поэтому цикл поиска проверяется без сети.
//
// Ошибка отмены контекста — штатное завершение поиска по бюджету (5.6), а не
// сбой; прочие ошибки означают, что мерить нельзя, и поиск останавливается.
type Evaluator interface {
	Fitness(ctx context.Context, s *strategy.Strategy) (float64, error)
}

// Individual — особь популяции: стратегия и её измеренная приспособленность.
type Individual struct {
	Strategy *strategy.Strategy
	Fitness  float64
}

// SearchParams задаёт параметры эволюции. Значения принадлежат конфигурации
// (10.1); здесь — их проверка.
type SearchParams struct {
	// Population — размер популяции (число особей в поколении).
	Population int
	// Elite — сколько лучших особей переносится в следующее поколение без
	// изменений. Гарантирует, что лучшее найденное не теряется (элитизм).
	Elite int
	// CrossoverRate — доля потомков, получаемых скрещиванием; остальные —
	// мутацией копии одного родителя.
	CrossoverRate float64
	// TournamentK — размер турнира отбора: столько случайных особей
	// сравниваются, лучшая становится родителем. Больше — сильнее давление
	// отбора и быстрее сходимость, но меньше разнообразие.
	TournamentK int
	// Generations — предел числа поколений; 0 означает «без предела»
	// (до отмены контекста по бюджету, 5.6).
	Generations int
	// OnGeneration, если задан, вызывается после засева (поколение 0) и после
	// каждого поколения с его номером и текущей популяцией (отсортированной,
	// лучшая — первой). Нужен наблюдаемости и фоновому режиму: по нему
	// вызывающий забирает находки в рабочий портфель, не вмешиваясь в сам
	// поиск. На ход поиска не влияет.
	OnGeneration func(generation int, population []Individual)
	// Seeds — готовые стратегии для начальной популяции (рабочий портфель).
	//
	// Поиск «поверх портфеля» (5.6): генетика стартует с заведомо рабочих
	// приёмов, а не с чистого листа — так она сразу видит превосходство и
	// улучшает их, а не тратит поколения на нащупывание базового обхода.
	// Негодный или непосильный исполнителю засев отбрасывается (как и всё, что
	// идёт мимо возможностей). Если засева меньше популяции, остаток добирается
	// случайными особями.
	Seeds []*strategy.Strategy
}

// validate проверяет согласованность параметров.
func (p SearchParams) validate() error {
	switch {
	case p.Population < 2:
		return fmt.Errorf("generator: популяция %d меньше двух", p.Population)
	case p.Elite < 0:
		return fmt.Errorf("generator: число элит %d отрицательно", p.Elite)
	case p.Elite >= p.Population:
		return fmt.Errorf("generator: элит %d не меньше популяции %d — потомкам нет места", p.Elite, p.Population)
	case p.CrossoverRate < 0 || p.CrossoverRate > 1:
		return fmt.Errorf("generator: доля скрещивания %v вне [0,1]", p.CrossoverRate)
	case p.TournamentK < 1:
		return fmt.Errorf("generator: размер турнира %d меньше одного", p.TournamentK)
	case p.Generations < 0:
		return fmt.Errorf("generator: число поколений %d отрицательно", p.Generations)
	}
	return nil
}

// Searcher ведёт эволюционный поиск: порождение генератором, отбор по
// приспособленности от Evaluator, элитизм. Не потокобезопасен (держит
// генератор с его источником случайности).
type Searcher struct {
	gen  *Generator
	eval Evaluator
	p    SearchParams
}

// NewSearcher собирает поиск.
func NewSearcher(gen *Generator, eval Evaluator, p SearchParams) (*Searcher, error) {
	if gen == nil {
		return nil, errors.New("generator: поиск без генератора")
	}
	if eval == nil {
		return nil, errors.New("generator: поиск без оценщика приспособленности")
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &Searcher{gen: gen, eval: eval, p: p}, nil
}

// Run ведёт поиск до исчерпания бюджета поколений или отмены контекста (5.6) и
// возвращает финальную популяцию, отсортированную по убыванию приспособленности
// (лучшая — первой).
//
// Отмена контекста — штатное завершение: возвращается лучшее, что успели найти,
// без ошибки. Так команда search с бюджетом по времени просто останавливается
// по сроку.
func (s *Searcher) Run(ctx context.Context) ([]Individual, error) {
	pop, err := s.seed(ctx)
	if err != nil {
		if ctx.Err() != nil {
			// Бюджет исчерпан ещё на засеве популяции — штатное завершение.
			return pop, nil
		}
		return pop, err
	}
	s.notify(0, pop)
	for gen := 0; s.p.Generations == 0 || gen < s.p.Generations; gen++ {
		if ctx.Err() != nil {
			return pop, nil
		}
		next, err := s.evolve(ctx, pop)
		if err != nil {
			if ctx.Err() != nil {
				// Бюджет исчерпан посреди поколения: отдаём лучшее из уже
				// оценённого прошлого поколения.
				return pop, nil
			}
			return pop, err
		}
		pop = next
		s.notify(gen+1, pop)
	}
	return pop, nil
}

// notify сообщает о поколении, если задан наблюдатель.
func (s *Searcher) notify(generation int, pop []Individual) {
	if s.p.OnGeneration != nil {
		s.p.OnGeneration(generation, pop)
	}
}

// seed строит и оценивает начальную популяцию: сначала годный засев из
// портфеля, затем добор случайными особями до размера популяции.
func (s *Searcher) seed(ctx context.Context) ([]Individual, error) {
	pop := make([]Individual, 0, s.p.Population)
	seen := make(map[string]bool, s.p.Population)

	// add оценивает стратегию и добавляет в популяцию; дубликаты по ID
	// пропускает. Возвращает ошибку только если оценка не состоялась (отмена).
	add := func(st *strategy.Strategy) error {
		id := st.ID.String()
		if seen[id] {
			return nil
		}
		fit, err := s.eval.Fitness(ctx, st)
		if err != nil {
			return err
		}
		seen[id] = true
		pop = append(pop, Individual{Strategy: st, Fitness: fit})
		return nil
	}

	// Засев из портфеля: берём только годное и посильное исполнителю.
	for _, st := range s.p.Seeds {
		if len(pop) >= s.p.Population {
			break
		}
		if ctx.Err() != nil {
			return pop, ctx.Err()
		}
		if !s.admissibleSeed(st) {
			continue
		}
		if err := add(st); err != nil {
			return pop, err
		}
	}

	// Добор случайными особями.
	for len(pop) < s.p.Population {
		if ctx.Err() != nil {
			return pop, ctx.Err()
		}
		st, err := s.gen.Random()
		if err != nil {
			return pop, err
		}
		if err := add(st); err != nil {
			return pop, err
		}
	}
	sortByFitness(pop)
	return pop, nil
}

// admissibleSeed сообщает, годится ли засев: непуст, валиден и посилен
// исполнителю. Идентификатор при необходимости досчитывается — засев может
// прийти собранным вручную. Непосильное отбрасывается, а не исполняется
// наполовину (4.7).
func (s *Searcher) admissibleSeed(st *strategy.Strategy) bool {
	if st == nil {
		return false
	}
	if err := strategy.Validate(st, s.gen.limits); err != nil {
		return false
	}
	if !s.gen.caps.Contains(strategy.RequiredCapabilities(st)) {
		return false
	}
	if st.ID == "" {
		id, err := strategy.ComputeID(st)
		if err != nil {
			return false
		}
		st.ID = id
	}
	return true
}

// evolve строит и оценивает одно следующее поколение из отсортированного
// текущего.
//
// Элиты переносятся как есть (их приспособленность уже известна), остальные
// места заполняются потомками отбора. Новое поколение сводится с элитами и
// сортируется, поэтому лучшая приспособленность никогда не убывает.
func (s *Searcher) evolve(ctx context.Context, parents []Individual) ([]Individual, error) {
	next := make([]Individual, 0, s.p.Population)
	seen := make(map[string]bool, s.p.Population)

	// Элиты — без изменений.
	for i := 0; i < s.p.Elite && i < len(parents); i++ {
		id := parents[i].Strategy.ID.String()
		if seen[id] {
			continue
		}
		seen[id] = true
		next = append(next, parents[i])
	}

	// Потомки до заполнения популяции.
	attempts := 0
	maxAttempts := s.p.Population * 16 // защита от зацикливания при малом разнообразии
	for len(next) < s.p.Population && attempts < maxAttempts {
		attempts++
		if ctx.Err() != nil {
			return next, ctx.Err()
		}
		child, err := s.breed(parents)
		if err != nil {
			return next, err
		}
		if seen[child.ID.String()] {
			continue // дубликат не добавляем: разнообразие важнее заполнения впритык
		}
		fit, err := s.eval.Fitness(ctx, child)
		if err != nil {
			return next, err
		}
		seen[child.ID.String()] = true
		next = append(next, Individual{Strategy: child, Fitness: fit})
	}

	// Если из-за дубликатов места остались незаполненными, добираем элитами
	// (они уже оценены) — популяция не должна схлопываться.
	for i := 0; len(next) < s.p.Population && i < len(parents); i++ {
		next = append(next, parents[i])
	}

	sortByFitness(next)
	if len(next) > s.p.Population {
		next = next[:s.p.Population]
	}
	return next, nil
}

// breed порождает одного потомка: скрещиванием двух отобранных родителей или
// мутацией копии одного.
func (s *Searcher) breed(parents []Individual) (*strategy.Strategy, error) {
	if s.gen.rng.Float64() < s.p.CrossoverRate {
		a := s.tournament(parents)
		b := s.tournament(parents)
		return s.gen.Crossover(a.Strategy, b.Strategy)
	}
	a := s.tournament(parents)
	return s.gen.Mutate(a.Strategy)
}

// tournament выбирает родителя турниром: берёт TournamentK случайных особей и
// возвращает лучшую. Давление отбора растёт с размером турнира.
func (s *Searcher) tournament(pop []Individual) Individual {
	best := pop[s.gen.rng.IntN(len(pop))]
	for i := 1; i < s.p.TournamentK; i++ {
		c := pop[s.gen.rng.IntN(len(pop))]
		if c.Fitness > best.Fitness {
			best = c
		}
	}
	return best
}

// sortByFitness сортирует особей по убыванию приспособленности; при равенстве —
// по идентификатору, чтобы порядок был устойчив и поиск воспроизводим.
func sortByFitness(pop []Individual) {
	sort.SliceStable(pop, func(i, j int) bool {
		if pop[i].Fitness != pop[j].Fitness {
			return pop[i].Fitness > pop[j].Fitness
		}
		return pop[i].Strategy.ID < pop[j].Strategy.ID
	})
}
