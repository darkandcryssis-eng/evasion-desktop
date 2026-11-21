package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"sort"
	"time"

	"github.com/fitting-1c/evasion/internal/control"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/generator"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/sandbox"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/windivert"
)

// Параметры поиска по умолчанию. Малые намеренно: каждый прогон поколения — это
// живые пробы (population × probes × цели), и большой поиск считается часами
// (5.6). Масштаб задаётся флагами и бюджетом.
const (
	searchPopulationDefault  = 12
	searchGenerationsDefault = 8
	searchEliteDefault       = 2
	searchTournamentDefault  = 3
	searchCrossoverDefault   = 0.6
	searchProbesDefault      = 4
	searchTopDefault         = 5
	// searchProbeTimeout — таймаут пробы поиска. Короче, чем у автопилота (5 с):
	// при поиске большинство проб — к заблокированной цели или неприменимого
	// кандидата, и они висят ровно до таймаута, съедая время. Успешное
	// рукопожатие укладывается в секунду-две, поэтому укорочение ускоряет
	// поиск, не теряя удач.
	searchProbeTimeout = 3 * time.Second
)

// foundStrategy — найденная стратегия в машинно-читаемом виде (2.3, 10.2):
// идентификатор, приспособленность и сериализованное дерево, готовое лечь в
// конфиг или портфель.
type foundStrategy struct {
	StrategyID string          `json:"strategy_id"`
	Fitness    float64         `json:"fitness"`
	Strategy   json.RawMessage `json:"strategy"`
}

// searchResult — итог поиска.
type searchResult struct {
	Budget      string          `json:"budget"`
	Generations int             `json:"generations"`
	Population  int             `json:"population"`
	Seed        uint64          `json:"seed"`
	Targets     []string        `json:"targets"`
	Found       []foundStrategy `json:"found"`
}

// searchCommand ведёт генетический поиск стратегий в песочнице (5.6, M7).
//
// Поиск гоняет кандидатов генератора на выделенных соединениях песочницы
// (отдельный дескриптор WinDivert по диапазону портов), меряет быстрый уровень
// (5.3) и отбирает лучших. К реальному трафику пользователя кандидаты не
// прикасаются (1.4 п. 6). Найденное выводится данными — владелец сам решает,
// что положить в конфиг или портфель.
func searchCommand(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	var (
		configPath  = fs.String("config", "", "путь к файлу конфигурации (JSON)")
		budget      = fs.Duration("budget", 0, "предел времени поиска (например 2h); 0 — по числу поколений")
		generations = fs.Int("generations", searchGenerationsDefault, "сколько поколений прогнать (0 — до бюджета)")
		population  = fs.Int("population", searchPopulationDefault, "размер популяции")
		probes      = fs.Int("probes", searchProbesDefault, "сколько проб на оценку кандидата на цель")
		top         = fs.Int("top", searchTopDefault, "сколько лучших стратегий вывести")
		seed        = fs.Uint64("seed", 0, "сид поиска для воспроизводимости; 0 — случайный")
		ipFlag      = fs.String("ip", "4", "версия IP для правок полей генератором: 4, 6 или both")
		jsonOut     = fs.Bool("json", false, "машинно-читаемый вывод")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Версия IP ограничивает правки полей генератора трафиком той же версии:
	// иначе он плодит неприменимые кандидаты (IPv6-поле на IPv4-пакете), жгущие
	// пробы. По умолчанию 4 — на нём идёт основной трафик; both снимает
	// ограничение.
	var ipVersion int
	switch *ipFlag {
	case "4":
		ipVersion = 4
	case "6":
		ipVersion = 6
	case "both":
		ipVersion = 0
	default:
		return fmt.Errorf("--ip: допустимо 4, 6 или both, получено %q", *ipFlag)
	}
	if *budget == 0 && *generations == 0 {
		return errors.New("нужен предел поиска: задайте --budget или --generations")
	}
	if *probes < 1 {
		return fmt.Errorf("число проб должно быть положительным, получено %d", *probes)
	}

	// Поиск гоняет кандидатов через WinDivert-песочницу — нужны права
	// администратора (драйвер) и внешний curl для проб.
	if elev, checked := elevated(); checked && !elev {
		return errors.New("search меряет через перехват и требует прав администратора (драйвер WinDivert)")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		return fmt.Errorf("search мерит внешним curl, но он не найден в PATH: %w", err)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if len(cfg.ProbeTargets) == 0 {
		return errors.New("для search нужны probe_targets в конфиге: на них меряются кандидаты")
	}

	logger := newLogger(os.Stderr, *jsonOut)

	// Возможности берём у пакетного исполнителя: генератор строит только то,
	// что тот умеет (4.7).
	caps := packetexec.New().Capabilities()

	if *seed == 0 {
		*seed = rand.Uint64()
	}
	gen, err := generator.New(generator.Config{
		Caps:      caps,
		Limits:    strategy.DefaultLimits(),
		IPVersion: ipVersion,
		Rand:      rand.New(rand.NewPCG(*seed, *seed)),
	})
	if err != nil {
		return err
	}

	// Песочница в режиме «только Evaluate»: портфель и приёмник не нужны,
	// стратегию подаёт генератор, исход возвращается оценщику.
	sbCfg := sandbox.DefaultConfig()
	sb, err := sandbox.New(sandbox.Options{
		Config:  sbCfg,
		Targets: cfg.ProbeTargets,
		Prober:  curlProber{timeout: searchProbeTimeout},
		Logger:  logger,
	})
	if err != nil {
		return err
	}

	// Засев рабочим портфелем: поиск стартует с проверенных приёмов и улучшает
	// их, а не ищет базовый обход с нуля (5.6, «поверх портфеля»). Негодный
	// засев поиск отбросит сам.
	starters, err := starterCandidates()
	if err != nil {
		return err
	}
	seeds := make([]*strategy.Strategy, 0, len(starters))
	for _, c := range starters {
		seeds = append(seeds, c.Strategy)
	}

	// Контур перехвата песочницы: отдельный дескриптор WinDivert по диапазону
	// портов песочницы. На не-Windows Open вернёт ошибку (стаб) — команда
	// честно откажет.
	_, sandPred := sbCfg.PortPredicates()
	handle, err := windivert.Open(interceptFilter + " and " + sandPred)
	if err != nil {
		return err
	}
	defer handle.Close()

	engine, err := intercept.New(intercept.Options{
		Source:   handle,
		Sink:     handle,
		Flows:    flow.NewTable(flowCapacity, flowTTL, intercept.TLSHelloDetector),
		Provider: sb.Provider(),
		Exec:     packetexec.New(),
		Parse:    intercept.TLSHelloParser,
		Logger:   logger,
	})
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = handle.Close()
	}()
	go func() { _ = engine.Run(ctx) }()

	// Бюджет времени (5.6): отменяет поиск по сроку. Без бюджета — только по
	// числу поколений.
	runCtx := ctx
	if *budget > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, *budget)
		defer cancel()
	}

	evaluator := &sandboxEvaluator{
		sb:      sb,
		targets: cfg.ProbeTargets,
		probes:  *probes,
		log:     logger,
	}
	searcher, err := generator.NewSearcher(gen, evaluator, generator.SearchParams{
		Population:    *population,
		Elite:         searchEliteDefault,
		CrossoverRate: searchCrossoverDefault,
		TournamentK:   searchTournamentDefault,
		Generations:   *generations,
		Seeds:         seeds,
	})
	if err != nil {
		return err
	}

	logger.Info("поиск запущен", "популяция", *population, "поколений", *generations,
		"бюджет", budget.String(), "сид", *seed, "цели", cfg.ProbeTargets)
	pop, err := searcher.Run(runCtx)
	if err != nil {
		return err
	}

	result := buildSearchResult(pop, *top, *budget, *generations, *population, *seed, cfg.ProbeTargets)
	if *jsonOut {
		return writeJSON(os.Stdout, result)
	}
	printSearch(os.Stdout, result)
	return nil
}

// sandboxEvaluator меряет приспособленность кандидата в песочнице как
// превосходство над базовой линией по всем целям (быстрый уровень, 5.3).
// Реализует generator.Evaluator.
type sandboxEvaluator struct {
	sb      *sandbox.Sandbox
	targets []string
	probes  int
	log     *slog.Logger
	// n — счётчик оценённых кандидатов. Поиск вызывает Fitness последовательно,
	// поэтому без атомарности. Нужен только для прогресса в журнале.
	n int
}

// Fitness измеряет ПРЕВОСХОДСТВО кандидата над базовой линией по всем целям и
// возвращает его в [0,1]. Отмена контекста (бюджет) поднимается наверх — поиск
// завершится штатно.
//
// Почему превосходство, а не сырая доля удач. Сырая доля врёт: если цель в
// момент пробы достижима (DPI держит состояние по IP и расслабился от удачных
// соединений, 5.4), то и неприменившаяся стратегия даёт «100%», хотя обхода в
// ней нет — это показал живой прогон. Поэтому рядом с кандидатом мерим ту же
// цель БЕЗ десинка и берём разницу: неприменившийся кандидат идёт вровень с
// базовой линией и получает ~0, а реально обходящий заблокированную цель — ~1.
// Это тот же принцип, что в 4.5: успех значим лишь настолько, насколько он
// отличается от доступности самой цели. Базовую линию мерим рядом (а не из
// кэша) намеренно: достижимость цели у этого DPI колеблется, и устаревшая
// базовая линия разово завысила бы превосходство — ровно ту ошибку, что уже
// ловили. Цена — вдвое больше проб; её гасят короткий таймаут пробы и засев
// рабочим портфелем (рабочие кандидаты отвечают быстро).
//
// Прогресс пишется по каждой оценке: поиск идёт минутами (живые пробы), без
// построчного вывода он выглядел бы зависшим.
func (e *sandboxEvaluator) Fitness(ctx context.Context, s *strategy.Strategy) (float64, error) {
	var advSum float64
	var measured int
	for _, target := range e.targets {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		// Базовая линия мерится рядом с кандидатом (та же цель, тот же момент),
		// чтобы погасить меняющееся во времени состояние DPI.
		bs, bt := e.sb.Evaluate(ctx, nil, target, e.probes)
		cs, ct := e.sb.Evaluate(ctx, s, target, e.probes)
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if bt == 0 || ct == 0 {
			continue // по этой цели измерить не вышло
		}
		adv := float64(cs)/float64(ct) - float64(bs)/float64(bt)
		if adv < 0 {
			adv = 0 // хуже базовой линии полезным обходом не считаем
		}
		advSum += adv
		measured++
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	e.n++
	if measured == 0 {
		// Ни по одной цели измерить не вышло — мерить нечем. Нулевая
		// приспособленность, а не ошибка: отдельный кандидат не повод рушить
		// весь поиск.
		e.log.Info("кандидат оценён", "n", e.n, "стратегия", short(s.ID.String()), "превосходство", "—")
		return 0, nil
	}
	fit := advSum / float64(measured)
	e.log.Info("кандидат оценён",
		"n", e.n, "стратегия", short(s.ID.String()),
		"превосходство", fmt.Sprintf("%.0f%%", fit*100))
	return fit, nil
}

// buildSearchResult отбирает top лучших и собирает их в машинно-читаемый итог.
func buildSearchResult(pop []generator.Individual, top int, budget time.Duration, generations, population int, seed uint64, targets []string) searchResult {
	if top > len(pop) {
		top = len(pop)
	}
	found := make([]foundStrategy, 0, top)
	for i := 0; i < top; i++ {
		ind := pop[i]
		data, err := strategy.Marshal(ind.Strategy)
		if err != nil {
			continue
		}
		found = append(found, foundStrategy{
			StrategyID: ind.Strategy.ID.String(),
			Fitness:    ind.Fitness,
			Strategy:   json.RawMessage(data),
		})
	}
	return searchResult{
		Budget:      budget.String(),
		Generations: generations,
		Population:  population,
		Seed:        seed,
		Targets:     targets,
		Found:       found,
	}
}

// printSearch выводит итог поиска человекочитаемо. Форматирование — забота CLI
// (2.2); структуры --json на него не опираются.
func printSearch(w *os.File, r searchResult) {
	fmt.Fprintf(w, "поиск: популяция %d, поколений %d, сид %d\n", r.Population, r.Generations, r.Seed)
	fmt.Fprintf(w, "цели: %v\n\n", r.Targets)
	if len(r.Found) == 0 {
		fmt.Fprintln(w, "ничего не найдено")
		return
	}
	fmt.Fprintln(w, "лучшие стратегии (превосходство над базовой линией):")
	for i, f := range r.Found {
		fmt.Fprintf(w, "  %d. %s  превосходство=%.0f%%\n", i+1, short(f.StrategyID), f.Fitness*100)
	}
	fmt.Fprintf(w, "\nлучшая (для cfg.strategy):\n%s\n", string(r.Found[0].Strategy))
}

// статическая проверка соответствия интерфейсу оценщика поиска.
var _ generator.Evaluator = (*sandboxEvaluator)(nil)

// Параметры фонового генератора автопилота.
const (
	// bgCycle — как часто генератор порождает новое поколение потомков. Не
	// пробы: пробы ведёт ОДИН контур (его песочница), а генератор лишь читает
	// оценки и скрещивает/мутирует. Поэтому цикл редкий — дать контуру набрать
	// доказательства по уже добавленным, прежде чем плодить новых.
	bgCycle = 30 * time.Second
	// bgPoolCap — потолок числа стратегий под управлением генератора: больше —
	// контур пробует больше кандидатов каждый круг, и доказательства по каждому
	// копятся медленнее. По достижении потолка генератор перестаёт плодить, а
	// не вытесняет (вытеснение/отставку оставляем контуру).
	bgPoolCap = 16
	// bgParentCount — сколько лучших по оценке контура берётся в родители.
	bgParentCount = 4
	// bgOffspringPerCycle — сколько потомков добавляется за цикл.
	bgOffspringPerCycle = 2
	// bgMinEvidence — минимум наблюдений у стратегии, чтобы брать её в родители:
	// оценка на одной-двух пробах — шум, скрещивать по ней рано.
	bgMinEvidence = 5
)

// runBackgroundSearch ведёт фоновый генетический поиск (5.6), НЕ заводя второго
// контура проб.
//
// Почему без своих проб. Отдельный контур проб гонял бы соединения к тем же
// целям параллельно с пробами контура управления, и две волны переводили бы DPI
// в расслабленный режим по IP (5.4) — измерение у обоих обнулялось (это и
// показал живой прогон: стартовые приёмы с 100% падали в 0%). Поэтому пробы
// ведёт ОДИН контур (его песочница по ProbeItems), а генератор здесь только
// порождает: читает приспособленность из оценок контура, скрещивает/мутирует
// лучших и отдаёт потомков в портфель кандидатами. Дальше их проверяет и
// повышает тот же контур по порогу 5.5 — к трафику напрямую они не прикасаются
// (1.4 п. 6).
func runBackgroundSearch(ctx context.Context, engine *control.Engine, caps core.PrimitiveSet, known []*strategy.Strategy, ipVersion int, logger *slog.Logger) {
	gen, err := generator.New(generator.Config{
		Caps:      caps,
		Limits:    strategy.DefaultLimits(),
		IPVersion: ipVersion,
		Rand:      rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
	})
	if err != nil {
		logger.Error("фоновый генератор не запущен", "ошибка", err)
		return
	}

	// pool — деревья стратегий под управлением генератора (стартовые + потомки).
	// Нужны, чтобы скрещивать/мутировать: контур хранит их тоже, но наружу
	// отдаёт оценки по идентификатору, а не деревья.
	pool := make(map[core.StrategyID]*strategy.Strategy, len(known))
	for _, s := range known {
		pool[s.ID] = s
	}

	logger.Info("фоновый генератор запущен (потомки идут в портфель кандидатами)")
	t := time.NewTicker(bgCycle)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if len(pool) >= bgPoolCap {
			continue // потолок: ждём, пока контур разберётся с уже добавленными
		}
		st, err := engine.Status(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		parents := bgParents(pool, st)
		if len(parents) == 0 {
			continue // ни у одной стратегии нет надёжной оценки — плодить рано
		}
		for i := 0; i < bgOffspringPerCycle && len(pool) < bgPoolCap; i++ {
			child, err := bgBreed(gen, parents)
			if err != nil || child == nil {
				continue
			}
			if _, ok := pool[child.ID]; ok {
				continue // уже есть — не плодим дубликат
			}
			if err := engine.Add(ctx, child.ID, control.Holding{Strategy: child, Status: core.StatusCandidate}); err != nil {
				return // контекст отменён
			}
			pool[child.ID] = child
			logger.Info("генератор: потомок добавлен в портфель кандидатом",
				"стратегия", short(child.ID.String()))
		}
	}
}

// bgParents выбирает родителей: стратегии из pool с надёжной (по объёму) и
// лучшей оценкой контура. Оценка берётся из статуса контура (нижняя граница
// доли успехов по целям) — той же, по которой контур принимает решения, а не
// отдельным измерением. Действующие стратегии считаются сильными родителями.
func bgParents(pool map[core.StrategyID]*strategy.Strategy, st control.Status) []*strategy.Strategy {
	type scored struct {
		s     *strategy.Strategy
		score int
	}
	best := map[core.StrategyID]int{}
	for _, tgt := range st.Targets {
		if tgt.Active != "" {
			best[tgt.Active] = 1000 // применяется — заведомо годный родитель
		}
		for _, c := range tgt.Candidates {
			if c.Have < bgMinEvidence {
				continue
			}
			if c.LowerPermille > best[c.StrategyID] {
				best[c.StrategyID] = c.LowerPermille
			}
		}
	}
	var cand []scored
	for id, score := range best {
		if s, ok := pool[id]; ok && score > 0 {
			cand = append(cand, scored{s: s, score: score})
		}
	}
	sort.SliceStable(cand, func(i, j int) bool {
		if cand[i].score != cand[j].score {
			return cand[i].score > cand[j].score
		}
		return cand[i].s.ID < cand[j].s.ID
	})
	if len(cand) > bgParentCount {
		cand = cand[:bgParentCount]
	}
	out := make([]*strategy.Strategy, len(cand))
	for i := range cand {
		out[i] = cand[i].s
	}
	return out
}

// bgBreed порождает одного потомка от выбранных родителей: скрещиванием двух
// либо мутацией одного.
func bgBreed(gen *generator.Generator, parents []*strategy.Strategy) (*strategy.Strategy, error) {
	if len(parents) == 1 {
		return gen.Mutate(parents[0])
	}
	a := parents[rand.IntN(len(parents))]
	b := parents[rand.IntN(len(parents))]
	if a.ID == b.ID {
		return gen.Mutate(a)
	}
	return gen.Crossover(a, b)
}
