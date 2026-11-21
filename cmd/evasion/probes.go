package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/fitting-1c/evasion/internal/config"
	"github.com/fitting-1c/evasion/internal/control"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/policy"
	"github.com/fitting-1c/evasion/internal/probe"
	"github.com/fitting-1c/evasion/internal/socketexec"
	"github.com/fitting-1c/evasion/internal/store"
)

// probeItemSource — откуда брать пары, которым нужны доказательства.
// Реализация — control.Engine.
type probeItemSource interface {
	ProbeItems(ctx context.Context) ([]control.ProbeItem, error)
}

// probePlanner переводит план контура в задание пробам.
//
// Зачем перевод, а не прямой вызов. Контур знает, кому нужны доказательства, но
// не знает, по какому имени ходить: цель радиуса — суффикс («youtube.com»), а
// проверять надо работающее имя («www.youtube.com»). Пакет probe, наоборот,
// умеет ходить, но про радиус ничего не знает. Сшивает их команда — тот же
// приём, что с исходами соединений, и по той же причине: ни контур, ни probe не
// должны зависеть друг от друга (4.7 п. 4).
type probePlanner struct {
	source probeItemSource
	// hot — живая таблица политик. По ней выясняется, какой цели радиуса
	// принадлежит имя из probe_targets: таблица отвечает на этот вопрос
	// точно так же, как для настоящего соединения, и второго набора правил
	// сопоставления имён в движке не появляется.
	hot *policy.Table
	// hosts — имена для проб из конфига (10.1).
	hosts []string
	log   *slog.Logger
}

// ProbePlan собирает задание пробам.
func (p *probePlanner) ProbePlan(ctx context.Context) (probe.Plan, error) {
	items, err := p.source.ProbeItems(ctx)
	if err != nil {
		return probe.Plan{}, err
	}

	byTarget := p.hostsByTarget()

	var plan probe.Plan
	for _, it := range items {
		hosts := byTarget[it.Target]
		if len(hosts) == 0 {
			// Имени для этой цели в конфиге нет — идём к самой цели.
			//
			// Это осознанная уступка, и она не бесплатна: цель радиуса может
			// не отвечать по своему имени («ytimg.com» не разрешается вовсе), и
			// тогда проба запишет стратегии провал, которого та не заслужила.
			// Поэтому в конфиге есть probe_targets, и заполнять их стоит; без
			// них движок делает что может, а не притворяется, что всё хорошо.
			hosts = []string{""}
		}
		for _, host := range hosts {
			plan.Items = append(plan.Items, probe.PlanItem{
				Target:     it.Target,
				Host:       host,
				Strategy:   it.Strategy,
				StrategyID: it.StrategyID,
				Baseline:   it.Baseline,
				Degraded:   it.Degraded,
			})
		}
	}
	return plan, nil
}

// hostsByTarget раскладывает имена из конфига по целям радиуса.
//
// Имя, не попавшее ни в одну цель, пробами не проверяется: к радиусу оно
// отношения не имеет, а ходить в сеть без причины — значит жечь бюджет живых
// прогонов и отдавать DPI сведения о поведении машины (5.8).
func (p *probePlanner) hostsByTarget() map[string][]string {
	out := make(map[string][]string, len(p.hosts))
	snap := p.hot.Current()
	for _, host := range p.hosts {
		sel, ok := snap.Lookup(host, "")
		if !ok || sel.Target == "" {
			p.log.Debug("имя для проб вне радиуса, пропущено", "имя", host)
			continue
		}
		out[sel.Target] = append(out[sel.Target], host)
	}
	return out
}

// probeSink отдаёт результат пробы контуру и журналу.
//
// Два получателя и у исходов соединений те же: контуру — для решений, журналу —
// чтобы наблюдение уцелело при перезапуске (6.4). Разница только в источнике:
// проба это активное измерение полным весом, а не пассивное наблюдение (5.7).
type probeSink struct {
	engine  observationSink
	archive archiveSink
	vantage core.VantageID
	log     *slog.Logger
}

// ProbeDone переводит результат пробы в наблюдения.
func (s *probeSink) ProbeDone(item probe.PlanItem, res probe.Result) {
	// Базовая проба идёт без стратегии, и пустой идентификатор у неё
	// законен — это и есть базовая линия. Остальные случаи пустоты
	// по-прежнему отвергаются: наблюдение, потерявшее стратегию по дороге,
	// относить не к чему, и принять его за базовую линию значило бы испортить
	// эталон цели чужими исходами.
	switch {
	case item.Target == "":
		s.log.Warn("результат пробы не отнесён к цели")
		return
	case item.Baseline && item.StrategyID != "":
		s.log.Warn("базовая проба со стратегией: план противоречив",
			"цель", item.Target, "стратегия", item.StrategyID.String())
		return
	case !item.Baseline && item.StrategyID == "":
		s.log.Warn("проба без стратегии и без признака базовой", "цель", item.Target)
		return
	}

	s.engine.Observe(control.Observation{
		StrategyID: item.StrategyID,
		Baseline:   item.Baseline,
		Target:     item.Target,
		Outcome:    res.Outcome,
		Source:     store.SourceProbe,
		// Проба — не доля живого трафика: соединение инициировал движок, и
		// риска для пользователя в нём нет (5.1, нижняя ступень лестницы).
		Trial: false,
		At:    res.Started,
	})

	if s.archive == nil {
		return
	}
	s.archive.Enqueue(store.Observation{
		At:              res.Started,
		StrategyID:      item.StrategyID,
		Target:          item.Target,
		VantageID:       s.vantage,
		Phase:           res.Phase,
		Outcome:         res.Outcome,
		Reason:          res.Reason,
		Source:          store.SourceProbe,
		StrategyApplied: res.StrategyApplied,
		// Время установки соединения значимо только при Connected: на Windows
		// разрешение таймера грубое, и ноль там означает «быстрее, чем
		// измеримо», а не «не соединилось».
		RTT:                res.ConnectRTT,
		RTTMeasured:        res.Connected,
		Throughput:         res.Throughput,
		ThroughputMeasured: res.ThroughputMeasured,
	})
}

// startProbes поднимает расписание проб.
//
// Это та часть, которой движку не хватало для самостоятельности: пакет probe
// существовал с M4, но вызывать его было некому, и кандидат не мог набрать
// доказательства нигде — на живой трафик его не пускал тот же порог, который
// открывается наблюдениями (5.5). Нижняя ступень лестницы (5.1) была закрыта, и
// автопилот умел только исполнять закрепления человека.
func startProbes(
	ctx context.Context,
	cfg *config.Config,
	engine *control.Engine,
	hot *policy.Table,
	arch *archive,
	vantage core.VantageID,
	logger *slog.Logger,
) (stop func(), err error) {
	prober, err := probe.New(probe.Config{
		// Исполнитель тот же, что у прокси: проба обязана применять стратегию
		// ровно так, как это сделает рабочий путь, иначе измеряется не то, что
		// работает.
		Executor: socketexec.New(),
	})
	if err != nil {
		return nil, fmt.Errorf("пробер: %w", err)
	}

	// Базовый RTT измеряется по контрольным целям: от него считается срок
	// ожидания (5.3), и константа здесь была бы неверна на любом канале, кроме
	// того, где её подобрали.
	if targets := cfg.ControlTargets; len(targets) > 0 {
		if rtt, err := prober.MeasureBaseRTT(ctx, withPort(targets)); err != nil {
			logger.Warn("базовый RTT не измерен, берётся значение по умолчанию", "ошибка", err)
		} else {
			logger.Info("базовый RTT измерен", "rtt", rtt.String())
		}
	}

	planner := &probePlanner{source: engine, hot: hot, hosts: cfg.ProbeTargets, log: logger}
	sink := &probeSink{engine: engine, archive: arch.writer, vantage: vantage, log: logger}

	sched, err := probe.NewSchedulerWithProber(probe.SchedulerConfig{
		Interval:         cfg.Autopilot.ProbeInterval,
		DegradedInterval: cfg.Autopilot.ProbeIntervalDegraded,
		Jitter:           cfg.Autopilot.ProbeJitter,
		Workers:          cfg.Parallelism.Workers,
		PerTarget:        cfg.Parallelism.PerTarget,
		Planner:          planner,
		Sink:             sink,
		Logger:           logger,
	}, prober)
	if err != nil {
		return nil, fmt.Errorf("расписание проб: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = sched.Run(runCtx)
	}()

	return func() {
		cancel()
		<-done
	}, nil
}

// withPort добавляет порт TLS к именам целей: пробер ждёт адрес вида host:port.
func withPort(hosts []string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, h+":443")
	}
	return out
}
