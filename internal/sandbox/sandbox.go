package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// Candidate — именованная стратегия-кандидат, проверяемая песочницей.
type Candidate struct {
	// Name — человекочитаемое имя для журнала.
	Name string
	// Strategy — дерево; ID уже вычислен (его ставит strategy.Unmarshal).
	Strategy *strategy.Strategy
}

// Observation — исход одной пробы песочницы.
//
// Свой тип, а не control.Observation: песочница поставляет наблюдения, но не
// знает, кто и как их считает. Приёмник (cmd) переводит его в наблюдение
// контура, проставляя источник (проба) и признак доли (ложь — это выделенное
// соединение, а не доля живого трафика). Так пакет песочницы не зависит от
// control (4.1: граница безопасности явная).
type Observation struct {
	// StrategyID — какой кандидат проверялся; пусто при Baseline.
	StrategyID core.StrategyID
	// Baseline — проба без десинка: мерилась сама цель. Нужна, чтобы исход
	// кандидата можно было истолковать — без неё «цель ответила» неотличимо от
	// «стратегия обошла DPI».
	Baseline bool
	// Target — цель пробы.
	Target string
	// Outcome — исход быстрого уровня (ok/fail/inconclusive).
	Outcome core.Outcome
	// At — время получения исхода.
	At time.Time
}

// Prober выполняет одну пробу к цели с закреплённого локального порта.
//
// Живая реализация — внешний curl с --local-port: измерено, что
// внутрипроцессная проба не получает десинк так, как внешнее соединение.
// Инъектируется, чтобы оркестровку проверять без сети и WinDivert.
type Prober interface {
	// Probe делает одну пробу к target, инициируя соединение с локального порта
	// localPort. Возвращает исход быстрого уровня. OutcomeInconclusive
	// означает, что проба не состоялась (вес 0), а не что цель недоступна.
	Probe(ctx context.Context, target string, localPort uint16) core.Outcome
}

// Reporter принимает исходы проб песочницы. Определён здесь, а не взят из
// control, по той же причине, что и свой Observation: песочница не зависит от
// контура управления.
type Reporter interface {
	Report(Observation)
}

// Options — зависимости песочницы.
type Options struct {
	Config     Config
	Candidates []Candidate
	// Targets — цели проб: все кандидаты проверяются по каждой из них.
	Targets  []string
	Prober   Prober
	Reporter Reporter
	Logger   *slog.Logger
	// Now — источник времени; nil означает time.Now. Подменяется в тестах.
	Now func() time.Time
}

// Sandbox ведёт подбор кандидатов на выделенных соединениях, не трогая
// пользовательский трафик (5.2).
//
// Отдельный контур перехвата песочницы (отдельный дескриптор WinDivert по
// диапазону портов, отдельная таблица потоков) спрашивает Provider() на каждом
// ClientHello пробы и применяет привязанного к порту кандидата. Сама Sandbox
// оркеструет пробы: берёт порт, привязывает к нему кандидата, запускает пробу,
// снимает привязку, отдаёт исход Reporter'у. Отбор и ротацию ведёт не она, а
// control по этим исходам.
type Sandbox struct {
	cfg        Config
	candidates []Candidate
	targets    []string
	ports      *portPool
	provider   *portProvider
	prober     Prober
	reporter   Reporter

	// perTarget — семафор на каждую цель (5.4): ограничивает одновременные
	// пробы к одной цели. По одному каналу на цель, создаются при сборке.
	perTarget map[string]chan struct{}
	// global — глобальный семафор воркеров (5.4).
	global chan struct{}

	now func() time.Time
	log *slog.Logger
}

// New собирает песочницу, проверив конфигурацию и зависимости.
func New(o Options) (*Sandbox, error) {
	if err := o.Config.validate(); err != nil {
		return nil, err
	}
	// Кандидаты и приёмник нужны только фоновому циклу Run (перебор портфеля).
	// Оценка по требованию (Evaluate), которой пользуется генератор, обходится
	// без них: стратегию ей передают в вызове, а исход она возвращает, а не
	// кладёт в контур. Поэтому пустой портфель и nil-приёмник — не ошибка, а
	// режим «только Evaluate». Непустой портфель обязан быть осмысленным:
	// кандидат без дерева — дефект.
	for i, c := range o.Candidates {
		if c.Strategy == nil {
			return nil, fmt.Errorf("sandbox: кандидат %d (%q) без стратегии", i, c.Name)
		}
	}
	if len(o.Targets) == 0 {
		return nil, errors.New("sandbox: не заданы цели проб")
	}
	if o.Prober == nil {
		return nil, errors.New("sandbox: не задан исполнитель проб")
	}

	pool, err := newPortPool(o.Config.PortLo, o.Config.PortHi)
	if err != nil {
		return nil, err
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	perTarget := make(map[string]chan struct{}, len(o.Targets))
	for _, t := range o.Targets {
		perTarget[t] = make(chan struct{}, o.Config.PerTarget)
	}

	return &Sandbox{
		cfg:        o.Config,
		candidates: append([]Candidate(nil), o.Candidates...),
		targets:    append([]string(nil), o.Targets...),
		ports:      pool,
		provider:   newPortProvider(),
		prober:     o.Prober,
		reporter:   o.Reporter,
		perTarget:  perTarget,
		global:     make(chan struct{}, o.Config.Workers),
		now:        now,
		log:        log,
	}, nil
}

// Provider возвращает провайдер «порт → кандидат» для контура перехвата
// песочницы. Он отдаёт привязку, действующую на момент ClientHello пробы.
func (s *Sandbox) Provider() proxy.StrategyProvider { return s.provider }

// Run ведёт непрерывный фоновый A/B: обход за обходом с паузой Round между
// ними, пока контекст не отменён. Это и есть то, чего не было у автопилота v1
// — подбор идёт постоянно и на выделенных соединениях, а не рывком на старте и
// при срыве.
func (s *Sandbox) Run(ctx context.Context) {
	// Фоновый перебор требует портфеля и приёмника исходов. Их отсутствие —
	// законный режим «только Evaluate» (генератор), и цикл тогда не запускается:
	// крутить обход без кандидатов значило бы без пользы слать базовые пробы.
	if len(s.candidates) == 0 || s.reporter == nil {
		s.log.Info("песочница: фоновый перебор не запущен (нет портфеля или приёмника)")
		return
	}
	s.log.Info("песочница запущена",
		"кандидатов", len(s.candidates), "целей", len(s.targets),
		"портов", s.ports.size(), "воркеров", s.cfg.Workers)
	for {
		if ctx.Err() != nil {
			return
		}
		s.RunRound(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.Round):
		}
	}
}

// Evaluate измеряет одну стратегию на выделенных соединениях и возвращает число
// удачных проб из отправленных. Это оценка по требованию — для генератора,
// которому нужно оценить конкретного кандидата сейчас, в отличие от фонового
// Run по фиксированному портфелю.
//
// Каждая проба берёт свой порт из пула (ротация против повторного занятия порта
// в TIME_WAIT), привязывает к нему стратегию, ждёт джиттер и шлёт пробу;
// nil-стратегия означает базовую линию (без десинка). Контур перехвата
// песочницы (отдельный дескриптор WinDivert по диапазону портов) выбирает
// стратегию по этому порту и накладывает десинк — как и в фоновом режиме.
//
// Исход OutcomeOK считается удачей; прочее (fail/inconclusive) — нет. Быстрый
// уровень (5.3): различать замедление не нужно, генетике довольно «обошёл или
// нет». Отмена контекста прекращает замер и возвращает уже накопленное.
func (s *Sandbox) Evaluate(ctx context.Context, strat *strategy.Strategy, target string, probes int) (success, total int) {
	for i := 0; i < probes; i++ {
		if ctx.Err() != nil {
			return success, total
		}
		port, err := s.ports.acquire(ctx)
		if err != nil {
			return success, total
		}
		if strat != nil {
			s.provider.bind(port, proxy.Selection{Strategy: strat, ID: strat.ID, Target: target})
		}
		if !s.jitter(ctx) {
			if strat != nil {
				s.provider.release(port)
			}
			s.ports.release(port)
			return success, total
		}
		outcome := s.prober.Probe(ctx, target, port)
		if strat != nil {
			s.provider.release(port)
		}
		s.ports.release(port)

		// Исход отменённой пробы не учитываем — он получен на оборванном замере.
		if ctx.Err() != nil {
			return success, total
		}
		total++
		if outcome == core.OutcomeOK {
			success++
		}
	}
	return success, total
}

// job — одна запланированная проба: кандидат (nil = базовая линия) к цели.
type job struct {
	cand   *Candidate
	target string
}

// buildRound строит список проб на один обход: по каждой цели сначала базовая
// линия, затем каждый кандидат.
func (s *Sandbox) buildRound() []job {
	jobs := make([]job, 0, len(s.targets)*(len(s.candidates)+1))
	for _, t := range s.targets {
		jobs = append(jobs, job{cand: nil, target: t})
		for i := range s.candidates {
			// Адрес элемента стабилен: срез кандидатов не меняется за время
			// жизни песочницы.
			jobs = append(jobs, job{cand: &s.candidates[i], target: t})
		}
	}
	return jobs
}

// RunRound прогоняет один обход портфеля: все пробы с соблюдением пределов
// параллельности (5.4). Возвращается, когда все пробы обхода завершены или
// контекст отменён. Пределы держат семафоры внутри runJob, поэтому запуск
// всех горутин разом безопасен: лишние паркуются на семафоре, а не грузят
// сеть.
func (s *Sandbox) RunRound(ctx context.Context) {
	var wg sync.WaitGroup
	for _, j := range s.buildRound() {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			s.runJob(ctx, j)
		}(j)
	}
	wg.Wait()
}

// runJob исполняет одну пробу: занимает воркера и место по цели (5.4), берёт
// порт, привязывает к нему кандидата, ждёт джиттер, пробует и отдаёт исход.
func (s *Sandbox) runJob(ctx context.Context, j job) {
	// Глобальный предел воркеров, затем предел на цель. Порядок постоянный,
	// чтобы не возникло взаимной блокировки при встречных ожиданиях.
	if !acquireSem(ctx, s.global) {
		return
	}
	defer releaseSem(s.global)
	if !acquireSem(ctx, s.perTarget[j.target]) {
		return
	}
	defer releaseSem(s.perTarget[j.target])

	// Джиттер до занятия порта, чтобы порт держался как можно меньше (5.4).
	if !s.jitter(ctx) {
		return
	}

	port, err := s.ports.acquire(ctx)
	if err != nil {
		return
	}
	defer s.ports.release(port)

	// Кандидату привязываем порт: контур перехвата песочницы выберет по нему
	// стратегию. Базовую линию не привязываем — её проба идёт без десинка.
	if j.cand != nil {
		s.provider.bind(port, proxy.Selection{
			Strategy: j.cand.Strategy,
			ID:       j.cand.Strategy.ID,
			Target:   j.target,
		})
		defer s.provider.release(port)
	}

	outcome := s.prober.Probe(ctx, j.target, port)

	// Исход отменённой пробы не учитываем: он получен на оборванном измерении
	// и только испортил бы оценку.
	if ctx.Err() != nil {
		return
	}

	obs := Observation{
		Baseline: j.cand == nil,
		Target:   j.target,
		Outcome:  outcome,
		At:       s.now(),
	}
	if j.cand != nil {
		obs.StrategyID = j.cand.Strategy.ID
		s.log.Debug("проба кандидата",
			"кандидат", j.cand.Name, "цель", j.target,
			"порт", port, "исход", outcome.String())
	}
	s.reporter.Report(obs)
}

// jitter ждёт случайное время в [0, cfg.Jitter] (5.4). Возвращает false, если
// ожидание прервано контекстом.
func (s *Sandbox) jitter(ctx context.Context) bool {
	if s.cfg.Jitter <= 0 {
		return ctx.Err() == nil
	}
	// rand/v2 потокобезопасен на уровне пакета, а джиттер вызывается из многих
	// горутин проб сразу.
	d := time.Duration(rand.Int64N(int64(s.cfg.Jitter) + 1))
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// acquireSem занимает место в семафоре, ожидая освобождения. false — контекст
// отменён.
func acquireSem(ctx context.Context, sem chan struct{}) bool {
	select {
	case sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// releaseSem освобождает место в семафоре. Парен к acquireSem.
func releaseSem(sem chan struct{}) { <-sem }
