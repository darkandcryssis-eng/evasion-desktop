package probe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// PlanItem — одна пара «цель × стратегия», которой нужны доказательства.
type PlanItem struct {
	// Target — цель радиуса. Именно цель, а не хост соединения: наблюдение
	// относится к четвёрке с целью радиуса (6.1).
	Target string
	// Host — к какому имени ходить. Пусто означает «идти к самой цели».
	//
	// Существует потому, что цель радиуса — суффикс («youtube.com»), а
	// проверять надо работающее имя («www.youtube.com»). Без этого поля
	// пришлось бы либо ходить к суффиксу, который может не отвечать вовсе,
	// либо приписывать наблюдение не той цели.
	Host string
	// Strategy, StrategyID — что проверяем. nil и пусто — у базовой пробы.
	Strategy   *strategy.Strategy
	StrategyID core.StrategyID
	// Baseline — проба без десинка: измеряется сама цель, а не стратегия.
	//
	// Признак явный, хотя его и можно было бы вывести из nil-стратегии.
	// Причина та же, по которой в Result есть StrategyApplied: «стратегии
	// нет» и «стратегия не применилась» — разные вещи, и приёмник результата
	// обязан различать их, не угадывая. Базовая линия — намерение, а не
	// отсутствие данных.
	Baseline bool
	// Degraded — цель деградирована: пробы по ней идут чаще (5.7).
	Degraded bool
}

// Plan — что проверить пробами на этом круге.
type Plan struct {
	Items []PlanItem
}

// Planner отдаёт план проб.
//
// Интерфейс объявлен здесь и реализуется контуром управления: кому нужны
// доказательства, знает портфель, а он принадлежит контуру. Обратной
// зависимости при этом не возникает — probe о контуре не знает, и переезд на
// этап 1 его не касается (4.7 п. 4).
type Planner interface {
	// ProbePlan возвращает пары, которым нужны доказательства.
	ProbePlan(ctx context.Context) (Plan, error)
}

// Sink принимает результаты проб.
//
// Отдаются собственные типы probe, а не наблюдения контура: перевод одного в
// другое — работа того, кто собирает движок. Так probe не тянет за собой ни
// контур, ни хранилище.
type Sink interface {
	// ProbeDone сообщает результат одной пробы.
	ProbeDone(item PlanItem, res Result)
}

// SchedulerConfig — параметры расписания проб (5.4, 5.7).
type SchedulerConfig struct {
	// Interval — интервал проб в норме.
	Interval time.Duration
	// DegradedInterval — интервал проб по деградированной цели: замену надо
	// искать быстро (5.7).
	DegradedInterval time.Duration
	// Jitter — доля разброса интервала, от 0 до 1.
	//
	// Обязателен (5.7): ровный интервал проб сам по себе рисунок трафика, по
	// которому машину видно. Нулевой разброс запрещён проверкой.
	Jitter float64
	// Workers — сколько проб идёт одновременно всего (5.4).
	Workers int
	// PerTarget — сколько проб идёт одновременно на одну цель.
	//
	// Предел нужен не для скорости, а для достоверности: если DPI держит
	// состояние по адресу источника, параллельные пробы к одной цели
	// коррелируют, и вместо N независимых наблюдений получается одно,
	// размазанное на N (5.4).
	PerTarget int

	// Planner, Sink — откуда брать план и куда отдавать результат.
	Planner Planner
	Sink    Sink
	// Probe — как выполнять пробу. nil означает быстрый уровень пробера.
	//
	// Подменяется в тестах: расписание и пределы параллельности надо
	// проверять без сети, иначе проверка превращается в измерение чужого
	// канала.
	Probe func(ctx context.Context, req Request) Result
	// Logger — журнал; nil означает отключённый.
	Logger *slog.Logger
	// Now — источник времени; nil означает time.Now.
	Now func() time.Time
}

// validate проверяет согласованность расписания.
func (c SchedulerConfig) validate() error {
	switch {
	case c.Interval <= 0:
		return errors.New("probe: интервал проб должен быть положительным")
	case c.DegradedInterval <= 0:
		return errors.New("probe: интервал проб при деградации должен быть положительным")
	case c.DegradedInterval > c.Interval:
		return fmt.Errorf("probe: интервал при деградации %v больше обычного %v: деградированную цель проверяют чаще, а не реже",
			c.DegradedInterval, c.Interval)
	case c.Jitter <= 0 || c.Jitter > 1:
		return fmt.Errorf("probe: разброс интервала %v вне интервала (0, 1]; нулевой разброс запрещён (5.7)", c.Jitter)
	case c.Workers < 1:
		return errors.New("probe: воркеров должно быть не меньше одного")
	case c.PerTarget < 1:
		return errors.New("probe: проб на цель должно быть не меньше одной")
	case c.PerTarget > c.Workers:
		return fmt.Errorf("probe: проб на цель %d больше числа воркеров %d", c.PerTarget, c.Workers)
	case c.Planner == nil:
		return errors.New("probe: планировщик без источника плана")
	case c.Sink == nil:
		return errors.New("probe: планировщик без приёмника результатов")
	}
	return nil
}

// Scheduler добывает доказательства пробами.
//
// Зачем существует. Порог допуска к живому трафику (5.5) открывается
// наблюдениями, а наблюдения кандидату взять негде: на пользовательский трафик
// его не пускает тот же порог. Без расписания проб нижняя ступень лестницы
// (5.1) закрыта, и автопилот умеет только исполнять закрепления человека. Это
// и была дыра в движке: пакет probe существовал с M4, а никто его не вызывал.
//
// Что знает: когда какую пару «цель × стратегия» проверить и сколько проб
// можно вести одновременно.
//
// Чего знать не должен: кому нужны доказательства (это план от контура), как
// считается оценка (scoring) и где хранится наблюдение (store).
type Scheduler struct {
	cfg   SchedulerConfig
	log   *slog.Logger
	now   func() time.Time
	probe func(ctx context.Context, req Request) Result

	// last — когда пара проверялась в последний раз. Принадлежит горутине
	// Run и её помощникам под мьютексом: круг запускает пробы параллельно, и
	// отметка ставится из них.
	mu   sync.Mutex
	last map[probeKey]time.Time
}

// probeKey — ключ отметки о последней пробе.
type probeKey struct {
	target   string
	strategy core.StrategyID
}

// NewScheduler создаёт планировщик проб.
func NewScheduler(cfg SchedulerConfig) (*Scheduler, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s := &Scheduler{
		cfg:   cfg,
		log:   cfg.Logger,
		now:   cfg.Now,
		probe: cfg.Probe,
		last:  make(map[probeKey]time.Time),
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.probe == nil {
		return nil, errors.New("probe: планировщик без способа выполнить пробу")
	}
	return s, nil
}

// NewSchedulerWithProber создаёт планировщик, выполняющий пробы быстрого
// уровня заданным пробером.
//
// Быстрый уровень, а не медленный: генератору и отбору кандидатов достаточно
// двоичного «обманулся ли DPI», видного по рукопожатию, а замер полосы стоит
// в восемьдесят раз дороже (5.3). Медленный уровень применяется отдельно, к
// стратегиям, дошедшим до решения о повышении.
func NewSchedulerWithProber(cfg SchedulerConfig, p *Prober) (*Scheduler, error) {
	if p == nil {
		return nil, errors.New("probe: планировщик без пробера")
	}
	if cfg.Probe == nil {
		cfg.Probe = p.Fast
	}
	return NewScheduler(cfg)
}

// Run ведёт расписание до отмены контекста.
//
// Круг запускается не по общему тикеру, а по наименьшему из интервалов: внутри
// круга каждая пара сверяется со своим сроком. Общий тикер по большому
// интервалу задерживал бы деградированные цели, для которых весь смысл в
// быстром поиске замены (5.7).
func (s *Scheduler) Run(ctx context.Context) error {
	// Первый круг идёт сразу: ждать интервал на старте значило бы оставить
	// движок без доказательств на первые двенадцать минут.
	if _, err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
		s.log.Warn("круг проб не удался", "ошибка", err)
	}

	for {
		wait := s.jittered(s.cfg.DegradedInterval)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		if _, err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("круг проб не удался", "ошибка", err)
		}
	}
}

// RunOnce проводит один круг проб и возвращает число выполненных.
//
// Выделен отдельно не для тестов (хотя и для них): этот же круг нужен командам
// doctor и blockcheck, которым расписание не нужно — им нужен один честный
// замер прямо сейчас.
func (s *Scheduler) RunOnce(ctx context.Context) (int, error) {
	plan, err := s.cfg.Planner.ProbePlan(ctx)
	if err != nil {
		return 0, fmt.Errorf("probe: план проб: %w", err)
	}

	due := s.due(plan.Items)
	if len(due) == 0 {
		return 0, nil
	}

	var (
		wg      sync.WaitGroup
		global  = make(chan struct{}, s.cfg.Workers)
		perHost = make(map[string]chan struct{}, len(due))
		done    int
		doneMu  sync.Mutex
	)
	for _, it := range due {
		if _, ok := perHost[it.Target]; !ok {
			perHost[it.Target] = make(chan struct{}, s.cfg.PerTarget)
		}
	}

	for _, it := range due {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(it PlanItem) {
			defer wg.Done()

			// Два предела сразу: общий и на цель. Общий берёт на себя нагрузку
			// машины, на цель — достоверность измерения.
			select {
			case global <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-global }()

			slot := perHost[it.Target]
			select {
			case slot <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-slot }()

			res := s.probeOne(ctx, it)
			s.cfg.Sink.ProbeDone(it, res)

			doneMu.Lock()
			done++
			doneMu.Unlock()
		}(it)
	}
	wg.Wait()
	return done, nil
}

// due отбирает пары, которым пора: у каждой свой срок, и деградированная цель
// проверяется чаще.
func (s *Scheduler) due(items []PlanItem) []PlanItem {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []PlanItem
	for _, it := range items {
		k := probeKey{target: it.Target, strategy: it.StrategyID}
		interval := s.cfg.Interval
		if it.Degraded {
			interval = s.cfg.DegradedInterval
		}
		if last, seen := s.last[k]; seen && now.Sub(last) < interval {
			continue
		}
		s.last[k] = now
		out = append(out, it)
	}
	return out
}

// probeOne выполняет одну пробу.
func (s *Scheduler) probeOne(ctx context.Context, it PlanItem) Result {
	host := it.Host
	if host == "" {
		host = it.Target
	}
	req := Request{
		// Цель пробы — имя с портом TLS: движок работает с HTTPS, и порт 443
		// здесь не настройка, а свойство измеряемого протокола.
		Target:     host + ":443",
		SNI:        host,
		Strategy:   it.Strategy,
		StrategyID: it.StrategyID,
	}
	res := s.probe(ctx, req)
	s.log.Info("проба выполнена",
		"цель", it.Target,
		"имя", host,
		"стратегия", it.StrategyID.String(),
		// Базовую пробу надо отличать в журнале: её исход читается
		// противоположно. Провал базовой пробы — довод в пользу стратегий
		// (цель блокируется), успех — довод против (цель жива и так).
		"базовая", it.Baseline,
		"исход", res.Outcome.String(),
		"причина", string(res.Reason))
	return res
}

// jittered разбрасывает интервал в пределах заданной доли.
//
// Разброс обязателен (5.7): ровный интервал проб — сам по себе рисунок
// трафика, по которому машину видно, а движку незачем отдавать DPI
// дополнительные сведения о своём поведении.
func (s *Scheduler) jittered(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	// Разброс симметричный: интервал одинаково часто короче и длиннее
	// заданного, иначе среднее расписание уехало бы в одну сторону.
	span := float64(d) * s.cfg.Jitter
	delta := (rand.Float64()*2 - 1) * span
	out := time.Duration(float64(d) + delta)
	if out < time.Millisecond {
		out = time.Millisecond
	}
	return out
}
