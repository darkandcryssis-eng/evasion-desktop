package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync/atomic"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/policy"
	"github.com/fitting-1c/evasion/internal/scoring"
	"github.com/fitting-1c/evasion/internal/store"
)

// Observation — наблюдение, пришедшее контуру с живого трафика или от пробы.
//
// Отдельный тип, а не store.Observation: хранилищу нужна полная запись со
// всеми измерениями, а контуру — только то, из чего складывается оценка.
// Принимать здесь полную запись значило бы тащить в горячий путь приёма поля,
// которые ему не нужны.
type Observation struct {
	// StrategyID — какая стратегия применялась. Пусто допустимо только при
	// Baseline.
	StrategyID core.StrategyID
	// Baseline — наблюдение без стратегии: измерялась сама цель.
	//
	// Базовая линия нужна затем, чтобы исход со стратегией можно было
	// истолковать: без неё «цель ответила» неотличимо от «стратегия обошла
	// DPI», и оценка растёт за чужую заслугу.
	Baseline bool
	// Target — к какой цели шло соединение.
	Target string
	// Outcome — исход (5.7). «Не определено» имеет нулевой вес, но считается.
	Outcome core.Outcome
	// Source — происхождение наблюдения; определяет вес (5.7).
	Source store.Source
	// Trial — наблюдение получено на доле проверки (5.1). Нужно учёту: по
	// нему видно, сколько соединений реально ушло на проверку.
	Trial bool
	// At — время наблюдения.
	At time.Time
}

// validate проверяет пригодность наблюдения к учёту.
//
// Пустая стратегия допустима только вместе с признаком Baseline, и это не
// формальность. Наблюдение, потерявшее стратегию по дороге, — настоящий дефект
// (так уже случалось с целью наблюдения), и если пустой идентификатор сам по
// себе признать базовой линией, такой дефект осел бы в эталоне: цель
// выглядела бы доступной по исходам чужих стратегий, и кредит перестали бы
// получать все. Поэтому базовая линия заявляется явно, а несогласованное
// наблюдение по-прежнему отвергается и видно в status как invalid.
func (o Observation) validate() error {
	switch {
	case o.Baseline && o.StrategyID != "":
		return errors.New("control: базовое наблюдение со стратегией")
	case !o.Baseline && o.StrategyID == "":
		return errors.New("control: наблюдение без стратегии")
	case o.Target == "":
		return errors.New("control: наблюдение без цели")
	case o.At.IsZero():
		return errors.New("control: наблюдение без времени")
	}
	return nil
}

// Options — всё, что нужно контуру при создании.
type Options struct {
	// Vantage — точка наблюдения (6.1). Обязательна: без неё наблюдения
	// некуда отнести.
	Vantage core.VantageID
	// Targets — радиус поражения: цели, по которым принимаются решения.
	Targets []string
	// Portfolio — начальный портфель стратегий.
	Portfolio Portfolio
	// Pins — начальные закрепления: цель → стратегия.
	//
	// Отдельно от команды Pin намеренно. Закрепления, заданные конфигом, — это
	// начальное состояние, а не действие: они известны до первого снимка.
	// Подавать их командами после запуска значило бы считать первый снимок без
	// них, то есть опубликовать состояние «ничего не применяется», поднять
	// ложную тревогу об обвале портфеля (5.8) и затем пересчитать снимок
	// столько раз, сколько в радиусе целей. Так и было, пока живой прогон не
	// показал в журнале восемь снимков и тревогу на старте.
	Pins map[string]core.StrategyID
	// Coverage — какие домены покрывает решение по цели (представитель группы →
	// все домены группы). Нужно затем, что не всякий домен радиуса можно
	// прозондировать независимо: решение по представителю применяется ко всей
	// группе (см. PlanInput.Coverage). Пусто означает подоменное решение.
	Coverage map[string][]string
	// Warmup — наблюдения для прогрева оценок при старте (тёплый старт).
	//
	// Оценки живут в памяти и исчезают при перезапуске, а каждое наблюдение
	// добыто живым соединением. Без прогрева движок после каждого запуска
	// учился бы заново, теряя уже найденную рабочую стратегию, — ровно та
	// потеря, на которой владелец терял прогресс при перезапуске --auto.
	// Наблюдения проигрываются в таблицу оценок ДО первого снимка, поэтому
	// первое же решение принимается по восстановленной истории, а не по
	// пустоте и не по ложной тревоге об обвале портфеля (5.8).
	//
	// Что обязан обеспечить вызывающий, и почему именно он:
	//   - подать только наблюдения этой точки наблюдения — оценки ключуются ею
	//     (6.1), и чужие сюда не относятся; у вызывающего есть и журнал, и
	//     точка наблюдения, а у контура — только точка;
	//   - подать только свежие наблюдения, за срок доверия к оценкам (5.9):
	//     воскрешать то, что движок и сам считает устаревшим, незачем. Отбор по
	//     сроку — забота вызывающего, у которого есть конфиг.
	//
	// Порядок подачи неважен: прогрев сам упорядочит по времени, иначе
	// затухание исказилось бы (оно применяется только вперёд во времени).
	Warmup []Observation
	// Control, Scoring — параметры автопилота. Приходят уже разобранными:
	// пакет config зависит от control, поэтому обратной зависимости быть не
	// может, и это правильный порядок — контур не должен знать про файлы.
	Control Config
	Scoring scoring.Config
	// Table — горячая таблица, в которую публикуются снимки. Обязательна:
	// контур без таблицы не влияет ни на что.
	Table *policy.Table
	// Interval — период пересчёта снимка. Ноль означает «только по команде»:
	// законный режим для CLI и тестов, когда пересчёт вызывается явно.
	Interval time.Duration
	// StatusInterval — период выкладывания состояния в файл.
	//
	// Отдельно от Interval, и это главное в настройке. Состояние меняется не
	// только при пересчёте: наблюдения принимаются непрерывно, а счётчики
	// приёма и число оценок — именно то, по чему человек судит, учится ли
	// движок. Пока состояние писалось только при пересчёте, команда status
	// показывала нули после реально выполненных проб, и вывод «движок не
	// работает» был естественным и неверным.
	//
	// Ноль означает значение по умолчанию, а не «не выкладывать». Направление
	// выбрано сознательно: выкладывание — это наблюдаемость, и забытое поле не
	// должно её молча отключать. Ровно так уже терялся StatusPath, и движок
	// работал, а status говорил «не запущен». Выключается выкладывание пустым
	// StatusPath — то есть явно.
	StatusInterval time.Duration
	// Queue — ёмкость очереди наблюдений. Ноль означает значение по умолчанию.
	Queue int
	// Logger — журнал. nil означает отключённый журнал.
	Logger *slog.Logger
	// Now — источник времени. nil означает time.Now. Подменяется в тестах:
	// иначе выдержку и свежесть пришлось бы ожидать по-настоящему.
	Now func() time.Time
	// StatusPath — файл, в который выкладывается состояние движка для команд
	// status и portfolio (2.3). Пусто означает «не выкладывать»: движок,
	// запущенный без каталога состояния, обязан работать.
	StatusPath string
}

// defaultQueue — ёмкость очереди наблюдений по умолчанию.
//
// Очередь нужна потому, что приём наблюдений не имеет права задерживать
// соединение: горутина соединения кладёт наблюдение и уходит. Размер выбран
// так, чтобы всплеск соединений не приводил к потерям на обычной машине, и при
// этом память была ограничена.
const defaultQueue = 1024

// defaultStatusInterval — как часто выкладывается состояние движка.
//
// Две секунды: человек, запустивший status после проб, не должен видеть
// устаревшую картину, а запись идёт только при изменениях, поэтому в покое
// движок не трогает диск вовсе. Цена при потоке наблюдений — одна запись
// небольшого файла в две секунды, что несопоставимо дешевле ложного вывода
// «движок не учится».
const defaultStatusInterval = 2 * time.Second

// Engine — горутина-владелец контура управления (4.2, правило 2).
//
// Владеет всем изменяемым состоянием: таблицей оценок (она намеренно не
// потокобезопасна), портфелем, памятью о целях, закреплениями. Никто другой
// это состояние не трогает: команды приходят каналом, наблюдения — каналом,
// результат публикуется атомарной подменой снимка в policy.Table.
//
// Почему не мьютексы. Защитив отдельные обращения, мьютекс не защитил бы
// последовательность «прочитать оценку, решить, записать» — а именно она и
// составляет работу контура. Ошибка была бы не в гонке на поле, а в решении,
// принятом по половине состояния.
type Engine struct {
	// Поля ниже неизменяемы после создания и читаются любой горутиной.
	table *policy.Table
	log   *slog.Logger
	now   func() time.Time
	tick  time.Duration
	// statusPath — куда выкладывать состояние; пусто означает «никуда».
	statusPath string
	// statusTick — период выкладывания состояния.
	statusTick time.Duration

	cmds chan command
	obs  chan Observation
	// ready закрывается, когда опубликован первый снимок.
	//
	// Нужен запуску: прокси не должен принимать соединения раньше, чем в
	// горячей таблице появится снимок. Иначе первые соединения пройдут без
	// стратегии — безопасно (прозрачный пропуск, 1.6), но случайно: сколько
	// их окажется, зависит от того, кто быстрее стартовал. Случайности в том,
	// применяется ли стратегия, быть не должно: именно из таких «иногда
	// применяется» потом вырастают необъяснимые измерения.
	ready chan struct{}

	// Счётчики приёма. Атомарные потому, что инкрементирует их горутина
	// соединения, а читает горутина-владелец: это единственное состояние
	// контура, которое по необходимости общее.
	accepted atomic.Int64
	dropped  atomic.Int64
	invalid  atomic.Int64

	// Поля ниже принадлежат горутине Run и больше никому.
	decider   *Decider
	scores    *scoring.Table
	portfolio Portfolio
	states    map[string]TargetState
	pins      map[string]core.StrategyID
	coverage  map[string][]string
	targets   []string
	vantage   core.VantageID
	rev       uint64
	lastPlan  time.Time
	blackout  bool
	trialPerm int
	// lastDecisions — причины последних решений по целям. Хранятся для status:
	// автопилот, который ничего не меняет, обязан объяснять, почему именно, и
	// без этой памяти объяснение терялось бы сразу после пересчёта.
	lastDecisions map[string]Decision
	// statusStale — состояние изменилось с последней записи файла.
	//
	// Нужен, чтобы таймер не писал на диск одно и то же без конца. Движок без
	// трафика и без проб ничего не меняет, и файл в этом случае трогать
	// незачем: запись «на всякий случай» каждые две секунды была бы работой,
	// которая никогда ничего не меняет.
	statusStale bool
	// statusFailed — последняя попытка выложить состояние не удалась.
	//
	// Нужен, чтобы о неполадке сообщалось один раз, а не каждые две секунды, и
	// чтобы о её устранении тоже сообщалось: «состояние снова выкладывается» —
	// это ответ на вопрос, который человек задаст, увидев предупреждение.
	statusFailed bool
}

// New создаёт контур управления.
func New(o Options) (*Engine, error) {
	if o.Vantage == "" {
		return nil, errors.New("control: контур без точки наблюдения")
	}
	if o.Table == nil {
		return nil, errors.New("control: контур без горячей таблицы")
	}
	decider, err := NewDecider(o.Control)
	if err != nil {
		return nil, err
	}
	scores, err := scoring.NewTable(o.Scoring)
	if err != nil {
		return nil, err
	}
	if o.Interval < 0 {
		return nil, fmt.Errorf("control: период пересчёта %v отрицателен", o.Interval)
	}
	if o.StatusInterval < 0 {
		return nil, fmt.Errorf("control: период выкладывания состояния %v отрицателен", o.StatusInterval)
	}
	statusTick := o.StatusInterval
	if statusTick == 0 {
		statusTick = defaultStatusInterval
	}

	queue := o.Queue
	if queue <= 0 {
		queue = defaultQueue
	}
	nowFn := o.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	log := o.Logger
	if log == nil {
		log = slog.New(discardHandler{})
	}

	// Закрепление на стратегию, которой нет в портфеле, применять нечем.
	// Проверяется здесь, при создании, а не при первом снимке: это ошибка
	// настройки, и сообщить о ней надо до запуска, а не записью в журнал.
	pins := make(map[string]core.StrategyID, len(o.Pins))
	for target, id := range o.Pins {
		if target == "" {
			return nil, errors.New("control: закрепление без цели")
		}
		if _, ok := o.Portfolio[id]; !ok {
			return nil, fmt.Errorf("control: закрепление цели %s на стратегию %s, которой нет в портфеле", target, id)
		}
		pins[target] = id
	}

	e := &Engine{
		table:         o.Table,
		log:           log,
		now:           nowFn,
		tick:          o.Interval,
		cmds:          make(chan command),
		ready:         make(chan struct{}),
		obs:           make(chan Observation, queue),
		decider:       decider,
		scores:        scores,
		portfolio:     clonePortfolio(o.Portfolio),
		states:        make(map[string]TargetState),
		pins:          pins,
		coverage:      o.Coverage,
		lastDecisions: make(map[string]Decision),
		targets:       append([]string(nil), o.Targets...),
		vantage:       o.Vantage,
		statusPath:    o.StatusPath,
		statusTick:    statusTick,
	}
	// Прогрев — до запуска Run и до первого снимка: восстановленная история
	// должна влиять уже на первое решение. Безопасно трогать таблицу оценок
	// здесь, хотя она не потокобезопасна: горутины-владельца ещё нет (Run не
	// запущен), конкурентов тоже.
	e.warmup(o.Warmup)
	return e, nil
}

// warmup проигрывает наблюдения тёплого старта в таблицу оценок.
//
// Порядок по времени обязателен: затухание в scoring применяется только вперёд,
// и перемешанные наблюдения дали бы другую оценку, а серия провалов и
// чередование — другой требуемый объём (5.5). Поэтому сортируем, а не доверяем
// порядку вызывающего.
//
// Точка наблюдения берётся контурная (e.vantage), а не из наблюдения: ключ
// оценки ключуется ею (6.1), и вызывающий обязан подать только свои наблюдения.
// Негодное наблюдение пропускается со счётом, а не роняет прогрев: журнал мог
// быть записан другой версией, и терять из-за одной строки весь набор хуже, чем
// недосчитать её.
func (e *Engine) warmup(obs []Observation) {
	if len(obs) == 0 {
		return
	}
	sorted := append([]Observation(nil), obs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].At.Before(sorted[j].At) })

	var skipped int
	for _, o := range sorted {
		if err := o.validate(); err != nil {
			skipped++
			continue
		}
		e.scores.Observe(scoring.Key{
			StrategyID: o.StrategyID,
			Target:     o.Target,
			VantageID:  e.vantage,
		}, o.Outcome, o.Source, o.At)
	}
	e.log.Info("оценки прогреты из журнала",
		"восстановлено", len(sorted)-skipped,
		"пропущено_негодных", skipped,
		"точка_наблюдения", e.vantage.String())
}

// Ready ждёт публикации первого снимка.
//
// Запуск обязан этим пользоваться: прокси начинает слушать только после того,
// как в горячей таблице появился снимок. Иначе вопрос «применилась ли стратегия
// к первому соединению» решался бы гонкой между стартом прокси и стартом
// контура.
//
// Возвращает ошибку контекста, если ждать больше нельзя: контур могли
// остановить до того, как он успел посчитать первый снимок, и вечное ожидание
// превратило бы это в зависание.
func (e *Engine) Ready(ctx context.Context) error {
	select {
	case <-e.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Observe принимает наблюдение, не блокируя вызывающего.
//
// Возвращает false, если наблюдение отброшено. Отбрасывание, а не ожидание —
// то же решение, что в store.Writer и по той же причине: ожидание означало бы,
// что медленный контур управления замедляет пользовательский трафик. Потери
// считаются и видны в status, поэтому тихой деградации не выходит.
//
// Вызывается из горутин соединений, то есть из многих сразу; поэтому здесь нет
// ничего, кроме отправки в канал и атомарного счётчика.
func (e *Engine) Observe(o Observation) bool {
	if err := o.validate(); err != nil {
		e.invalid.Add(1)
		return false
	}
	select {
	case e.obs <- o:
		e.accepted.Add(1)
		return true
	default:
		e.dropped.Add(1)
		return false
	}
}

// Run ведёт контур до отмены контекста. Это и есть горутина-владелец: всё
// изменяемое состояние меняется только здесь.
func (e *Engine) Run(ctx context.Context) error {
	// Первый снимок считается сразу: до него таблица пуста и трафик идёт
	// прозрачным пропуском. Ждать первого тика значило бы держать движок
	// бездействующим на весь период.
	e.replan("старт")
	close(e.ready)

	var tickC <-chan time.Time
	if e.tick > 0 {
		ticker := time.NewTicker(e.tick)
		defer ticker.Stop()
		tickC = ticker.C
	}

	// Состояние выкладывается своим таймером, независимым от пересчёта.
	//
	// Без него файл состояния обновлялся бы только при пересчёте снимка (по
	// умолчанию раз в минуту), и человек, запустивший status сразу после проб,
	// видел бы нули: наблюдения приняты, а в файле картина с прошлого
	// пересчёта. Вывод «движок не учится» из этого следует сам, и он неверен.
	var statusC <-chan time.Time
	if e.statusPath != "" && e.statusTick > 0 {
		ticker := time.NewTicker(e.statusTick)
		defer ticker.Stop()
		statusC = ticker.C
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case o := <-e.obs:
			e.ingest(o)
		case c := <-e.cmds:
			e.handle(c)
		case <-tickC:
			e.replan("период")
		case <-statusC:
			// Пересчёта здесь нет намеренно: решения принимаются по своему
			// расписанию и с выдержкой, а это лишь публикация того, что уже
			// известно. Считать снимок каждые две секунды значило бы подменить
			// период пересчёта и обесценить выдержку.
			e.publishStatusIfStale()
		}
	}
}

// ingest учитывает одно наблюдение.
//
// Наблюдения по стратегиям, которых нет в портфеле, учитываются тоже: они
// относятся к ступени, с которой стратегия уже ушла, но исход от этого не
// перестаёт быть исходом. Отбросить их значило бы потерять ровно те данные, по
// которым видно, что снятие было верным.
// Базовое наблюдение попадает в ту же таблицу с пустым идентификатором
// стратегии (scoring.BaselineKey): оно затухает и копится по тем же правилам,
// и второго механизма учёта в движке не появляется. Из отбора стратегий
// базовая линия исключена самой таблицей (scoring.Table.Rank).
func (e *Engine) ingest(o Observation) {
	e.scores.Observe(scoring.Key{
		StrategyID: o.StrategyID,
		Target:     o.Target,
		VantageID:  e.vantage,
	}, o.Outcome, o.Source, o.At)

	// Состояние изменилось: прибавилось наблюдение, возможно — оценка, а
	// именно по этим числам человек судит, учится ли движок. Отметка нужна
	// затем, чтобы таймер выложил файл; сама запись здесь была бы записью на
	// диск на каждое наблюдение, то есть приём наблюдений начал бы зависеть
	// от скорости диска.
	e.statusStale = true
}

// drainObs учитывает наблюдения, уже лежащие в очереди, не ожидая новых.
//
// Вызывается перед пересчётом. Не блокируется: если очередь пуста, возвращает
// управление сразу, поэтому пересчёт не зависит от того, идёт ли трафик.
//
// Число наблюдений за один заход ограничено ёмкостью очереди, и это не
// перестраховка. Без предела при плотном потоке наблюдений вычерпывание не
// кончалось бы никогда: писатели пополняют очередь быстрее, чем владелец её
// разбирает, и до канала команд дело не доходит — движок перестаёт отвечать на
// status и на закрепление. Обнаружено прогоном под -race, где writers
// опережают владельца особенно сильно.
//
// Цена предела: при переполнении решение принимается по очереди глубиной не
// больше одной ёмкости, а остаток ждёт основного цикла. Это ровно та же
// уступка, что и отбрасывание при переполнении: свежесть данных уступает
// отзывчивости движка.
func (e *Engine) drainObs() {
	for range cap(e.obs) {
		select {
		case o := <-e.obs:
			e.ingest(o)
		default:
			return
		}
	}
}

// replan пересчитывает снимок и публикует его.
//
// Причина пересчёта передаётся для журнала: «почему снимок сменился» —
// первый вопрос при разборе поведения движка.
func (e *Engine) replan(cause string) {
	// Сначала вычерпываем всё, что уже пришло.
	//
	// Без этого решение принималось бы по неполным данным: select выбирает из
	// готовых каналов случайно, поэтому команда пересчёта могла опередить
	// наблюдения, лежащие в очереди с прошлой секунды. Снимок считался бы по
	// части доказательств, причём по какой именно — зависело бы от удачи.
	// Такую невоспроизводимость в решениях автопилота допускать нельзя.
	e.drainObs()

	now := e.now()
	plan := e.decider.BuildPlan(e.scores, PlanInput{
		Vantage:   e.vantage,
		Targets:   e.targets,
		States:    e.states,
		Pins:      e.pins,
		Portfolio: e.portfolio,
		Coverage:  e.coverage,
		Now:       now,
	})

	// Снимок строится с новым номером. Номер растёт даже тогда, когда
	// содержимое не изменилось: он отвечает на вопрос «какой снимок сейчас
	// живёт», а не «сколько раз менялись решения».
	e.rev++
	snap, err := policy.NewSnapshot(e.vantage, e.rev, plan.Entries)
	if err != nil {
		// Негодный план — дефект контура, а не сети. Прежний снимок остаётся
		// жить: он хуже нового, но он работает, а подменять его на пустой
		// значило бы наказать пользователя за свою ошибку (1.6).
		e.log.Error("снимок не построен, остаётся прежний",
			"причина", cause, "ошибка", err, "номер", e.rev)
		return
	}
	e.table.Install(snap)

	wasBlackout := e.blackout
	e.applyPlan(plan, now)
	e.lastPlan = now
	e.blackout = plan.Blackout
	e.trialPerm = plan.TrialPermille

	for _, dec := range plan.Changes() {
		e.log.Info("стратегия цели сменилась",
			"цель", dec.Target,
			"было", dec.Previous.String(),
			"стало", dec.Effective().String(),
			"причина", string(dec.Reason),
			"снимок", e.rev)
	}
	for _, dec := range plan.Trials() {
		e.log.Info("кандидат на доле трафика",
			"цель", dec.Target,
			"стратегия", dec.Trial.String(),
			"доля_промилле", dec.TrialPermille,
			"снимок", e.rev)
	}
	e.publishStatus()

	// Тревога пишется на переходе в обвал, а не на каждом пересчёте.
	//
	// Прежде она звучала каждый пересчёт (по умолчанию раз в период), и во
	// время обычного прогрева — пока песочница набирает доказательства и
	// применять ещё нечего — журнал заливался строками ERROR, в которых
	// настоящая авария потерялась бы. Само состояние обвала по-прежнему видно
	// постоянно: признак Blackout живёт в status и в файле состояния. Это тот
	// же приём «логировать переход, а не состояние», что у killswitch и у
	// выкладывания состояния.
	switch {
	case plan.Blackout && !wasBlackout:
		// Громкая тревога (5.8). Уровень именно Error: состояние «не работает
		// ничего» — авария, а не сведение к размышлению.
		e.log.Error("полный обвал портфеля: ни одной действующей стратегии",
			"целей", len(plan.Entries),
			"доля_проверки_промилле", plan.TrialPermille,
			"снимок", e.rev)
	case !plan.Blackout && wasBlackout:
		// Выход из обвала так же значим, как вход: по нему видно, что движок
		// снова держит обход.
		e.log.Info("обвал портфеля снят: действующая стратегия найдена",
			"снимок", e.rev)
	}
}

// publishStatus выкладывает состояние движка в файл, если он задан.
//
// Ошибка записи не останавливает контур и не отменяет снимок: состояние — это
// наблюдаемость, а не работа движка. Упасть из-за недоступного каталога
// значило бы променять обход DPI на отчётность о нём.
func (e *Engine) publishStatus() {
	if e.statusPath == "" {
		return
	}
	if err := WriteStatusFile(e.statusPath, e.status()); err != nil {
		// Отметка НЕ снимается: обновление состояния не состоялось, и
		// следующий тик обязан попробовать снова. Так ведёт себя и Windows,
		// где замену файла способен заблокировать читатель, — потеря в этом
		// случае временная, а наблюдаемость важнее одной лишней попытки.
		//
		// В журнал пишется только первая неудача подряд. Недоступный каталог
		// иначе давал бы предупреждение каждые две секунды — шум, в котором
		// настоящая неполадка теряется.
		if !e.statusFailed {
			e.log.Warn("состояние не выложено", "ошибка", err, "путь", e.statusPath)
			e.statusFailed = true
		}
		return
	}
	if e.statusFailed {
		e.log.Info("состояние снова выкладывается", "путь", e.statusPath)
		e.statusFailed = false
	}
	e.statusStale = false
}

// publishStatusIfStale выкладывает состояние, если оно изменилось с последней
// записи.
func (e *Engine) publishStatusIfStale() {
	if !e.statusStale {
		return
	}
	e.publishStatus()
}

// applyPlan переносит последствия плана в состояние владельца: память о целях
// и ступени жизненного цикла.
func (e *Engine) applyPlan(plan Plan, now time.Time) {
	for _, dec := range plan.Decisions {
		st := e.states[dec.Target]
		if dec.Changes() {
			st.Current = dec.Effective()
			st.Since = now
			st.Switches++
			// История цели пополняется, потому что от неё зависит требуемый
			// объём наблюдений в следующий раз (scoring.RequiredObservations).
			switch dec.Reason {
			case ReasonBrokenReplaced, ReasonBrokenDisabled,
				ReasonCollateralReplaced, ReasonCollateralDisabled:
				st.Degraded = appendUnique(st.Degraded, dec.Previous)
			}
		}
		e.states[dec.Target] = st
		e.lastDecisions[dec.Target] = dec
	}

	// Статусы сводятся по всем целям сразу: статус у стратегии один (4.5).
	for id, status := range Merge(plan.Transitions) {
		h, ok := e.portfolio[id]
		if !ok {
			continue
		}
		if h.Status == status {
			continue
		}
		e.log.Info("ступень стратегии изменилась",
			"стратегия", id.String(), "было", h.Status.String(), "стало", status.String())
		h.Status = status
		e.portfolio[id] = h
	}
}

// handle исполняет одну команду. Все команды обрабатываются здесь, то есть в
// горутине-владельце, и поэтому могут менять состояние без оглядки.
func (e *Engine) handle(c command) {
	switch c.kind {
	case cmdStatus:
		c.reply(e.status(), nil)
	case cmdProbeItems:
		c.reply(e.probeItems(), nil)
	case cmdReplan:
		e.replan("команда")
		c.reply(nil, nil)
	case cmdPin:
		if _, ok := e.portfolio[c.strategy]; !ok {
			c.reply(nil, fmt.Errorf("control: стратегии %s нет в портфеле", c.strategy))
			return
		}
		e.pins[c.target] = c.strategy
		e.log.Info("стратегия закреплена", "цель", c.target, "стратегия", c.strategy.String())
		e.replan("закрепление")
		c.reply(nil, nil)
	case cmdUnpin:
		if _, ok := e.pins[c.target]; !ok {
			c.reply(nil, fmt.Errorf("control: цель %s не закреплена", c.target))
			return
		}
		delete(e.pins, c.target)
		e.log.Info("закрепление снято", "цель", c.target)
		e.replan("снятие закрепления")
		c.reply(nil, nil)
	case cmdCollateral:
		h, ok := e.portfolio[c.strategy]
		if !ok {
			c.reply(nil, fmt.Errorf("control: стратегии %s нет в портфеле", c.strategy))
			return
		}
		h.Collateral = c.flag
		e.portfolio[c.strategy] = h
		// Побочный вред требует немедленной реакции (5.1): пересчёт тут же, а
		// не на следующем тике.
		e.log.Warn("побочный вред изменён", "стратегия", c.strategy.String(), "вредит", c.flag)
		e.replan("побочный вред")
		c.reply(nil, nil)
	case cmdAllowCollateral:
		h, ok := e.portfolio[c.strategy]
		if !ok {
			c.reply(nil, fmt.Errorf("control: стратегии %s нет в портфеле", c.strategy))
			return
		}
		h.CollateralAllowed = c.flag
		e.portfolio[c.strategy] = h
		e.log.Warn("разрешение на побочный вред изменено",
			"стратегия", c.strategy.String(), "разрешено", c.flag)
		e.replan("разрешение вреда")
		c.reply(nil, nil)
	case cmdAdd:
		e.portfolio[c.strategy] = c.holding
		e.log.Info("стратегия добавлена в портфель",
			"стратегия", c.strategy.String(), "ступень", c.holding.Status.String())
		e.replan("портфель пополнен")
		c.reply(nil, nil)
	case cmdReload:
		if err := e.reload(c.control, c.scoring, c.targets); err != nil {
			c.reply(nil, err)
			return
		}
		c.reply(nil, nil)
	case cmdVantage:
		if c.vantage == "" {
			c.reply(nil, errors.New("control: пустая точка наблюдения"))
			return
		}
		e.changeVantage(c.vantage)
		c.reply(nil, nil)
	default:
		c.reply(nil, fmt.Errorf("control: неизвестная команда %d", c.kind))
	}
}

// reload применяет новые параметры без перезапуска (10.5).
//
// Порядок важен: сначала проверяем оба набора параметров, и только потом
// меняем состояние. Иначе негодная конфигурация оставила бы контур с
// половиной применённых настроек — состоянием, которого нет ни в одном файле.
func (e *Engine) reload(c Config, s scoring.Config, targets []string) error {
	decider, err := NewDecider(c)
	if err != nil {
		return err
	}
	if err := e.scores.Reconfigure(s); err != nil {
		return err
	}
	e.decider = decider
	if targets != nil {
		e.targets = append([]string(nil), targets...)
	}
	e.log.Info("конфигурация перечитана",
		"выдержка", c.MinDwell.String(),
		"доля_проверки_промилле", c.TrialPermille,
		"целей", len(e.targets))
	e.replan("перечитана конфигурация")
	return nil
}

// changeVantage переводит контур в другую точку наблюдения.
//
// Память о целях сбрасывается, а оценки — нет. Оценки ключуются точкой
// наблюдения (6.1), поэтому прежние просто перестают находиться, но остаются
// на случай возвращения в ту же сеть. Память о целях, наоборот, относится к
// применённому здесь и сейчас, и переносить её в другую сеть нельзя: там
// ничего не применено.
func (e *Engine) changeVantage(v core.VantageID) {
	if v == e.vantage {
		return
	}
	e.log.Warn("точка наблюдения сменилась: оценки другой сети неприменимы",
		"было", e.vantage.String(), "стало", v.String())
	e.vantage = v
	e.states = make(map[string]TargetState)
	e.replan("смена точки наблюдения")
}

// appendUnique добавляет идентификатор в список, если его там ещё нет.
func appendUnique(list []core.StrategyID, id core.StrategyID) []core.StrategyID {
	if id == "" || containsID(list, id) {
		return list
	}
	return append(list, id)
}

// clonePortfolio копирует портфель: владелец не должен зависеть от того, что
// вызывающий сделает со своей картой после создания контура.
func clonePortfolio(p Portfolio) Portfolio {
	out := make(Portfolio, len(p))
	for id, h := range p {
		out[id] = h
	}
	return out
}
