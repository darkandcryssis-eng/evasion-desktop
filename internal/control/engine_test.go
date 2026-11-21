package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/policy"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/scoring"
	"github.com/fitting-1c/evasion/internal/store"
)

// fixedClock — время, которым управляет тест. Нужен потому, что выдержка и
// свежесть измеряются временем, а ожидать его по-настоящему в тестах нельзя.
type fixedClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *fixedClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *fixedClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

type engineFixture struct {
	engine *Engine
	table  *policy.Table
	clock  *fixedClock
	cancel context.CancelFunc
	done   chan struct{}
}

// startEngine поднимает контур в своей горутине и гасит его по завершении
// теста. Период пересчёта нулевой: пересчёт вызывается командами, иначе тест
// зависел бы от хода настоящего времени.
func startEngine(t *testing.T, o Options) *engineFixture {
	t.Helper()
	clock := &fixedClock{at: base}
	table := policy.NewTable()

	if o.Vantage == "" {
		o.Vantage = vantage
	}
	if o.Table == nil {
		o.Table = table
	}
	if o.Control == (Config{}) {
		o.Control = DefaultConfig()
	}
	if o.Scoring == (scoring.Config{}) {
		o.Scoring = scoring.DefaultConfig()
	}
	o.Now = clock.now

	e, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = e.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	return &engineFixture{engine: e, table: o.Table, clock: clock, cancel: cancel, done: done}
}

func ctxt(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// baselineObservations — сколько базовых наблюдений кладёт observeBlocked.
// Названо числом с именем, потому что на него ссылаются проверки учёта приёма.
const baselineObservations = 10

// observeBlocked кормит контур базовой линией «цель без стратегии не
// отвечает».
//
// Нужно всем тестам, где стратегия должна быть применена: без базовой линии
// контур не повышает ничего, потому что успех стратегии нельзя отличить от
// доступности самой цели. Это предусловие движка, а не формальность теста —
// на заблокированной цели движок именно такую базовую линию и намеряет.
func observeBlocked(e *Engine, target string, at time.Time) {
	for range baselineObservations {
		e.Observe(Observation{
			Baseline: true, Target: target,
			Outcome: core.OutcomeFail, Source: store.SourceProbe, At: at,
		})
	}
}

// TestEnginePublishesSnapshotAtStart: до первого снимка таблица пуста и трафик
// идёт мимо. Ждать первого тика значило бы держать движок бездействующим весь
// период, поэтому снимок считается на старте.
func TestEnginePublishesSnapshotAtStart(t *testing.T) {
	f := startEngine(t, Options{Targets: []string{"youtube.com"}})

	st, err := f.engine.Status(ctxt(t))
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.SnapshotRev == 0 {
		t.Fatal("снимок должен быть опубликован на старте")
	}
	if f.table.Current() == nil {
		t.Fatal("горячая таблица должна получить снимок")
	}
	// Радиус есть, применять нечего — это обвал (5.8), и он обязан быть виден.
	if !st.Blackout {
		t.Fatal("без доказанных стратегий состояние обязано быть обвалом")
	}
	if st.TrialPermille != DefaultConfig().BlackoutTrialPermille {
		t.Fatalf("доля проверки = %d, ожидалась повышенная %d",
			st.TrialPermille, DefaultConfig().BlackoutTrialPermille)
	}
}

// TestEngineAppliesProvenStrategy — полный проход контура: наблюдения приходят
// каналом, кандидат поднимается по ступеням, снимок публикуется, и выбор
// доходит до соединения.
func TestEngineAppliesProvenStrategy(t *testing.T) {
	s := splitStrategy(5)
	id := mustID(t, s)

	f := startEngine(t, Options{
		Targets:   []string{"youtube.com"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusTesting}},
	})
	ctx := ctxt(t)

	// Базовая линия: без стратегии цель не отвечает. Только на этом фоне успех
	// стратегии принадлежит ей, а не цели.
	observeBlocked(f.engine, "youtube.com", base)

	// 25 успехов от пробы: объём больше нижней границы, граница Уилсона выше
	// порога (5.5).
	for range 25 {
		if !f.engine.Observe(Observation{
			StrategyID: id, Target: "youtube.com",
			Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base,
		}) {
			t.Fatal("наблюдение не принято")
		}
	}
	if err := f.engine.Replan(ctx); err != nil {
		t.Fatalf("Replan: %v", err)
	}

	st, err := f.engine.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st.Targets) != 1 || st.Targets[0].Active != id {
		t.Fatalf("состояние целей = %+v, ожидалась применённая %q", st.Targets, id)
	}
	if st.Blackout {
		t.Fatal("действующая стратегия есть — обвала нет")
	}
	if want := 25 + baselineObservations; st.Intake.Accepted != int64(want) || st.Intake.Dropped != 0 {
		t.Fatalf("учёт приёма = %+v, ожидалось %d принятых без потерь", st.Intake, want)
	}
	if st.Portfolio[0].Status != core.StatusActive {
		t.Fatalf("ступень стратегии = %v, ожидалась active", st.Portfolio[0].Status)
	}

	// И главное: выбор доходит до соединения.
	sel := f.table.Select(proxy.ConnMeta{Host: "www.youtube.com", SNI: "www.youtube.com", IsClientHello: true})
	if sel.Strategy != s || sel.ID != id {
		t.Fatal("горячая таблица должна отдавать применённую стратегию")
	}
}

// TestEngineDropsObservationsWhenQueueFull: приём отбрасывает, а не ждёт —
// замедление контура не должно замедлять пользовательский трафик. Потери
// считаются, поэтому тихой деградации не выходит.
func TestEngineDropsObservationsWhenQueueFull(t *testing.T) {
	// Контур не запускаем: очередь никто не вычерпывает.
	table := policy.NewTable()
	e, err := New(Options{
		Vantage: vantage, Table: table, Queue: 4,
		Control: DefaultConfig(), Scoring: scoring.DefaultConfig(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var accepted, dropped int
	for range 100 {
		if e.Observe(Observation{
			StrategyID: idA, Target: target,
			Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base,
		}) {
			accepted++
		} else {
			dropped++
		}
	}

	if accepted != 4 {
		t.Fatalf("принято %d, ожидалась ёмкость очереди 4", accepted)
	}
	if dropped != 96 {
		t.Fatalf("отброшено %d, ожидалось 96", dropped)
	}
	if e.dropped.Load() != 96 {
		t.Fatalf("счётчик потерь = %d, ожидалось 96", e.dropped.Load())
	}
}

// TestEngineRejectsInvalidObservation — наблюдение без стратегии, цели или
// времени учесть нельзя: оно приписалось бы не той четвёрке (6.1).
func TestEngineRejectsInvalidObservation(t *testing.T) {
	f := startEngine(t, Options{Targets: []string{"youtube.com"}})

	for _, o := range []Observation{
		{Target: target, Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base},
		{StrategyID: idA, Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base},
		{StrategyID: idA, Target: target, Outcome: core.OutcomeOK, Source: store.SourceProbe},
	} {
		if f.engine.Observe(o) {
			t.Fatalf("непригодное наблюдение принято: %+v", o)
		}
	}

	st, err := f.engine.Status(ctxt(t))
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Intake.Invalid != 3 {
		t.Fatalf("непригодных = %d, ожидалось 3", st.Intake.Invalid)
	}
}

// TestEnginePinAndUnpin: закрепление применяется немедленно и обходит пороги —
// это главный способ работать, пока у движка нет своих доказательств.
func TestEnginePinAndUnpin(t *testing.T) {
	s := splitStrategy(11)
	id := mustID(t, s)
	f := startEngine(t, Options{
		Targets:   []string{"youtube.com"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusCandidate}},
	})
	ctx := ctxt(t)

	// Ни одного наблюдения нет, и всё равно применяется.
	if err := f.engine.Pin(ctx, "youtube.com", id); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	sel := f.table.Select(proxy.ConnMeta{Host: "youtube.com", IsClientHello: true})
	if sel.Strategy != s {
		t.Fatal("закреплённая стратегия должна применяться без доказательств")
	}

	st, _ := f.engine.Status(ctx)
	if st.Targets[0].Pinned != id || st.Targets[0].Reason != ReasonPinned {
		t.Fatalf("состояние цели = %+v, ожидалось закрепление", st.Targets[0])
	}

	if err := f.engine.Unpin(ctx, "youtube.com"); err != nil {
		t.Fatalf("Unpin: %v", err)
	}
	st, _ = f.engine.Status(ctx)
	if st.Targets[0].Pinned != "" {
		t.Fatal("после снятия закрепления цель должна вернуться автопилоту")
	}

	// Закрепить стратегию, которой нет в портфеле, нельзя: применять было бы
	// нечего, а ошибка должна быть явной, а не тихим бездействием.
	if err := f.engine.Pin(ctx, "youtube.com", core.StrategyID("нет-такой")); err == nil {
		t.Fatal("закрепление неизвестной стратегии должно быть ошибкой")
	}
	if err := f.engine.Unpin(ctx, "discord.com"); err == nil {
		t.Fatal("снятие закрепления с незакреплённой цели должно быть ошибкой")
	}
}

// TestEngineCollateralRollsBackImmediately — 5.1: мгновенный откат по
// побочному вреду. Пересчёт происходит по самой команде, а не на следующем
// тике: вред означает, что ломается то, что обязано работать.
func TestEngineCollateralRollsBackImmediately(t *testing.T) {
	s := splitStrategy(5)
	id := mustID(t, s)
	f := startEngine(t, Options{
		Targets:   []string{"youtube.com"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusTesting}},
	})
	ctx := ctxt(t)

	observeBlocked(f.engine, "youtube.com", base)
	for range 25 {
		f.engine.Observe(Observation{
			StrategyID: id, Target: "youtube.com",
			Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base,
		})
	}
	if err := f.engine.Replan(ctx); err != nil {
		t.Fatalf("Replan: %v", err)
	}
	if f.table.Select(proxy.ConnMeta{Host: "youtube.com"}).Strategy != s {
		t.Fatal("обстановка теста негодна: стратегия должна применяться")
	}

	if err := f.engine.SetCollateral(ctx, id, true); err != nil {
		t.Fatalf("SetCollateral: %v", err)
	}
	if sel := f.table.Select(proxy.ConnMeta{Host: "youtube.com"}); sel.Strategy != nil {
		t.Fatal("вредящая стратегия обязана быть снята немедленно")
	}

	// Снятая стратегия ушла в degraded: с полки берут замену, и предлагать
	// оттуда вредившую нельзя.
	st, _ := f.engine.Status(ctx)
	if st.Portfolio[0].Status != core.StatusDegraded {
		t.Fatalf("ступень снятой стратегии = %v, ожидалась degraded", st.Portfolio[0].Status)
	}

	// Разрешение владельца снимает запрет (4.5), но не отменяет лестницу:
	// стратегия возвращается через долю проверки, а не прыжком на весь
	// трафик. Для «применяй немедленно» есть закрепление.
	if err := f.engine.AllowCollateral(ctx, id, true); err != nil {
		t.Fatalf("AllowCollateral: %v", err)
	}
	st, _ = f.engine.Status(ctx)
	if st.Targets[0].Active != "" {
		t.Fatal("разрешение вреда не должно само возвращать стратегию на весь трафик")
	}
	// И на долю она сразу не возвращается: снятие попало в историю цели, а
	// история поднимает требуемый объём наблюдений до верхней границы (5.5).
	// Прежних 25 наблюдений теперь недостаточно — нужно 60.
	if st.Targets[0].Trial != "" {
		t.Fatalf("вернувшейся стратегии нужны новые доказательства, получена %q", st.Targets[0].Trial)
	}
	if st.Targets[0].TrialReason != ReasonTrialNotPromotable {
		t.Fatalf("причина = %q, ожидалась %q", st.Targets[0].TrialReason, ReasonTrialNotPromotable)
	}
	if len(st.Targets[0].Degraded) != 1 || st.Targets[0].Degraded[0] != id {
		t.Fatalf("история цели = %v, ожидалась запись о снятии %q", st.Targets[0].Degraded, id)
	}

	// А закрепление возвращает её немедленно: это осознанная команда человека,
	// и она же служит тем «явным разрешением» из 4.5.
	if err := f.engine.Pin(ctx, "youtube.com", id); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if sel := f.table.Select(proxy.ConnMeta{Host: "youtube.com"}); sel.Strategy != s {
		t.Fatal("закреплённая стратегия должна применяться немедленно")
	}
}

// TestEngineReloadAppliesWithoutRestart — 10.5: параметры автопилота
// применяются на ходу.
func TestEngineReloadAppliesWithoutRestart(t *testing.T) {
	f := startEngine(t, Options{Targets: []string{"youtube.com"}})
	ctx := ctxt(t)

	newControl := DefaultConfig()
	newControl.MinDwell = time.Hour
	newScoring := scoring.DefaultConfig()
	newScoring.HalfLife = 2 * time.Hour

	if err := f.engine.Reload(ctx, newControl, newScoring, []string{"discord.com"}); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	st, err := f.engine.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st.Targets) != 1 || st.Targets[0].Target != "discord.com" {
		t.Fatalf("радиус = %+v, ожидался discord.com", st.Targets)
	}

	// Негодная конфигурация отвергается целиком: контур не должен остаться с
	// половиной применённых настроек.
	bad := DefaultConfig()
	bad.MinDwell = 0
	if err := f.engine.Reload(ctx, bad, newScoring, nil); err == nil {
		t.Fatal("негодная конфигурация должна быть отвергнута")
	}
	st, _ = f.engine.Status(ctx)
	if len(st.Targets) != 1 || st.Targets[0].Target != "discord.com" {
		t.Fatal("отвергнутая конфигурация не должна менять состояние")
	}
}

// TestEngineVantageChangeResetsTargets — 6.2: при смене сети оценки прежней
// точки неприменимы, и память о применённом в другой сети тоже.
func TestEngineVantageChangeResetsTargets(t *testing.T) {
	s := splitStrategy(5)
	id := mustID(t, s)
	f := startEngine(t, Options{
		Targets:   []string{"youtube.com"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusTesting}},
	})
	ctx := ctxt(t)

	observeBlocked(f.engine, "youtube.com", base)
	for range 25 {
		f.engine.Observe(Observation{
			StrategyID: id, Target: "youtube.com",
			Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base,
		})
	}
	if err := f.engine.Replan(ctx); err != nil {
		t.Fatalf("Replan: %v", err)
	}
	if st, _ := f.engine.Status(ctx); st.Targets[0].Active != id {
		t.Fatal("обстановка теста негодна: стратегия должна быть применена")
	}

	if err := f.engine.SetVantage(ctx, core.VantageID("другая-сеть")); err != nil {
		t.Fatalf("SetVantage: %v", err)
	}
	st, _ := f.engine.Status(ctx)
	if st.Vantage != "другая-сеть" {
		t.Fatalf("точка наблюдения = %q", st.Vantage)
	}
	if st.Targets[0].Active != "" {
		t.Fatal("в новой сети ничего не применено: память о целях обязана обнулиться")
	}
	// Оценки при этом не выброшены: они ключуются точкой наблюдения и ждут
	// возвращения в ту же сеть.
	if st.Intake.Estimates == 0 {
		t.Fatal("оценки прежней сети не должны удаляться при переезде")
	}
	if err := f.engine.SetVantage(ctx, core.VantageID("")); err == nil {
		t.Fatal("пустая точка наблюдения должна быть отвергнута")
	}
}

func TestNewEngineValidatesOptions(t *testing.T) {
	table := policy.NewTable()
	good := Options{Vantage: vantage, Table: table, Control: DefaultConfig(), Scoring: scoring.DefaultConfig()}

	if _, err := New(Options{Table: table, Control: good.Control, Scoring: good.Scoring}); err == nil {
		t.Fatal("контур без точки наблюдения должен быть отвергнут")
	}
	if _, err := New(Options{Vantage: vantage, Control: good.Control, Scoring: good.Scoring}); err == nil {
		t.Fatal("контур без горячей таблицы ни на что не влияет и должен быть отвергнут")
	}
	bad := good
	bad.Interval = -time.Second
	if _, err := New(bad); err == nil {
		t.Fatal("отрицательный период пересчёта должен быть отвергнут")
	}
	if _, err := New(good); err != nil {
		t.Fatalf("годные параметры отвергнуты: %v", err)
	}
}

// TestEngineCommandsFailAfterStop: остановленный контур не должен превращать
// команду в вечное ожидание — иначе остановка движка выглядела бы как
// зависание CLI.
func TestEngineCommandsFailAfterStop(t *testing.T) {
	clock := &fixedClock{at: base}
	e, err := New(Options{
		Vantage: vantage, Table: policy.NewTable(),
		Control: DefaultConfig(), Scoring: scoring.DefaultConfig(), Now: clock.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = e.Run(ctx)
	}()
	cancel()
	<-done

	callCtx, callCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer callCancel()
	if _, err := e.Status(callCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ошибка = %v, ожидалось истечение срока ожидания", err)
	}
}

// TestEngineConcurrentObserveDuringReplan — проверка под -race того, ради чего
// контур сделан единственной горутиной-владельцем: наблюдения приходят из
// многих горутин, пока владелец считает снимок и публикует его.
func TestEngineConcurrentObserveDuringReplan(t *testing.T) {
	s := splitStrategy(5)
	id := mustID(t, s)
	f := startEngine(t, Options{
		Targets:   []string{"youtube.com", "discord.com"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusTesting}},
	})
	ctx := ctxt(t)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Писатели наблюдений.
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				f.engine.Observe(Observation{
					StrategyID: id, Target: "youtube.com",
					Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base,
				})
			}
		}()
	}
	// Читатели горячей таблицы — то есть горутины соединений.
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = f.table.Select(proxy.ConnMeta{Host: "www.youtube.com", IsClientHello: true})
			}
		}()
	}

	for range 50 {
		if err := f.engine.Replan(ctx); err != nil {
			t.Fatalf("Replan: %v", err)
		}
	}
	close(stop)
	wg.Wait()

	st, err := f.engine.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	// Защита от беззвучного успеха: если наблюдений не было, проверять было
	// нечего.
	if st.Intake.Accepted == 0 {
		t.Fatal("ни одного наблюдения не принято: тест ничего не проверил")
	}
	if st.SnapshotRev < 50 {
		t.Fatalf("номер снимка = %d, ожидался не меньше числа пересчётов", st.SnapshotRev)
	}
}

// TestEngineWritesStatusFile закрепляет поверхность команд status и portfolio:
// состояние обязано попадать в файл, причём читаемым строгим разбором.
//
// Тест появился после настоящего промаха: поле StatusPath не присваивалось при
// создании контура, и файл просто не писался. Ни одна проверка этого не
// замечала — движок работал, а команда status говорила «движок не запущен».
// Молчаливая потеря наблюдаемости хуже поломки: она выглядит как чужая
// неисправность.
func TestEngineWritesStatusFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")

	f := startEngine(t, Options{
		Targets:    []string{"youtube.com"},
		StatusPath: path,
	})
	ctx := ctxt(t)

	if err := f.engine.Replan(ctx); err != nil {
		t.Fatalf("Replan: %v", err)
	}

	st, err := ReadStatusFile(path)
	if err != nil {
		t.Fatalf("ReadStatusFile: %v", err)
	}
	if st.Vantage != vantage {
		t.Fatalf("точка наблюдения в файле = %q, ожидалась %q", st.Vantage, vantage)
	}
	if st.SnapshotRev == 0 {
		t.Fatal("номер снимка в файле нулевой: значит состояние не записано, а придумано")
	}
	if len(st.Targets) != 1 || st.Targets[0].Target != "youtube.com" {
		t.Fatalf("цели в файле = %+v", st.Targets)
	}

	// Содержимое обязано быть годным JSON целиком: запись атомарна, поэтому
	// половины документа читатель увидеть не может.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение файла: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("файл состояния не разбирается как JSON: %v", err)
	}
	// Поля — машинно-читаемые, без готовых формулировок (2.2).
	for _, key := range []string{"vantage", "snapshot_rev", "blackout", "trial_permille", "targets", "portfolio", "intake"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("в состоянии нет поля %q: контракт --json нарушен", key)
		}
	}
}

// TestEngineWithoutStatusPathWorks: движок, запущенный без каталога состояния,
// обязан работать — наблюдаемость не условие работы.
func TestEngineWithoutStatusPathWorks(t *testing.T) {
	f := startEngine(t, Options{Targets: []string{"youtube.com"}})
	if err := f.engine.Replan(ctxt(t)); err != nil {
		t.Fatalf("Replan: %v", err)
	}
}

// TestStatusFileReplacedAtomically: повторная запись заменяет файл целиком, а
// не дописывает его.
func TestStatusFileReplacedAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")

	if err := WriteStatusFile(path, Status{Vantage: vantage, SnapshotRev: 1}); err != nil {
		t.Fatalf("WriteStatusFile: %v", err)
	}
	if err := WriteStatusFile(path, Status{Vantage: vantage, SnapshotRev: 2}); err != nil {
		t.Fatalf("WriteStatusFile: %v", err)
	}

	st, err := ReadStatusFile(path)
	if err != nil {
		t.Fatalf("ReadStatusFile: %v", err)
	}
	if st.SnapshotRev != 2 {
		t.Fatalf("номер снимка = %d, ожидался 2", st.SnapshotRev)
	}

	// Временных файлов после себя запись не оставляет: иначе каталог
	// состояния зарастал бы мусором на каждом пересчёте.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("чтение каталога: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("в каталоге состояния %v, ожидался только status.json", names)
	}
}

// TestEngineHoldsDwellAcrossReplans — выдержка через весь контур: применённая
// стратегия держится, пока не истечёт MinDwell, даже если претендент лучше и
// пересчёт случается многократно.
//
// Проверяется именно контур, а не решатель: здесь участвуют память о целях
// (когда применили) и источник времени, то есть то, чего у чистого решателя
// нет. Время двигает тест, а не часы: ждать четверть часа было бы нельзя.
func TestEngineHoldsDwellAcrossReplans(t *testing.T) {
	weak := splitStrategy(5)
	weakID := mustID(t, weak)
	strong := splitStrategy(77)
	strongID := mustID(t, strong)

	f := startEngine(t, Options{
		Targets: []string{"youtube.com"},
		Portfolio: Portfolio{
			weakID:   {Strategy: weak, Status: core.StatusTesting},
			strongID: {Strategy: strong, Status: core.StatusBenched},
		},
	})
	ctx := ctxt(t)

	observe := func(id core.StrategyID, n int) {
		for range n {
			f.engine.Observe(Observation{
				StrategyID: id, Target: "youtube.com",
				Outcome: core.OutcomeOK, Source: store.SourceProbe, At: f.clock.now(),
			})
		}
	}

	// Слабая стратегия доказана и применяется. Базовая линия цели — провалы:
	// без неё повышать нечего, потому что успех был бы неотличим от
	// доступности цели.
	observeBlocked(f.engine, "youtube.com", f.clock.now())
	observe(weakID, 25)
	if err := f.engine.Replan(ctx); err != nil {
		t.Fatalf("Replan: %v", err)
	}
	if st, _ := f.engine.Status(ctx); st.Targets[0].Active != weakID {
		t.Fatalf("действует %q, ожидалась %q", st.Targets[0].Active, weakID)
	}

	// Появляется заметно лучшая, но выдержка не истекла.
	observe(strongID, 40)
	f.clock.advance(DefaultConfig().MinDwell / 2)
	if err := f.engine.Replan(ctx); err != nil {
		t.Fatalf("Replan: %v", err)
	}
	st, _ := f.engine.Status(ctx)
	if st.Targets[0].Active != weakID {
		t.Fatalf("до истечения выдержки стратегия не должна меняться, действует %q", st.Targets[0].Active)
	}
	if st.Targets[0].Reason != ReasonDwell {
		t.Fatalf("причина = %q, ожидалась %q", st.Targets[0].Reason, ReasonDwell)
	}

	// Выдержка истекла — смена происходит.
	f.clock.advance(DefaultConfig().MinDwell)
	if err := f.engine.Replan(ctx); err != nil {
		t.Fatalf("Replan: %v", err)
	}
	st, _ = f.engine.Status(ctx)
	if st.Targets[0].Active != strongID {
		t.Fatalf("после выдержки должна действовать %q, действует %q", strongID, st.Targets[0].Active)
	}
	if st.Targets[0].Switches != 2 {
		t.Fatalf("смен = %d, ожидалось 2", st.Targets[0].Switches)
	}
	// Вытесненная стратегия уходит на полку, а не в degraded: она не
	// срывалась, просто уступила лучшей (5.1).
	for _, h := range st.Portfolio {
		if h.StrategyID == weakID && h.Status != core.StatusBenched {
			t.Fatalf("ступень вытесненной стратегии = %v, ожидалась benched", h.Status)
		}
	}
}

// TestEngineInitialPinsAppliedInFirstSnapshot закрепляет то, что показал живой
// прогон: закрепления из конфига обязаны попасть в ПЕРВЫЙ снимок.
//
// Пока они подавались командами после запуска, старт выглядел так: снимок №1
// без стратегий, громкая тревога об обвале портфеля (5.8) — которого не было, —
// и затем по пересчёту на каждую цель, то есть восемь снимков и восемь записей
// файла состояния на семи целях. Ложная тревога при каждом запуске обесценивает
// тревогу настоящую, а это единственный признак, по которому видно, что движок
// ничего не применяет.
func TestEngineInitialPinsAppliedInFirstSnapshot(t *testing.T) {
	s := splitStrategy(5)
	id := mustID(t, s)
	targets := []string{"youtube.com", "discord.com", "ytimg.com"}

	pins := make(map[string]core.StrategyID, len(targets))
	for _, target := range targets {
		pins[target] = id
	}

	f := startEngine(t, Options{
		Targets:   targets,
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusActive}},
		Pins:      pins,
	})

	st, err := f.engine.Status(ctxt(t))
	if err != nil {
		t.Fatalf("Status: %v", err)
	}

	// Снимок ровно один: первый же содержит всё, что нужно.
	if st.SnapshotRev != 1 {
		t.Fatalf("номер снимка = %d, ожидался 1: закрепления не должны вызывать пересчёт", st.SnapshotRev)
	}
	// Тревоги быть не должно: стратегия применена ко всем целям.
	if st.Blackout {
		t.Fatal("ложная тревога об обвале: закреплённая стратегия применена с первого снимка")
	}
	if st.TrialPermille != DefaultConfig().TrialPermille {
		t.Fatalf("доля проверки = %d, ожидалась обычная %d (повышенная — признак обвала)",
			st.TrialPermille, DefaultConfig().TrialPermille)
	}
	for _, ts := range st.Targets {
		if ts.Active != id {
			t.Fatalf("цель %s: действует %q, ожидалась %q", ts.Target, ts.Active, id)
		}
		if ts.Pinned != id {
			t.Fatalf("цель %s: закрепление %q, ожидалось %q", ts.Target, ts.Pinned, id)
		}
	}

	// И трафик получает её сразу, без ожидания команд.
	if sel := f.table.Select(proxy.ConnMeta{Host: "www.youtube.com", IsClientHello: true}); sel.Strategy != s {
		t.Fatal("стратегия должна применяться с первого снимка")
	}
}

// TestNewEngineRejectsPinToUnknownStrategy: закрепление на стратегию, которой
// нет в портфеле, применять нечем. Сообщить об этом надо до запуска, а не
// записью в журнал на первом снимке.
func TestNewEngineRejectsPinToUnknownStrategy(t *testing.T) {
	_, err := New(Options{
		Vantage: vantage,
		Table:   policy.NewTable(),
		Control: DefaultConfig(),
		Scoring: scoring.DefaultConfig(),
		Targets: []string{"youtube.com"},
		Pins:    map[string]core.StrategyID{"youtube.com": idA},
	})
	if err == nil {
		t.Fatal("закрепление на стратегию вне портфеля должно быть отвергнуто")
	}

	_, err = New(Options{
		Vantage:   vantage,
		Table:     policy.NewTable(),
		Control:   DefaultConfig(),
		Scoring:   scoring.DefaultConfig(),
		Portfolio: Portfolio{idA: {Status: core.StatusActive}},
		Pins:      map[string]core.StrategyID{"": idA},
	})
	if err == nil {
		t.Fatal("закрепление без цели должно быть отвергнуто")
	}
}

// TestEngineReadyWaitsForFirstSnapshot закрепляет гарантию запуска: после
// Ready снимок в горячей таблице уже есть.
//
// Без этой гарантии вопрос «применилась ли стратегия к первому соединению»
// решался бы гонкой между стартом прокси и стартом контура. Исход такой гонки
// безопасен (прозрачный пропуск), но непредсказуем, а непредсказуемость в том,
// применяется ли стратегия, портит измерения: часть соединений попадала бы в
// наблюдения как «без стратегии» по случайной причине.
func TestEngineReadyWaitsForFirstSnapshot(t *testing.T) {
	s := splitStrategy(5)
	id := mustID(t, s)
	table := policy.NewTable()
	clock := &fixedClock{at: base}

	e, err := New(Options{
		Vantage:   vantage,
		Table:     table,
		Control:   DefaultConfig(),
		Scoring:   scoring.DefaultConfig(),
		Targets:   []string{"youtube.com"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusActive}},
		Pins:      map[string]core.StrategyID{"youtube.com": id},
		Now:       clock.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// До запуска снимка нет, и таблица пропускает трафик без изменений.
	if table.Current() != nil {
		t.Fatal("до запуска контура снимка быть не должно")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = e.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	if err := e.Ready(ctxt(t)); err != nil {
		t.Fatalf("Ready: %v", err)
	}

	// После Ready снимок обязан быть живым, а стратегия — применяться.
	if table.Current() == nil {
		t.Fatal("после Ready снимок обязан быть опубликован")
	}
	if sel := table.Select(proxy.ConnMeta{Host: "www.youtube.com", IsClientHello: true}); sel.Strategy != s {
		t.Fatal("после Ready первое же соединение должно получать стратегию")
	}
}

// TestEngineReadyRespectsContext: контур могли остановить раньше, чем он успел
// посчитать первый снимок. Ожидание в этом случае обязано кончиться ошибкой, а
// не зависанием запуска.
func TestEngineReadyRespectsContext(t *testing.T) {
	e, err := New(Options{
		Vantage: vantage,
		Table:   policy.NewTable(),
		Control: DefaultConfig(),
		Scoring: scoring.DefaultConfig(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Run не запускаем: снимка не будет никогда.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := e.Ready(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ошибка = %v, ожидалось истечение срока ожидания", err)
	}
}

// TestStatusShowsCandidateProgress — status показывает оценку кандидата по цели
// (успехи, объём, близость к порогу 5.5). Без этого застрявший в candidate
// портфель неотличим от работающего, но ещё не добравшего наблюдений — ровно
// это затруднило первый живой прогон песочницы (капстоун M7).
func TestStatusShowsCandidateProgress(t *testing.T) {
	cand := splitStrategy(5)
	candID := mustID(t, cand)
	f := startEngine(t, Options{
		Targets:   []string{"youtube.com"},
		Portfolio: Portfolio{candID: {Strategy: cand, Status: core.StatusCandidate}},
	})
	ctx := ctxt(t)

	// Базовая линия — провалы (цель заблокирована), кандидат — двенадцать
	// успехов: меньше порога в двадцать наблюдений (5.5).
	observeBlocked(f.engine, "youtube.com", f.clock.now())
	for range 12 {
		f.engine.Observe(Observation{
			StrategyID: candID, Target: "youtube.com",
			Outcome: core.OutcomeOK, Source: store.SourceProbe, At: f.clock.now(),
		})
	}
	if err := f.engine.Replan(ctx); err != nil {
		t.Fatalf("Replan: %v", err)
	}

	st, _ := f.engine.Status(ctx)
	if len(st.Targets) != 1 {
		t.Fatalf("целей %d, ожидалась 1", len(st.Targets))
	}
	cands := st.Targets[0].Candidates
	if len(cands) != 1 {
		t.Fatalf("кандидатов в статусе %d, ожидался 1", len(cands))
	}
	c := cands[0]
	if c.StrategyID != candID {
		t.Fatalf("идентификатор кандидата %q, ожидался %q", c.StrategyID, candID)
	}
	if c.Successes != 12 || c.Conclusive != 12 {
		t.Fatalf("успехи/определённые = %d/%d, ожидалось 12/12", c.Successes, c.Conclusive)
	}
	if c.Have != 12 {
		t.Fatalf("набрано %d, ожидалось 12", c.Have)
	}
	if c.Required < 20 {
		t.Fatalf("требуемый объём %d, ожидался не меньше 20 (5.5)", c.Required)
	}
	// 12 из 20 — «ещё рано», а не «не работает»: кандидат не готов, но успешен.
	if c.Ready {
		t.Fatal("при 12 наблюдениях из 20 кандидат не должен быть готов")
	}
	if c.LowerPermille == 0 {
		t.Fatal("нижняя граница доли успехов не должна быть нулевой при 12/12")
	}
}

// TestEngineWarmStartAppliesProvenStrategy — тёплый старт: доказательства,
// добытые в прошлом запуске, применяют стратегию уже на ПЕРВОМ снимке, без
// единого живого наблюдения в этом запуске.
//
// Это и есть разница с TestEngineAppliesProvenStrategy: там те же
// доказательства приходят каналом в текущем запуске, здесь — восстановлены из
// журнала при создании контура. Моделирует перезапуск --auto, при котором
// раньше весь прогресс обнулялся.
func TestEngineWarmStartAppliesProvenStrategy(t *testing.T) {
	s := splitStrategy(5)
	id := mustID(t, s)

	// Те же наблюдения, что доказали стратегию в прошлом запуске: базовая линия
	// «цель заблокирована» плюс 25 успехов. Подаём их прогревом, а не каналом.
	warm := make([]Observation, 0, baselineObservations+25)
	for range baselineObservations {
		warm = append(warm, Observation{
			Baseline: true, Target: "youtube.com",
			Outcome: core.OutcomeFail, Source: store.SourceProbe, At: base,
		})
	}
	for range 25 {
		warm = append(warm, Observation{
			StrategyID: id, Target: "youtube.com",
			Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base,
		})
	}

	f := startEngine(t, Options{
		Targets:   []string{"youtube.com"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusTesting}},
		Warmup:    warm,
	})
	ctx := ctxt(t)

	// Никакого Observe и Replan: проверяем состояние ровно после старта.
	st, err := f.engine.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st.Targets) != 1 || st.Targets[0].Active != id {
		t.Fatalf("состояние целей = %+v, ожидалась применённая %q по прогреву", st.Targets, id)
	}
	if st.Blackout {
		t.Fatal("прогрев восстановил рабочую стратегию — обвала быть не должно")
	}
	// Прогрев не идёт через канал приёма: это восстановление, а не живой трафик.
	// Приём обязан показывать ноль, иначе владелец счёл бы прогрев за новые
	// пробы.
	if st.Intake.Accepted != 0 {
		t.Fatalf("учёт приёма = %+v, прогрев не должен считаться принятым трафиком", st.Intake)
	}

	// Главное: выбор доходит до соединения сразу после перезапуска.
	sel := f.table.Select(proxy.ConnMeta{Host: "www.youtube.com", SNI: "www.youtube.com", IsClientHello: true})
	if sel.Strategy != s || sel.ID != id {
		t.Fatal("после тёплого старта горячая таблица должна отдавать восстановленную стратегию")
	}
}

// TestEngineWarmStartSkipsInvalid — негодное наблюдение в прогреве
// пропускается, а не роняет запуск: журнал мог быть записан другой версией, и
// терять из-за одной строки весь набор хуже, чем недосчитать её.
func TestEngineWarmStartSkipsInvalid(t *testing.T) {
	s := splitStrategy(5)
	id := mustID(t, s)

	warm := []Observation{
		// Негодное: не базовое, но без стратегии.
		{Target: "youtube.com", Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base},
		// Годное.
		{StrategyID: id, Target: "youtube.com", Outcome: core.OutcomeOK, Source: store.SourceProbe, At: base},
	}

	// Не паникует и не отказывает: контур создаётся и работает.
	f := startEngine(t, Options{
		Targets:   []string{"youtube.com"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusTesting}},
		Warmup:    warm,
	})
	if _, err := f.engine.Status(ctxt(t)); err != nil {
		t.Fatalf("Status: %v", err)
	}
}
