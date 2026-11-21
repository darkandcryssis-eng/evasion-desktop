package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/store"
)

const (
	testVantage = core.VantageID("v1")
	testTarget  = "www.example.com"
)

// openTemp создаёт базу в каталоге теста и закрывает её по завершении.
func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evasion.sqlite")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

// obs собирает годное наблюдение, меняя только нужное тесту.
func obs(at time.Time, mods ...func(*store.Observation)) store.Observation {
	o := store.Observation{
		At:         at,
		StrategyID: core.StrategyID("s1"),
		Target:     testTarget,
		VantageID:  testVantage,
		Phase:      core.PhaseFast,
		Outcome:    core.OutcomeOK,
		Reason:     core.ReasonHandshakeDone,
		Source:     store.SourceProbe,
	}
	for _, m := range mods {
		m(&o)
	}
	return o
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("пустой путь должен отвергаться")
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	// Повторное открытие существующей базы не должно ни падать, ни терять
	// данные: движок перезапускают, и схема создаётся заново при каждом пуске.
	path := filepath.Join(t.TempDir(), "evasion.sqlite")
	first, err := Open(path)
	if err != nil {
		t.Fatalf("первое открытие: %v", err)
	}
	now := time.Now()
	if err := first.AppendObservations(context.Background(), []store.Observation{obs(now)}); err != nil {
		t.Fatalf("запись: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("закрытие: %v", err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatalf("повторное открытие: %v", err)
	}
	defer second.Close()

	got, err := second.Tallies(context.Background(), store.Query{
		VantageID: testVantage, Since: now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("Tallies: %v", err)
	}
	if len(got) != 1 || got[0].Total != 1 {
		t.Fatalf("после повторного открытия данные %+v", got)
	}
}

// TestDataSurvivesRestart — то, ради чего хранилище на диске и существует.
func TestDataSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evasion.sqlite")
	now := time.Now()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	err = s.AppendObservations(context.Background(), []store.Observation{
		obs(now), obs(now, func(o *store.Observation) { o.Outcome = core.OutcomeFail }),
	})
	if err != nil {
		t.Fatalf("запись: %v", err)
	}
	err = s.AppendStrategyEvents(context.Background(), []store.StrategyEvent{
		{At: now, StrategyID: "s1", Kind: store.EventCreated, Note: "порождена"},
	})
	if err != nil {
		t.Fatalf("запись события: %v", err)
	}
	// Закрытие обязано дописать всё: иначе часть принятого осталась бы только
	// в журнале опережающей записи.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("повторное открытие: %v", err)
	}
	defer reopened.Close()

	got, _ := reopened.Tallies(context.Background(), store.Query{
		VantageID: testVantage, Since: now.Add(-time.Hour),
	})
	if len(got) != 1 || got[0].Total != 2 {
		t.Fatalf("наблюдения после перезапуска %+v", got)
	}
	events, _ := reopened.StrategyEvents(context.Background(), "s1", 0)
	if len(events) != 1 || events[0].Note != "порождена" {
		t.Fatalf("события после перезапуска %+v", events)
	}
}

// TestEnumsStoredAsText закрепляет решение схемы.
//
// Числовые значения привязали бы архив к текущему порядку констант в коде:
// перестановка значения молча испортила бы всю прошлую историю. Текст
// самодокументируем и переносится в колоночную СУБД без преобразования.
func TestEnumsStoredAsText(t *testing.T) {
	s, path := openTemp(t)
	now := time.Now()
	err := s.AppendObservations(context.Background(), []store.Observation{
		obs(now, func(o *store.Observation) {
			o.Outcome = core.OutcomeThrottled
			o.Source = store.SourcePassive
			o.Phase = core.PhaseSlow
		}),
	})
	if err != nil {
		t.Fatalf("запись: %v", err)
	}

	// Читаем в обход своего кода, чтобы увидеть, что лежит в базе на самом
	// деле, а не то, что мы думаем, будто там лежит.
	db, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatalf("прямое открытие: %v", err)
	}
	defer db.Close()

	var outcome, source, phase string
	err = db.QueryRow(`SELECT outcome, source, phase FROM observations LIMIT 1`).
		Scan(&outcome, &source, &phase)
	if err != nil {
		t.Fatalf("прямое чтение: %v", err)
	}
	if outcome != "throttled" || source != "passive" || phase != "slow" {
		t.Fatalf("в базе хранятся %q/%q/%q, ожидались текстовые обозначения",
			outcome, source, phase)
	}
}

func TestTalliesGroupAndWeight(t *testing.T) {
	s, _ := openTemp(t)
	now := time.Now()
	err := s.AppendObservations(context.Background(), []store.Observation{
		obs(now.Add(-3 * time.Minute)),
		obs(now.Add(-2 * time.Minute)),
		obs(now.Add(-time.Minute), func(o *store.Observation) {
			o.Source = store.SourcePassive
			o.Outcome = core.OutcomeFail
			o.Reason = core.ReasonTimeout
		}),
	})
	if err != nil {
		t.Fatalf("запись: %v", err)
	}

	got, err := s.Tallies(context.Background(), store.Query{
		VantageID: testVantage, Since: now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("Tallies: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("срезов %d", len(got))
	}
	tl := got[0]
	if tl.Total != 3 {
		t.Fatalf("всего %d", tl.Total)
	}
	if tl.Counts[core.OutcomeOK] != 2 || tl.Counts[core.OutcomeFail] != 1 {
		t.Fatalf("количества %v", tl.Counts)
	}
	// Вес активного наблюдения единица, пассивного 0.3 (5.7), в тысячных.
	if tl.WeightedCounts[core.OutcomeOK] != 2000 {
		t.Fatalf("взвешенные успехи %d", tl.WeightedCounts[core.OutcomeOK])
	}
	if tl.WeightedCounts[core.OutcomeFail] != 300 {
		t.Fatalf("взвешенные провалы %d, ожидалось 300", tl.WeightedCounts[core.OutcomeFail])
	}
	// Миллисекундная точность: время хранится целым числом миллисекунд.
	if got := tl.First.UnixMilli(); got != now.Add(-3*time.Minute).UnixMilli() {
		t.Fatalf("первое наблюдение %d", got)
	}
}

func TestTalliesSeparateByVantage(t *testing.T) {
	// Наблюдения разных точек наблюдения не смешиваются: иначе оценки чужой
	// сети применялись бы как свои (6.1).
	s, _ := openTemp(t)
	now := time.Now()
	_ = s.AppendObservations(context.Background(), []store.Observation{
		obs(now),
		obs(now, func(o *store.Observation) { o.VantageID = "v2" }),
		obs(now, func(o *store.Observation) { o.VantageID = "v2" }),
	})

	first, _ := s.Tallies(context.Background(), store.Query{VantageID: testVantage, Since: now.Add(-time.Hour)})
	if len(first) != 1 || first[0].Total != 1 {
		t.Fatalf("первая точка %+v", first)
	}
	second, _ := s.Tallies(context.Background(), store.Query{VantageID: "v2", Since: now.Add(-time.Hour)})
	if len(second) != 1 || second[0].Total != 2 {
		t.Fatalf("вторая точка %+v", second)
	}
}

func TestTalliesFiltersAndOrder(t *testing.T) {
	s, _ := openTemp(t)
	now := time.Now()
	_ = s.AppendObservations(context.Background(), []store.Observation{
		obs(now),
		obs(now, func(o *store.Observation) { o.Target = "other.example.com" }),
		obs(now, func(o *store.Observation) { o.StrategyID = "s2" }),
		obs(now, func(o *store.Observation) { o.Phase = core.PhaseSlow }),
	})

	all, err := s.Tallies(context.Background(), store.Query{
		VantageID: testVantage, Since: now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("Tallies: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("при отборе быстрого уровня срезов %d: %+v", len(all), all)
	}
	// Порядок задан запросом и обязан быть устойчивым.
	if all[0].Target != "other.example.com" {
		t.Fatalf("порядок неустойчив: %+v", all)
	}

	byTarget, _ := s.Tallies(context.Background(), store.Query{
		VantageID: testVantage, Target: testTarget, Since: now.Add(-time.Hour),
	})
	if len(byTarget) != 2 {
		t.Fatalf("отбор по цели дал %d срезов", len(byTarget))
	}

	byStrategy, _ := s.Tallies(context.Background(), store.Query{
		VantageID: testVantage, StrategyID: "s2", Since: now.Add(-time.Hour),
	})
	if len(byStrategy) != 1 || byStrategy[0].StrategyID != "s2" {
		t.Fatalf("отбор по стратегии дал %+v", byStrategy)
	}

	bothPhases, _ := s.Tallies(context.Background(), store.Query{
		VantageID: testVantage, Since: now.Add(-time.Hour), IncludeAllPhases: true,
	})
	total := int64(0)
	for _, tl := range bothPhases {
		total += tl.Total
	}
	if total != 4 {
		t.Fatalf("без отбора по уровню всего %d наблюдений", total)
	}
}

func TestTalliesTimeWindowInclusive(t *testing.T) {
	// Границы включительны: иначе наблюдение ровно на границе терялось бы при
	// склейке соседних окон.
	s, _ := openTemp(t)
	now := time.Now().Truncate(time.Millisecond)
	_ = s.AppendObservations(context.Background(), []store.Observation{
		obs(now.Add(-time.Hour)),
		obs(now),
		obs(now.Add(time.Hour)),
	})

	got, _ := s.Tallies(context.Background(), store.Query{
		VantageID: testVantage, Since: now.Add(-time.Hour), Until: now,
	})
	if len(got) != 1 || got[0].Total != 2 {
		t.Fatalf("в окно попало %+v, ожидались обе границы", got)
	}
}

func TestValidationRejectsBadRecords(t *testing.T) {
	// Проверка пригодности общая со store: разойдясь, реализации принимали бы
	// разные данные, и расхождение заметили бы только при переносе.
	s, _ := openTemp(t)
	now := time.Now()
	err := s.AppendObservations(context.Background(), []store.Observation{
		obs(now),
		obs(now, func(o *store.Observation) { o.VantageID = "" }),
	})
	if err == nil {
		t.Fatal("пачка с непригодной записью должна отвергаться целиком")
	}
	got, _ := s.Tallies(context.Background(), store.Query{VantageID: testVantage, Since: now.Add(-time.Hour)})
	if len(got) != 0 {
		t.Fatalf("после отвергнутой пачки в базе %+v", got)
	}

	if err := s.AppendStrategyEvents(context.Background(), []store.StrategyEvent{{At: now}}); err == nil {
		t.Fatal("событие без стратегии должно отвергаться")
	}
	if _, err := s.Tallies(context.Background(), store.Query{}); err == nil {
		t.Fatal("запрос без точки наблюдения должен отвергаться")
	}
}

func TestStrategyEventsNewestFirstAndLimit(t *testing.T) {
	s, _ := openTemp(t)
	now := time.Now()
	err := s.AppendStrategyEvents(context.Background(), []store.StrategyEvent{
		{At: now.Add(-2 * time.Hour), StrategyID: "s1", Kind: store.EventCreated},
		{At: now.Add(-time.Hour), StrategyID: "s1", Kind: store.EventStatusChanged,
			From: "candidate", To: "testing", VantageID: testVantage, Target: testTarget},
		{At: now, StrategyID: "s2", Kind: store.EventRetired},
	})
	if err != nil {
		t.Fatalf("запись событий: %v", err)
	}

	got, err := s.StrategyEvents(context.Background(), "s1", 0)
	if err != nil {
		t.Fatalf("StrategyEvents: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("событий %d", len(got))
	}
	if got[0].Kind != store.EventStatusChanged {
		t.Fatalf("первым пришло %v, ожидалось новейшее", got[0].Kind)
	}
	// Поля перехода должны пережить круговой перенос через базу.
	if got[0].From != "candidate" || got[0].To != "testing" {
		t.Fatalf("переход %q -> %q", got[0].From, got[0].To)
	}
	if got[0].VantageID != testVantage || got[0].Target != testTarget {
		t.Fatalf("контекст события утрачен: %+v", got[0])
	}

	limited, _ := s.StrategyEvents(context.Background(), "s1", 1)
	if len(limited) != 1 {
		t.Fatalf("при пределе 1 получено %d", len(limited))
	}
}

func TestPurgeDeletesOnlyFullyExpiredDays(t *testing.T) {
	// Удаление идёт по дню, и срок соблюдается в сторону БОЛЬШЕГО хранения:
	// удалять частично истёкший день значило бы терять наблюдения раньше
	// заявленного срока.
	s, _ := openTemp(t)
	now := time.Now()
	_ = s.AppendObservations(context.Background(), []store.Observation{
		obs(now.Add(-40 * 24 * time.Hour)),
		obs(now.Add(-10 * 24 * time.Hour)),
	})
	_ = s.AppendStrategyEvents(context.Background(), []store.StrategyEvent{
		{At: now.Add(-400 * 24 * time.Hour), StrategyID: "s1", Kind: store.EventCreated},
	})

	stats, err := s.Purge(context.Background(), now, store.RetentionPolicy{
		Observations: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if stats.Observations != 1 {
		t.Fatalf("удалено наблюдений %d, ожидалось одно", stats.Observations)
	}
	// Нулевой срок означает бессрочно: история решений нужна, чтобы разобрать
	// прошлое поведение автопилота (6.4).
	if stats.Events != 0 {
		t.Fatalf("удалено событий %d при бессрочном хранении", stats.Events)
	}
	events, _ := s.StrategyEvents(context.Background(), "s1", 0)
	if len(events) != 1 {
		t.Fatal("события удалены вопреки бессрочному хранению")
	}

	left, _ := s.Tallies(context.Background(), store.Query{
		VantageID: testVantage, Since: now.Add(-100 * 24 * time.Hour),
	})
	if len(left) != 1 || left[0].Total != 1 {
		t.Fatalf("после уборки осталось %+v", left)
	}
}

func TestPurgeEventsWhenPolicySet(t *testing.T) {
	s, _ := openTemp(t)
	now := time.Now()
	_ = s.AppendStrategyEvents(context.Background(), []store.StrategyEvent{
		{At: now.Add(-400 * 24 * time.Hour), StrategyID: "s1", Kind: store.EventCreated},
		{At: now, StrategyID: "s1", Kind: store.EventSelected},
	})

	stats, err := s.Purge(context.Background(), now, store.RetentionPolicy{
		Events: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if stats.Events != 1 {
		t.Fatalf("удалено событий %d, ожидалось одно", stats.Events)
	}
}

func TestUnknownTokenInDatabaseIsError(t *testing.T) {
	// Неизвестное обозначение означает, что база писалась другой версией кода.
	// Молча отнести запись к какому-нибудь исходу нельзя: оценка оказалась бы
	// основана на догадке.
	s, path := openTemp(t)
	now := time.Now()
	_ = s.AppendObservations(context.Background(), []store.Observation{obs(now)})

	db, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatalf("прямое открытие: %v", err)
	}
	_, err = db.Exec(`UPDATE observations SET outcome = 'из-будущего'`)
	_ = db.Close()
	if err != nil {
		t.Fatalf("прямая правка: %v", err)
	}

	_, err = s.Tallies(context.Background(), store.Query{
		VantageID: testVantage, Since: now.Add(-time.Hour),
	})
	if err == nil {
		t.Fatal("нераспознанное обозначение исхода должно давать ошибку")
	}
	if !strings.Contains(err.Error(), "не распознан") {
		t.Fatalf("ошибка %q не объясняет причину", err)
	}
}

func TestNewerSchemaIsRejected(t *testing.T) {
	// База новее кода: мы не знаем, что означают её столбцы, и запись
	// испортила бы данные, которые кто-то другой считает своими.
	path := filepath.Join(t.TempDir(), "evasion.sqlite")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = s.Close()

	db, _ := sql.Open(driverName, path)
	_, err = db.Exec(`INSERT INTO schema_version (version) VALUES (?)`, schemaVersion+1)
	_ = db.Close()
	if err != nil {
		t.Fatalf("правка версии: %v", err)
	}

	if _, err := Open(path); err == nil {
		t.Fatal("база новее кода должна отвергаться")
	}
}

// TestReadsDoNotBlockWrites проверяет смысл разделения соединений.
//
// На одном пуле длинная аналитическая выборка задерживала бы приём, а приём при
// задержке отбрасывает наблюдения (store.Writer). То есть тяжёлый запрос
// приводил бы к потере измерений — ровно к тому, от чего разделение слоёв и
// защищает (6.3).
func TestReadsDoNotBlockWrites(t *testing.T) {
	s, _ := openTemp(t)
	now := time.Now()

	// Набиваем данными, чтобы выборка была не мгновенной.
	batch := make([]store.Observation, 0, 2000)
	for i := range 2000 {
		batch = append(batch, obs(now.Add(-time.Duration(i)*time.Second)))
	}
	if err := s.AppendObservations(context.Background(), batch); err != nil {
		t.Fatalf("наполнение: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	readErr := make(chan error, 1)
	writeErr := make(chan error, 1)

	go func() {
		defer wg.Done()
		for range 20 {
			_, err := s.Tallies(context.Background(), store.Query{
				VantageID: testVantage, Since: now.Add(-24 * time.Hour), IncludeAllPhases: true,
			})
			if err != nil {
				readErr <- err
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range 20 {
			err := s.AppendObservations(context.Background(), []store.Observation{obs(now)})
			if err != nil {
				writeErr <- err
				return
			}
		}
	}()
	wg.Wait()

	select {
	case err := <-readErr:
		t.Fatalf("чтение при одновременной записи: %v", err)
	default:
	}
	select {
	case err := <-writeErr:
		t.Fatalf("запись при одновременном чтении: %v", err)
	default:
	}
}

func TestEmptyBatchesAreNoOps(t *testing.T) {
	s, _ := openTemp(t)
	if err := s.AppendObservations(context.Background(), nil); err != nil {
		t.Fatalf("пустая пачка наблюдений: %v", err)
	}
	if err := s.AppendStrategyEvents(context.Background(), nil); err != nil {
		t.Fatalf("пустая пачка событий: %v", err)
	}
}

func TestDayPartitionUsesUTC(t *testing.T) {
	// Разделы считаются по UTC: иначе при смене пояса или переходе на летнее
	// время границы разделов сдвинулись бы, и удаление по сроку задело бы не
	// те данные.
	utc := time.Date(2026, 3, 15, 23, 30, 0, 0, time.UTC)
	east := utc.In(time.FixedZone("восток", 5*3600))
	if dayOf(utc) != dayOf(east) {
		t.Fatalf("один момент в разных поясах дал разные разделы: %d и %d",
			dayOf(utc), dayOf(east))
	}
}

// TestObservationsReturnedInTimeOrder: сырые наблюдения отдаются по возрастанию
// времени независимо от порядка записи. На этом порядке держится прогрев
// оценок — scoring воспроизводит серию провалов и чередование только по нему.
func TestObservationsReturnedInTimeOrder(t *testing.T) {
	s, _ := openTemp(t)
	base := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

	// Пишем вперемешку по времени: +2с, +0с, +1с.
	batch := []store.Observation{
		obs(base.Add(2*time.Second), func(o *store.Observation) { o.Outcome = core.OutcomeFail }),
		obs(base, func(o *store.Observation) { o.Outcome = core.OutcomeOK }),
		obs(base.Add(1*time.Second), func(o *store.Observation) { o.Outcome = core.OutcomeThrottled }),
	}
	if err := s.AppendObservations(context.Background(), batch); err != nil {
		t.Fatalf("запись: %v", err)
	}

	got, err := s.Observations(context.Background(), store.Query{
		VantageID: testVantage, Since: base.Add(-time.Hour), IncludeAllPhases: true,
	})
	if err != nil {
		t.Fatalf("Observations: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("прочитано %d наблюдений, ожидалось 3", len(got))
	}
	wantOrder := []core.Outcome{core.OutcomeOK, core.OutcomeThrottled, core.OutcomeFail}
	for i, w := range wantOrder {
		if got[i].Outcome != w {
			t.Fatalf("наблюдение %d имеет исход %v, ожидался %v (порядок времени нарушен)", i, got[i].Outcome, w)
		}
	}
}

// TestObservationsPreserveInsertionOrderWithinMillisecond: наблюдения, равные
// по времени, сохраняют порядок записи. Это и есть порядок наступления, от
// которого зависят серия провалов и чередование.
func TestObservationsPreserveInsertionOrderWithinMillisecond(t *testing.T) {
	s, _ := openTemp(t)
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

	batch := []store.Observation{
		obs(at, func(o *store.Observation) { o.Outcome = core.OutcomeOK }),
		obs(at, func(o *store.Observation) { o.Outcome = core.OutcomeFail }),
		obs(at, func(o *store.Observation) { o.Outcome = core.OutcomeOK }),
	}
	if err := s.AppendObservations(context.Background(), batch); err != nil {
		t.Fatalf("запись: %v", err)
	}

	got, err := s.Observations(context.Background(), store.Query{
		VantageID: testVantage, Since: at.Add(-time.Hour), IncludeAllPhases: true,
	})
	if err != nil {
		t.Fatalf("Observations: %v", err)
	}
	want := []core.Outcome{core.OutcomeOK, core.OutcomeFail, core.OutcomeOK}
	if len(got) != len(want) {
		t.Fatalf("прочитано %d, ожидалось %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Outcome != want[i] {
			t.Fatalf("наблюдение %d = %v, ожидалось %v", i, got[i].Outcome, want[i])
		}
	}
}

// TestObservationsRoundTripAllFields: все поля наблюдения переживают запись и
// чтение сырьём, включая базовую линию (пустая стратегия) и замеры.
func TestObservationsRoundTripAllFields(t *testing.T) {
	s, _ := openTemp(t)
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

	want := store.Observation{
		At:                 at,
		StrategyID:         "", // базовая линия
		Target:             testTarget,
		VantageID:          testVantage,
		Phase:              core.PhaseSlow,
		Outcome:            core.OutcomeThrottled,
		Reason:             core.ReasonThroughputLow,
		Source:             store.SourceLiveTraffic,
		StrategyApplied:    true,
		RTT:                42 * time.Millisecond,
		RTTMeasured:        true,
		Throughput:         123456,
		ThroughputMeasured: true,
	}
	if err := s.AppendObservations(context.Background(), []store.Observation{want}); err != nil {
		t.Fatalf("запись: %v", err)
	}

	got, err := s.Observations(context.Background(), store.Query{
		VantageID: testVantage, Since: at.Add(-time.Hour), IncludeAllPhases: true,
	})
	if err != nil {
		t.Fatalf("Observations: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("прочитано %d, ожидалось 1", len(got))
	}
	g := got[0]
	if !g.At.Equal(want.At) || g.StrategyID != want.StrategyID || g.Target != want.Target ||
		g.VantageID != want.VantageID || g.Phase != want.Phase || g.Outcome != want.Outcome ||
		g.Reason != want.Reason || g.Source != want.Source || g.StrategyApplied != want.StrategyApplied ||
		g.RTT != want.RTT || g.RTTMeasured != want.RTTMeasured ||
		g.Throughput != want.Throughput || g.ThroughputMeasured != want.ThroughputMeasured {
		t.Fatalf("наблюдение не совпало после круга записи-чтения:\nбыло  %+v\nстало %+v", want, g)
	}
}

// TestObservationsPhaseFilter: без IncludeAllPhases выборка ограничена одним
// уровнем. Прогрев читает все уровни, но фильтр обязан работать для аналитики.
func TestObservationsPhaseFilter(t *testing.T) {
	s, _ := openTemp(t)
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

	batch := []store.Observation{
		obs(at, func(o *store.Observation) { o.Phase = core.PhaseFast }),
		obs(at.Add(time.Second), func(o *store.Observation) { o.Phase = core.PhaseSlow }),
	}
	if err := s.AppendObservations(context.Background(), batch); err != nil {
		t.Fatalf("запись: %v", err)
	}

	fast, err := s.Observations(context.Background(), store.Query{
		VantageID: testVantage, Since: at.Add(-time.Hour), Phase: core.PhaseFast,
	})
	if err != nil {
		t.Fatalf("Observations: %v", err)
	}
	if len(fast) != 1 || fast[0].Phase != core.PhaseFast {
		t.Fatalf("фильтр по быстрому уровню вернул %+v", fast)
	}
}
