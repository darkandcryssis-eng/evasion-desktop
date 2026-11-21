package telemetry

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestCounterNamesComplete(t *testing.T) {
	// Промах в соответствии «счётчик → имя» обязан обнаруживаться тестом, а не
	// во время работы: безымянный счётчик попал бы в вывод под пустым ключом и
	// перекрыл бы другой.
	seen := make(map[string]Counter, counterCount)
	for i := Counter(0); i < counterCount; i++ {
		name := i.String()
		if name == "" {
			t.Fatalf("счётчик %d без имени", uint8(i))
		}
		if name == "unknown" {
			t.Fatalf("счётчик %d получил имя-заглушку", uint8(i))
		}
		if prev, dup := seen[name]; dup {
			t.Fatalf("имя %q у двух счётчиков: %d и %d", name, uint8(prev), uint8(i))
		}
		seen[name] = i
	}
	if len(seen) != int(counterCount) {
		t.Fatalf("имён %d при %d счётчиках", len(seen), counterCount)
	}
}

func TestCountersZeroValueUsable(t *testing.T) {
	// Счётчики нужны раньше, чем поднимается остальное, поэтому нулевое
	// значение обязано быть готовым к работе.
	var c Counters
	c.Inc(CounterConnAccepted)
	c.Add(CounterProbeOK, 5)

	if got := c.Get(CounterConnAccepted); got != 1 {
		t.Fatalf("после одного инкремента %d", got)
	}
	if got := c.Get(CounterProbeOK); got != 5 {
		t.Fatalf("после Add(5) %d", got)
	}
	if got := c.Get(CounterProbeFail); got != 0 {
		t.Fatalf("нетронутый счётчик %d", got)
	}
}

func TestCountersSnapshotIsData(t *testing.T) {
	var c Counters
	c.Inc(CounterStrategyApplied)
	snap := c.Snapshot()

	if len(snap) != int(counterCount) {
		t.Fatalf("в снимке %d записей при %d счётчиках", len(snap), counterCount)
	}
	if snap["strategy_applied"] != 1 {
		t.Fatalf("strategy_applied = %d", snap["strategy_applied"])
	}
	// Снимок — копия: изменение счётчика после снятия его не затрагивает.
	c.Inc(CounterStrategyApplied)
	if snap["strategy_applied"] != 1 {
		t.Fatal("снимок изменился вслед за счётчиком")
	}
}

func TestCountersConcurrentIncrements(t *testing.T) {
	// Счётчики инкрементируются с горячего пути из многих горутин. Потеря
	// инкремента означала бы, что наблюдаемость врёт тем сильнее, чем больше
	// нагрузка, — то есть именно тогда, когда она нужна.
	var c Counters
	const goroutines, perGoroutine = 16, 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range perGoroutine {
				c.Inc(CounterClientHelloSeen)
			}
		}()
	}
	wg.Wait()

	if got, want := c.Get(CounterClientHelloSeen), int64(goroutines*perGoroutine); got != want {
		t.Fatalf("получено %d инкрементов из %d", got, want)
	}
}

func TestRingKeepsOrderAndEvictsOldest(t *testing.T) {
	r := NewRing(3)
	for _, m := range []string{"a", "b", "c", "d", "e"} {
		r.Append(Event{Message: m})
	}

	snap := r.Snapshot()
	var got []string
	for _, e := range snap {
		got = append(got, e.Message)
	}
	// Ёмкость три: остались три последних, от старого к новому.
	if strings.Join(got, ",") != "c,d,e" {
		t.Fatalf("содержимое буфера %v, ожидалось [c d e]", got)
	}
}

func TestRingNotFullKeepsAllInOrder(t *testing.T) {
	r := NewRing(5)
	r.Append(Event{Message: "a"})
	r.Append(Event{Message: "b"})

	snap := r.Snapshot()
	if len(snap) != 2 || snap[0].Message != "a" || snap[1].Message != "b" {
		t.Fatalf("содержимое неполного буфера %+v", snap)
	}
}

func TestRingStatsReportDropped(t *testing.T) {
	// Без числа потерянных снимок выглядел бы полной картиной, тогда как при
	// переполнении он лишь хвост. Разбирая сбой, важно знать, что начало
	// утрачено.
	r := NewRing(2)
	for range 7 {
		r.Append(Event{})
	}
	held, capacity, total, dropped := r.Stats()
	if held != 2 || capacity != 2 {
		t.Fatalf("занято %d при ёмкости %d", held, capacity)
	}
	if total != 7 {
		t.Fatalf("всего прошло %d, ожидалось 7", total)
	}
	if dropped != 5 {
		t.Fatalf("потеряно %d, ожидалось 5", dropped)
	}
}

func TestRingEmptySnapshot(t *testing.T) {
	r := NewRing(4)
	if snap := r.Snapshot(); len(snap) != 0 {
		t.Fatalf("снимок пустого буфера содержит %d записей", len(snap))
	}
	_, _, total, dropped := r.Stats()
	if total != 0 || dropped != 0 {
		t.Fatalf("пустой буфер: всего %d, потеряно %d", total, dropped)
	}
}

func TestRingDefaultCapacity(t *testing.T) {
	for _, c := range []int{0, -1} {
		r := NewRing(c)
		if _, capacity, _, _ := r.Stats(); capacity != DefaultRingCapacity {
			t.Fatalf("при ёмкости %d получено %d, ожидалось %d", c, capacity, DefaultRingCapacity)
		}
	}
}

func TestRingConcurrentAppendAndSnapshot(t *testing.T) {
	// Буфер читают во время записи: именно так он и используется при разборе
	// сбоя. Снимок обязан быть согласованным, а не смесью записей.
	r := NewRing(64)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 2000 {
			r.Append(Event{Message: "x", Fields: []Field{{Key: "i", Value: i}}})
		}
	}()
	go func() {
		defer wg.Done()
		for range 500 {
			for _, e := range r.Snapshot() {
				// Обращение к полям снимка не должно обнаруживать
				// недописанных записей.
				_ = e.Message
				_ = len(e.Fields)
			}
		}
	}()
	wg.Wait()
}

// newTestHandler собирает обработчик с подложенным буфером и текстовым
// журналом в память.
func newTestHandler(t *testing.T, nextLevel, ringLevel slog.Level) (*slog.Logger, *Ring, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	next := slog.NewTextHandler(&out, &slog.HandlerOptions{Level: nextLevel})
	ring := NewRing(16)
	return slog.New(NewHandler(next, ring, ringLevel)), ring, &out
}

func TestHandlerRecordsAndForwards(t *testing.T) {
	log, ring, out := newTestHandler(t, slog.LevelInfo, slog.LevelInfo)
	log.Info("соединение принято", "remote", "127.0.0.1:1234")

	snap := ring.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("в буфере %d записей", len(snap))
	}
	if snap[0].Message != "соединение принято" {
		t.Fatalf("сообщение %q", snap[0].Message)
	}
	if len(snap[0].Fields) != 1 || snap[0].Fields[0].Key != "remote" {
		t.Fatalf("поля %+v", snap[0].Fields)
	}
	if !strings.Contains(out.String(), "соединение принято") {
		t.Fatalf("запись не ушла в журнал: %q", out.String())
	}
}

// TestHandlerFillsRingWhenLogIsQuiet — главная проверка обработчика.
//
// Журнал настроен на предупреждения, а события жизненного цикла соединения
// идут на уровне сведений. Если спрашивать разрешение только у нижележащего
// обработчика, такие записи до Handle не дойдут, и буфер окажется пустым —
// ровно тогда, когда он нужен для разбора сбоя.
func TestHandlerFillsRingWhenLogIsQuiet(t *testing.T) {
	log, ring, out := newTestHandler(t, slog.LevelWarn, slog.LevelInfo)
	log.Info("начало соединения обработано", "sni", "example.com")

	if snap := ring.Snapshot(); len(snap) != 1 {
		t.Fatalf("в буфере %d записей при молчаливом журнале", len(snap))
	}
	// В журнал запись при этом уйти не должна: надстройка не вправе повышать
	// разговорчивость, это решение вызывающего.
	if out.Len() != 0 {
		t.Fatalf("запись ушла в журнал вопреки его уровню: %q", out.String())
	}
}

func TestHandlerRespectsRingLevel(t *testing.T) {
	// Обратный случай: отладочные записи в буфер не попадают, иначе он
	// переполнится подробностями и вытеснит то, ради чего существует.
	log, ring, _ := newTestHandler(t, slog.LevelDebug, slog.LevelInfo)
	log.Debug("подробность по пакету", "len", 1460)
	log.Info("исход соединения")

	snap := ring.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("в буфере %d записей, ожидалась одна", len(snap))
	}
	if snap[0].Message != "исход соединения" {
		t.Fatalf("в буфер попала не та запись: %q", snap[0].Message)
	}
}

func TestHandlerWithAttrsAndGroup(t *testing.T) {
	log, ring, _ := newTestHandler(t, slog.LevelInfo, slog.LevelInfo)

	log.With("conn", 7).WithGroup("strategy").Info("применена", "id", "abc", "at", "inside_sni")

	snap := ring.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("в буфере %d записей", len(snap))
	}
	got := make(map[string]any, len(snap[0].Fields))
	for _, f := range snap[0].Fields {
		got[f.Key] = f.Value
	}
	// Поле, добавленное до группы, остаётся на верхнем уровне; поля записи
	// получают составное имя. Иначе одноимённые поля из разных групп
	// перекрыли бы друг друга.
	if got["conn"] != int64(7) {
		t.Fatalf("поле conn = %#v", got["conn"])
	}
	if got["strategy.id"] != "abc" {
		t.Fatalf("поле strategy.id = %#v, все поля: %+v", got["strategy.id"], got)
	}
	if got["strategy.at"] != "inside_sni" {
		t.Fatalf("поле strategy.at = %#v", got["strategy.at"])
	}
}

func TestHandlerSharedWithAttrsIsIndependent(t *testing.T) {
	// Обработчик с полями может быть создан однажды и использован из
	// нескольких мест. Общий срез накопленных полей стал бы гонкой и
	// перепутал бы поля между записями.
	log, ring, _ := newTestHandler(t, slog.LevelInfo, slog.LevelInfo)
	base := log.With("common", 1)

	base.With("a", 1).Info("первое")
	base.With("b", 2).Info("второе")

	snap := ring.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("в буфере %d записей", len(snap))
	}
	for _, e := range snap {
		keys := make([]string, 0, len(e.Fields))
		for _, f := range e.Fields {
			keys = append(keys, f.Key)
		}
		joined := strings.Join(keys, ",")
		switch e.Message {
		case "первое":
			if joined != "common,a" {
				t.Fatalf("поля первой записи %q", joined)
			}
		case "второе":
			if joined != "common,b" {
				t.Fatalf("поля второй записи %q", joined)
			}
		}
	}
}

func TestHandlerNestedGroups(t *testing.T) {
	log, ring, _ := newTestHandler(t, slog.LevelInfo, slog.LevelInfo)
	log.WithGroup("outer").WithGroup("inner").Info("событие", "key", "value")

	snap := ring.Snapshot()
	if len(snap) != 1 || len(snap[0].Fields) != 1 {
		t.Fatalf("записи %+v", snap)
	}
	if snap[0].Fields[0].Key != "outer.inner.key" {
		t.Fatalf("составное имя %q", snap[0].Fields[0].Key)
	}
}

func TestHandlerGroupAttrValue(t *testing.T) {
	// Набор полей, переданный значением, разворачивается так же, как открытая
	// группа: иначе в буфер попал бы объект вместо полей.
	log, ring, _ := newTestHandler(t, slog.LevelInfo, slog.LevelInfo)
	log.Info("событие", slog.Group("probe", slog.String("outcome", "ok"), slog.Int("rtt_ms", 12)))

	snap := ring.Snapshot()
	got := make(map[string]any)
	for _, f := range snap[0].Fields {
		got[f.Key] = f.Value
	}
	if got["probe.outcome"] != "ok" {
		t.Fatalf("probe.outcome = %#v, поля %+v", got["probe.outcome"], got)
	}
	if got["probe.rtt_ms"] != int64(12) {
		t.Fatalf("probe.rtt_ms = %#v", got["probe.rtt_ms"])
	}
}

func TestHandlerEventTimeIsRecorded(t *testing.T) {
	// Время события берётся из записи журнала, а не из момента попадания в
	// буфер: иначе при разборе сбоя порядок событий мог бы не совпасть с их
	// настоящей последовательностью.
	synctest.Test(t, func(t *testing.T) {
		log, ring, _ := newTestHandler(t, slog.LevelInfo, slog.LevelInfo)
		log.Info("первое")
		time.Sleep(time.Minute)
		log.Info("второе")

		snap := ring.Snapshot()
		if len(snap) != 2 {
			t.Fatalf("в буфере %d записей", len(snap))
		}
		gap := snap[1].Time.Sub(snap[0].Time)
		if gap != time.Minute {
			t.Fatalf("разрыв между событиями %v, ожидалась минута", gap)
		}
	})
}

// TestHandlerAttrsQualifiedByOpenGroup закрывает пробел, найденный проверкой на
// мутацию.
//
// Поле, добавленное ПОСЛЕ открытия группы, обязано получить её имя. Прежние
// проверки этот случай не задевали: они либо добавляли поле до группы, либо
// передавали поля прямо в вызов записи, а не через With. Подмена групп на
// пустые при добавлении оставалась незамеченной.
func TestHandlerAttrsQualifiedByOpenGroup(t *testing.T) {
	log, ring, _ := newTestHandler(t, slog.LevelInfo, slog.LevelInfo)

	// Поле before добавлено до группы — остаётся наверху.
	// Поле inside добавлено после — принадлежит группе.
	log.With("before", 1).WithGroup("probe").With("inside", 2).Info("исход", "at_call", 3)

	snap := ring.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("в буфере %d записей", len(snap))
	}
	got := make(map[string]any, len(snap[0].Fields))
	for _, f := range snap[0].Fields {
		got[f.Key] = f.Value
	}
	for key, want := range map[string]any{
		"before":        int64(1),
		"probe.inside":  int64(2),
		"probe.at_call": int64(3),
	} {
		if got[key] != want {
			t.Fatalf("поле %q = %#v, ожидалось %#v; все поля: %+v", key, got[key], want, got)
		}
	}
}
