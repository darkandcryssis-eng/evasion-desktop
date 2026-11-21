// Прогон: наблюдения выживают перезапуск движка.
//
// Проверяется то, ради чего журнал наблюдений вообще существует (6.4): каждое
// наблюдение добыто живым соединением и повторить его нельзя, а оценки контура
// живут в памяти и исчезают при остановке. Если журнал не пишется, движок
// после каждого запуска начинает учиться заново — и заметно это становится
// только через сутки работы, когда портфель оказывается пуст.
//
// Прогон проверяет не «файл создан», а «запись читается обратно»: пустой файл
// базы создаётся и при полном отсутствии наблюдений.
package main

import (
	"context"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/store"
	"github.com/fitting-1c/evasion/internal/store/sqlite"
	"github.com/fitting-1c/evasion/tests/harness"
)

const controlTarget = "example.com"

// flushWait — сколько ждать, пока писатель журнала допишет пачку.
//
// Писатель накапливает наблюдения и дописывает их по сроку, чтобы не ходить на
// диск за каждым соединением. Поэтому прогон ждёт срок дописывания, а не
// останавливает движок немедленно: на Windows остановка жёсткая (консольному
// процессу без окна нечего закрывать), и неотправленная пачка пропала бы — но
// по вине прогона, а не движка.
const flushWait = 3 * time.Second

func main() {
	run := harness.StartRun(
		"archive-persists-observations",
		"наблюдение с живого соединения попадает в журнал на диске и читается обратно")
	defer run.Finish()

	cfg := harness.DefaultConfig("", map[string][]string{"control": {controlTarget}})
	eng, err := harness.StartEngine(cfg)
	if err != nil {
		run.Fail("движок не запустился: %v", err)
		return
	}
	defer eng.Cleanup()
	run.Step("движок запущен, журнал ожидается в %s", eng.ArchivePath())

	code, err := eng.Get("https://"+controlTarget+"/", 20*time.Second)
	if err != nil {
		run.Fact("запрос через прокси не удался: %v", err)
	}
	run.Fact("ответ контрольной цели: код %d", code)

	// Состояние читается не сразу: исход соединения идёт к контуру через
	// очередь, и мгновенное чтение показывало бы ноль принятых наблюдений —
	// цифру, которая вводит в заблуждение, потому что наблюдение уже в пути.
	st, err := eng.Status()
	deadline := time.Now().Add(5 * time.Second)
	for err == nil && st.Intake.Accepted == 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		st, err = eng.Status()
	}
	if err != nil {
		run.Fail("состояние не прочитано: %v", err)
		return
	}
	run.Fact("наблюдений принято контуром: %d", st.Intake.Accepted)
	// Точка наблюдения нужна для запроса к журналу: она часть ключа любого
	// наблюдения (6.1), и запрос без неё бессмыслен.
	vantage := st.Vantage

	run.Step("ждём %v: писатель журнала дописывает пачку по сроку, а не на каждое соединение", flushWait)
	time.Sleep(flushWait)

	// Движок останавливается до чтения журнала: так проверяется именно то, что
	// данные уцелели без него, а не то, что они лежат в его памяти.
	if err := eng.Stop(); err != nil {
		run.Fail("движок не остановился: %v", err)
		return
	}
	run.Step("движок остановлен, журнал читается заново")

	st2, err := sqlite.Open(eng.ArchivePath())
	if err != nil {
		run.Fail("журнал не открывается после остановки движка: %v", err)
		return
	}
	defer st2.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Срез берётся с запасом по времени в обе стороны: прогон идёт секунды, а
	// границы разделов считаются по UTC.
	tallies, err := st2.Tallies(ctx, store.Query{
		VantageID: vantage,
		Target:    controlTarget,
		Since:     time.Now().Add(-time.Hour),
		Until:     time.Now().Add(time.Hour),
	})
	if err != nil {
		run.Fail("срез наблюдений не прочитан: %v", err)
		return
	}

	var total int64
	for _, t := range tallies {
		total += t.Total
		run.Fact("срез: стратегия %s, цель %s, наблюдений %d (успехов %d, провалов %d, неопределённых %d)",
			short(t.StrategyID.String()), t.Target, t.Total,
			t.Counts[core.OutcomeOK], t.Counts[core.OutcomeFail], t.Counts[core.OutcomeInconclusive])
	}

	run.Require(total > 0,
		"в журнале нет ни одного наблюдения по цели %s: движок будет учиться заново после каждого запуска",
		controlTarget)
}

// short укорачивает идентификатор для отчёта: в полном виде он нужен машине, а
// не человеку, читающему вывод.
func short(id string) string {
	const keep = 12
	if len(id) <= keep {
		return id
	}
	return id[:keep]
}
