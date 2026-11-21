// Прогон: стратегия доходит от конфига до соединения.
//
// Проверяется самый длинный путь движка целиком, настоящим бинарником и
// настоящим трафиком: конфиг → контур управления → снимок → горячая таблица →
// SOCKS-прокси → десинк ClientHello → ответ сервера → наблюдение в контуре.
//
// Зачем такой прогон, если есть юнит-тесты. Юнит-тесты проверяют части и путь
// к состоянию не проверяют вовсе — именно так в этом проекте трижды
// проскочили дефекты запуска: ложная тревога об обвале, восемь снимков вместо
// одного и гонка между прокси и первым снимком. Все три видны только живьём.
package main

import (
	"time"

	"github.com/fitting-1c/evasion/tests/harness"
)

// controlTarget — нецензурируемая цель. Берётся именно такая: прогон проверяет
// движок, а не доступность заблокированного сайта, и на цели, которую ломает
// DPI, нельзя отличить свой дефект от чужой блокировки.
const controlTarget = "example.com"

func main() {
	run := harness.StartRun(
		"proxy-applies-strategy-end-to-end",
		"стратегия из конфига доходит до соединения, и исход возвращается в контур")
	defer run.Finish()

	cfg := harness.DefaultConfig("", map[string][]string{"control": {controlTarget}})
	eng, err := harness.StartEngine(cfg)
	if err != nil {
		run.Fail("движок не запустился: %v", err)
		return
	}
	defer eng.Cleanup()
	defer eng.Stop()
	run.Step("движок запущен, прокси на %s", eng.Listen)

	// До трафика состояние обязано быть осмысленным: стратегия из конфига
	// закреплена за целью с первого же снимка.
	before, err := eng.Status()
	if err != nil {
		run.Fail("состояние не прочитано: %v", err)
		return
	}
	run.Fact("снимок №%d, целей %d, тревога обвала: %v",
		before.SnapshotRev, len(before.Targets), before.Blackout)
	run.Require(before.SnapshotRev == 1,
		"снимок №%d: закрепления из конфига должны попадать в первый снимок", before.SnapshotRev)
	run.Require(!before.Blackout,
		"тревога обвала при закреплённой стратегии — ложная")

	applied := ""
	for _, t := range before.Targets {
		if t.Target == controlTarget {
			applied = t.Active.String()
			run.Fact("цель %s: действует %s, причина %q", t.Target, applied, t.Reason)
		}
	}
	if !run.Require(applied != "", "к цели %s не применено ничего", controlTarget) {
		return
	}

	// Живой трафик через прокси.
	code, err := eng.Get("https://"+controlTarget+"/", 20*time.Second)
	if err != nil {
		run.Fact("запрос через прокси не удался: %v", err)
	}
	run.Fact("ответ контрольной цели: код %d", code)
	run.Require(code == 200,
		"контрольная цель ответила %d вместо 200: при стратегии ломается то, что должно работать", code)

	// Наблюдение обязано вернуться в контур: без этого автопилот не учится.
	deadline := time.Now().Add(5 * time.Second)
	var after = before
	for time.Now().Before(deadline) {
		if after, err = eng.Status(); err == nil && after.Intake.Accepted > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	run.Fact("наблюдений принято %d, отброшено %d, непригодных %d, оценок %d",
		after.Intake.Accepted, after.Intake.Dropped, after.Intake.Invalid, after.Intake.Estimates)
	run.Require(after.Intake.Accepted > 0,
		"исход соединения не дошёл до контура: автопилот не учится на живом трафике")
	run.Require(after.Intake.Invalid == 0,
		"непригодных наблюдений %d: исход не удалось отнести к цели радиуса", after.Intake.Invalid)
	run.Require(after.Intake.Estimates > 0,
		"оценок в таблице нет: наблюдение не стало знанием")
}
