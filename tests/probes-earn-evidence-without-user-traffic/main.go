// Прогон: движок сам добывает доказательства, без трафика пользователя.
//
// Проверяется нижняя ступень лестницы допуска (5.1). Порог допуска к живому
// трафику открывается наблюдениями (5.5), а кандидату взять их негде: на живой
// трафик его не пускает тот же порог. Единственный выход — пробы, соединения
// которые движок инициирует сам, с нулевым риском для пользователя.
//
// Пока расписания проб не было, эта ступень была закрыта, и автопилот умел
// только исполнять закрепления человека: пакет probe существовал с M4, а
// вызывать его было некому. Прогон стоит на страже именно этого — он не
// пропускает ни одного соединения через прокси и требует, чтобы наблюдения
// всё равно появились.
package main

import (
	"time"

	"github.com/fitting-1c/evasion/internal/control"
	"github.com/fitting-1c/evasion/tests/harness"
)

const controlTarget = "example.com"

// waitForProbes — сколько ждать наблюдений.
//
// Интервал проб в прогоне короткий (конфиг ниже), поэтому ждать долго не
// нужно; запас взят на медленный канал и на разброс интервала, который
// обязателен (5.7) и может отодвинуть пробу.
const waitForProbes = 25 * time.Second

func main() {
	run := harness.StartRun(
		"probes-earn-evidence-without-user-traffic",
		"движок добывает наблюдения пробами, не пропуская через себя ни одного соединения пользователя")
	defer run.Finish()

	cfg := harness.DefaultConfig("", map[string][]string{"control": {controlTarget}})
	cfg.ProbeTargets = []string{controlTarget}
	cfg.ControlTargets = []string{controlTarget}
	// Интервалы ускорены: прогон проверяет, что пробы идут вообще, а не что
	// они идут раз в двенадцать минут. Разброс оставлен обязательным.
	cfg.Autopilot = map[string]any{
		"probe_interval":          "3s",
		"probe_interval_degraded": "2s",
		"probe_jitter":            0.2,
	}

	eng, err := harness.StartEngine(cfg)
	if err != nil {
		run.Fail("движок не запустился: %v", err)
		return
	}
	defer eng.Cleanup()
	defer eng.Stop()
	run.Step("движок запущен; через прокси намеренно не идёт ни одного соединения")

	deadline := time.Now().Add(waitForProbes)
	st, err := eng.Status()
	for err == nil && st.Intake.Accepted == 0 && time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		st, err = eng.Status()
	}
	if err != nil {
		run.Fail("состояние не прочитано: %v", err)
		return
	}

	run.Fact("наблюдений принято %d, оценок %d, непригодных %d",
		st.Intake.Accepted, st.Intake.Estimates, st.Intake.Invalid)

	if !run.Require(st.Intake.Accepted > 0,
		"за %v пробы не добыли ни одного наблюдения: нижняя ступень лестницы закрыта, и кандидат никогда не доберётся до живого трафика (5.1, 5.5)",
		waitForProbes) {
		run.Fact("журнал движка:\n%s", eng.Logs())
		return
	}
	run.Require(st.Intake.Invalid == 0,
		"непригодных наблюдений %d: результат пробы не отнесён к цели радиуса", st.Intake.Invalid)
	run.Require(st.Intake.Estimates > 0,
		"оценок нет: наблюдение не стало знанием")

	// Пробы обязаны ходить по именам из конфига, а не по целям радиуса:
	// цель — суффикс, и ходить к ней можно лишь тогда, когда она отвечает
	// сама.
	run.Fact("имя для проб: %s (из probe_targets)", controlTarget)

	// Базовая линия: движок обязан знать, жива ли цель БЕЗ стратегии.
	//
	// Это та самая двусмысленность, из-за которой первое измерение пробами
	// нельзя было истолковать: discord.gg прошёл рукопожатие со стратегией, но
	// он доступен и без неё, а базовой пробы у движка не было. Здесь цель
	// контрольная и заведомо доступная, поэтому ожидание однозначно: базовая
	// линия обязана быть измерена и обязана быть успешной.
	//
	// Прогон не требует, чтобы цель открывалась, нигде, кроме контрольной:
	// провал заблокированной цели — измерение, а не дефект. Но контрольная
	// цель обязана отвечать, иначе измерять нечем вовсе.
	baseline, ok := baselineOf(st, controlTarget)
	if !run.Require(ok, "цели %s нет в состоянии движка: базовую линию не к чему отнести", controlTarget) {
		return
	}
	run.Fact("базовая линия %s: наблюдений %d, успешных %d, верхняя граница %d‰, последнее %s",
		controlTarget, baseline.Observations, baseline.Successes,
		baseline.UpperPermille, baseline.Last.Format(time.RFC3339))

	if !run.Require(baseline.Known,
		"базовая линия цели %s не измерена: без неё положительный исход пробы двусмыслен — "+
			"движок не отличит «стратегия обошла DPI» от «цель и так не блокировалась»",
		controlTarget) {
		run.Fact("журнал движка:\n%s", eng.Logs())
		return
	}
	run.Require(baseline.Successes > 0,
		"контрольная цель %s не ответила без стратегии (%d наблюдений, 0 успешных): "+
			"либо канал неисправен, либо базовая проба идёт не туда — в обоих случаях измерять нечем",
		controlTarget, baseline.Observations)

	// И следствие, которое было целью правки: на доступной цели автопилот не
	// присваивает стратегии чужую заслугу.
	//
	// Утверждение сформулировано осторожно, и первая его версия была неверной.
	// Она требовала, чтобы на доступной цели не применялось ничего, — и
	// провалилась на этом самом прогоне: стратегия из конфига закрепляется за
	// целями радиуса, а закрепление по заданию обходит все пороги (4.5,
	// правило 1 решателя). Это осознанная команда человека, и спорить с ней
	// статистикой движок не вправе. Прав был движок, а не прогон.
	//
	// Поэтому проверяется то, что действительно обязано выполняться: стратегия
	// на доступной цели может стоять только по закреплению. Любая другая
	// причина означала бы, что порог базовой линии не сработал и автопилот
	// выдал кредит за доступность цели.
	ts, _ := targetOf(st, controlTarget)
	run.Fact("цель %s: применена %q, закреплена %q, причина решения %q",
		controlTarget, ts.Active, ts.Pinned, ts.Reason)

	if ts.Active != "" {
		run.Require(ts.Reason == control.ReasonPinned && ts.Pinned == ts.Active,
			"на доступной без стратегии цели %s стратегия %q применена по причине %q, "+
				"а не закреплением: автопилот присвоил себе доступность цели",
			controlTarget, ts.Active, ts.Reason)
	}

	// Долю проверки закрепление подавляет отдельно, но если бы не подавляло,
	// кандидат на доступной цели всё равно не должен был бы её получить:
	// доказать на ней нечего.
	run.Require(ts.Trial == "" || ts.TrialReason != control.ReasonTrialAdmitted ||
		baseline.Successes == 0,
		"на доступной цели %s кандидат %q допущен к доле трафика: "+
			"превосходства над базовой линией у него быть не может",
		controlTarget, ts.Trial)
}

// targetOf достаёт состояние цели из состояния движка.
func targetOf(st control.Status, target string) (control.TargetStatus, bool) {
	for _, ts := range st.Targets {
		if ts.Target == target {
			return ts, true
		}
	}
	return control.TargetStatus{}, false
}

// baselineOf достаёт базовую линию цели из состояния движка.
func baselineOf(st control.Status, target string) (control.BaselineStatus, bool) {
	ts, ok := targetOf(st, target)
	return ts.Baseline, ok
}
