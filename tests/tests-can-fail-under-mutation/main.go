// Прогон: тесты способны провалиться.
//
// Приём, которым в этом проекте найдено больше дефектов, чем любым другим: в
// код вносится мутация, и тест, заявляющий сломанное свойство, обязан упасть.
// Тест, который проходит при сломанном коде, не защищает ничего — он
// украшение. За время работы приём нашёл четыре таких теста в прежних пакетах
// и ещё несколько в свежем коде.
//
// Почему это прогон, а не юнит-тест. Он правит исходники на диске и гоняет
// `go test` — изнутри `go test` такое делать нельзя. Поэтому мутации живут
// здесь, в библиотеке прогонов, и запускаются отдельно.
//
// Прогон обязан возвращать исходники в прежний вид при любом исходе, включая
// панику: иначе он оставил бы репозиторий с внесённой мутацией, и это
// выяснилось бы при следующем коммите.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/fitting-1c/evasion/tests/harness"
)

// mutation — одна мутация: что портим и какой тест обязан это заметить.
type mutation struct {
	// name — что именно сломано, человеческими словами.
	name string
	// file — файл исходника относительно корня репозитория.
	file string
	// test — выражение -run для теста, который обязан упасть.
	test string
	// old, new — что на что заменить. Замена одна, первая по тексту.
	old, new string
	// extra — дополнительные правки того же файла.
	//
	// Нужны мутациям, которые иначе не собираются: подменить атомарный
	// указатель обычным полем нельзя одной правкой — вместе с объявлением
	// меняются все обращения. А мутация, которая не собралась, ничего не
	// проверяет.
	extra []edit
	// race — проверять под детектором гонок: без него мутация не видна.
	race bool
	// goos — платформа, на которой мутация доказывает своё свойство. Пусто
	// означает «на любой».
	//
	// Нужно windows-only файлам. Их код в песочнице разработки не
	// компилируется вовсе, поэтому мутация там применится к тексту, но тест не
	// упадёт — и батарея объявила бы его декоративным, хотя декоративности
	// никакой нет. До появления этого признака windows-only файлы не имели
	// покрытия мутациями ни одной штуки: заявить их свойства было нечем.
	//
	// Пропущенные мутации считаются и печатаются отдельно: пропуск обязан быть
	// видимым, иначе через полгода никто не узнает, что свойство проверяется
	// только у владельца.
	goos string
}

// edit — одна текстовая правка.
type edit struct{ old, new string }

// mutations — батарея мутаций.
//
// Список именно такой длины не случайно: каждая мутация соответствует
// свойству, которое кто-то решил проверять тестом. Добавляя тест на
// неочевидное свойство, добавляйте сюда и мутацию — иначе через полгода
// никто не узнает, что тест перестал его проверять.
var mutations = []mutation{
	// policy: горячая таблица решений.
	{
		name: "обход суффиксов идёт по одному знаку вместо метки",
		file: "internal/policy/snapshot.go", test: "TestSnapshotDoesNotMatchSiblingName",
		old: "folded = folded[i+1:]", new: "folded = folded[1:]",
	},
	{
		name: "более точная запись перестаёт выигрывать у общей",
		file: "internal/policy/snapshot.go", test: "TestSnapshotMostSpecificRecordWins",
		old: "folded := buf[:n]",
		new: "folded := buf[:n]; if i := bytes.IndexByte(folded, 0x2e); i >= 0 { folded = folded[i+1:] }",
	},
	{
		name: "запись-исключение выброшена из снимка",
		file: "internal/policy/snapshot.go", test: "TestSnapshotExclusionOverridesBroaderRecord",
		old: "\t\tif err := validateTrial(e); err != nil {",
		new: "\t\tif e.Strategy == nil && e.Trial == nil {\n\t\t\tcontinue\n\t\t}\n\t\tif err := validateTrial(e); err != nil {",
	},
	{
		name: "повторный домен молча перезаписывает прежний",
		file: "internal/policy/snapshot.go", test: "TestNewSnapshotRejectsDuplicateDomain",
		old: "if _, dup := byName[name]; dup {", new: "if _, dup := byName[name]; false && dup {",
	},
	{
		name: "жребий доли трафика не бросается",
		file: "internal/policy/arm.go", test: "TestTrial",
		old: "if r.permille != 0 && drawPermille() < r.permille {", new: "if false {",
	},
	{
		name: "проверочная ветвь не помечается в выборе",
		file: "internal/policy/snapshot.go", test: "TestTrial",
		old: "return proxy.Selection{Strategy: s, ID: id, Trial: trial}, nil",
		new: "return proxy.Selection{Strategy: s, ID: id}, nil",
	},
	{
		name: "цель радиуса не попадает в выбор",
		file: "internal/policy/arm.go", test: "TestSelectionCarriesRadiusTarget",
		old: "sel.Target = r.target", new: "",
	},
	{
		name: "приведение регистра имени убрано",
		file: "internal/policy/name.go", test: "TestSnapshotCaseAndTrailingDot",
		old: "if c >= 'A' && c <= 'Z' {\n\t\t\tc += 'a' - 'A'\n\t\t}", new: "",
	},

	// control: решение о смене стратегии.
	{
		name: "закрепление проверяется после статистики",
		file: "internal/control/decide.go", test: "TestDecidePin",
		old: `if in.Pinned != "" {`, new: `if false && in.Pinned != "" {`,
	},
	{
		name: "срыв стратегии ждёт истечения выдержки",
		file: "internal/control/decide.go", test: "TestDecideBrokenBeatsDwell",
		old: `if cur != "" && t.Broken(key(cur)) {`,
		new: `if cur != "" && t.Broken(key(cur)) && in.Now.Sub(in.State.Since) >= d.cfg.MinDwell {`,
	},
	{
		name: "выдержки между сменами нет вовсе",
		file: "internal/control/decide.go", test: "TestDecideHoldsDwell",
		old: `if cur != "" && in.Now.Sub(in.State.Since) < d.cfg.MinDwell {`, new: "if false {",
	},
	{
		name: "порог доверия не проверяется",
		file: "internal/control/decide.go", test: "TestDecideWithoutProofAppliesNothing",
		old: "if !promo.Ready {", new: "if false {",
	},
	{
		name: "история цели не поднимает требуемый объём наблюдений",
		file: "internal/control/decide.go", test: "TestDecideHistoryRaisesBar",
		old: "return t.EvaluatePromotion(k,\n\t\tcontainsID(in.State.Collateral, id),\n\t\tcontainsID(in.State.Degraded, id))",
		new: "return t.EvaluatePromotion(k, false, false)",
	},
	{
		name: "кандидат прыгает в active, минуя ступень проверки",
		file: "internal/control/decide.go", test: "TestCandidateNeverJumpsToActive",
		old: "case core.StatusTesting, core.StatusActive, core.StatusBenched:",
		new: "case core.StatusTesting, core.StatusActive, core.StatusBenched, core.StatusCandidate:",
	},
	{
		name: "побочный вред не запрещает применение",
		file: "internal/control/portfolio.go", test: "TestCollateral",
		old: "return h.Collateral && !h.CollateralAllowed", new: "_ = h\n\treturn false",
	},
	{
		name: "цель без стратегии пропускается вместо исключения",
		file: "internal/control/plan.go", test: "TestBuildPlanCoversEveryTarget",
		old: "\t\tplan.Entries = append(plan.Entries, policy.Entry{",
		new: "\t\tif in.Portfolio.Strategy(dec.Effective()) == nil && trial == nil {\n\t\t\tcontinue\n\t\t}\n\t\tplan.Entries = append(plan.Entries, policy.Entry{",
	},
	{
		name: "обвал портфеля не замечается",
		file: "internal/control/plan.go", test: "TestBlackoutRaisesTrialShare",
		old: "plan.Blackout = len(targets) > 0 && !anyActive", new: "_ = anyActive\n\tplan.Blackout = false",
	},
	{
		name: "закрепления из конфига не попадают в первый снимок",
		file: "internal/control/engine.go", test: "TestEngineInitialPinsAppliedInFirstSnapshot",
		old: "pins[target] = id", new: "",
	},
	{
		name: "очередь наблюдений не вычерпывается перед пересчётом",
		file: "internal/control/engine.go", test: "TestEngineAppliesProvenStrategy",
		old: "e.drainObs()", new: "",
	},
	{
		name: "обычное поле вместо атомарного указателя",
		file: "internal/policy/table.go", test: "TestTableConcurrentSelectDuringInstall",
		old: "cur atomic.Pointer[Snapshot]", new: "cur *Snapshot",
		extra: []edit{
			{old: "import (\n\t\"sync/atomic\"\n\n\t\"github.com/fitting-1c/evasion/internal/proxy\"\n)",
				new: "import (\n\t\"github.com/fitting-1c/evasion/internal/proxy\"\n)"},
			{old: "func (t *Table) Install(s *Snapshot) { t.cur.Store(s) }",
				new: "func (t *Table) Install(s *Snapshot) { t.cur = s }"},
			{old: "func (t *Table) Current() *Snapshot { return t.cur.Load() }",
				new: "func (t *Table) Current() *Snapshot { return t.cur }"},
			{old: "func (t *Table) Rev() uint64 { return t.cur.Load().Rev() }",
				new: "func (t *Table) Rev() uint64 { return t.cur.Rev() }"},
			{old: "sel, _ := t.cur.Load().Lookup(meta.Host, meta.SNI)",
				new: "sel, _ := t.cur.Lookup(meta.Host, meta.SNI)"},
		},
		race: true,
	},

	// probe: расписание проб — нижняя ступень лестницы допуска.
	{
		name: "интервал проб не соблюдается: пробы идут каждый круг",
		file: "internal/probe/scheduler.go", test: "TestSchedulerRespectsInterval",
		old: "seen && now.Sub(last) < interval", new: "seen && now.Sub(last) < 0 && interval > 0",
	},
	{
		name: "деградированная цель проверяется не чаще обычной",
		file: "internal/probe/scheduler.go", test: "TestSchedulerProbesDegradedTargetSooner",
		old: "		if it.Degraded {\n			interval = s.cfg.DegradedInterval\n		}", new: "",
	},
	{
		name: "предел одновременных проб на цель снят",
		file: "internal/probe/scheduler.go", test: "TestSchedulerLimitsConcurrencyPerTarget",
		old: "			slot := perHost[it.Target]", new: "			slot := make(chan struct{}, len(due))",
	},
	{
		name: "разброс интервала проб убран",
		file: "internal/probe/scheduler.go", test: "TestSchedulerJitterStaysInBounds",
		old: "(rand.Float64()*2 - 1) * span", new: "0 * span * rand.Float64()",
	},
	{
		name: "проба идёт к цели радиуса вместо работающего имени",
		file: "internal/probe/scheduler.go", test: "TestSchedulerUsesHostForRequest",
		old: "	host := it.Host\n	if host == \"\" {\n		host = it.Target\n	}", new: "	host := it.Target",
	},

	// scoring: базовая линия цели — чем успех стратегии отличается от
	// доступности самой цели.
	{
		name: "кредит выдаётся без сравнения с базовой линией",
		file: "internal/scoring/table.go", test: "TestPromotionRequiresBaseline",
		old: "	if lower-baseline < t.cfg.BaselineMargin {", new: "	if false {",
	},
	{
		name: "отсутствие базовой линии считается нулевой: цель молча объявлена мёртвой",
		file: "internal/scoring/table.go", test: "TestPromotionRequiresBaseline",
		old: "	if !known {", new: "	if false {",
	},
	{
		name: "базовая линия сравнивается долей вместо верхней границы",
		file: "internal/scoring/table.go", test: "TestBaselineVolumeRegulatesItself",
		old: "	return wilsonUpperBound(e.Successes, e.Conclusive, t.cfg.ConfidenceZ), true",
		new: "	return float64(e.Successes) / float64(e.Conclusive), true",
	},
	{
		name: "базовая линия попадает в отбор стратегий",
		file: "internal/scoring/table.go", test: "TestBaselineStaysOutOfRanking",
		old: "		if k.IsBaseline() {\n			continue\n		}", new: "",
	},
	{
		name: "саму базовую линию можно повысить в стратегию",
		file: "internal/scoring/table.go", test: "TestBaselineIsNotPromotable",
		old: "	if k.IsBaseline() {", new: "	if false {",
	},

	// control: базовая проба в плане и приём базового наблюдения.
	{
		name: "базовая проба не попадает в план: исходы нечем истолковать",
		file: "internal/control/probeitems.go", test: "TestProbeItemsAlwaysIncludeBaseline",
		old: "		out = append(out, ProbeItem{\n			Target: target, Baseline: true,\n			Degraded: degraded, Reason: ProbeReasonBaseline,\n		})",
		new: "",
	},
	{
		name: "пустая стратегия сходит за базовую линию без признака",
		file: "internal/control/engine.go", test: "TestBaselineObservationValidation",
		old: "	case o.Baseline && o.StrategyID != \"\":\n\t\treturn errors.New(\"control: базовое наблюдение со стратегией\")\n\tcase !o.Baseline && o.StrategyID == \"\":",
		new: "	case false:\n\t\treturn errors.New(\"control: базовое наблюдение со стратегией\")\n\tcase false:",
	},
	{
		name: "базовая линия не видна в состоянии движка",
		file: "internal/control/status.go", test: "TestEngineWithholdsCreditOnAvailableTarget",
		old: "		ts.Baseline = e.baselineStatus(target)", new: "",
	},

	// control: свежесть файла состояния.
	{
		name: "файл состояния обновляется только при пересчёте снимка",
		file: "internal/control/engine.go", test: "TestStatusFileRefreshesBetweenReplans",
		old: "			e.publishStatusIfStale()", new: "",
	},
	{
		name: "наблюдение не помечает состояние изменившимся",
		file: "internal/control/engine.go", test: "TestStatusFileRefreshesBetweenReplans",
		old: "	e.statusStale = true", new: "",
	},
	{
		name: "состояние пишется по таймеру без проверки изменений",
		file: "internal/control/engine.go", test: "TestStatusFileNotRewrittenWhenNothingChanges",
		old: "	if !e.statusStale {", new: "	if false {",
	},

	// scoring, control: свежесть портфеля (5.9).
	{
		name: "свежесть берёт любое наблюдение вместо позднейшего",
		file: "internal/scoring/table.go", test: "TestEvidenceTakesLatestObservation",
		old: "		if e.Last.After(ev.Last) {\n			ev.Last = e.Last\n		}",
		new: "		ev.Last = e.Last",
	},
	{
		name: "сводка наблюдений не отличает чужую сеть",
		file: "internal/scoring/table.go", test: "TestEvidenceIgnoresOtherVantage",
		old: "		if k.StrategyID != id || k.VantageID != vantage {", new: "		if k.StrategyID != id {",
	},
	{
		name: "сводка выдаётся и для базовой линии",
		file: "internal/scoring/table.go", test: "TestEvidenceOfBaselineIsEmpty",
		old: "	if id == \"\" {\n		return ev\n	}", new: "",
	},
	{
		name: "число целей не попадает в портфель: сумма наблюдений вводит в заблуждение",
		file: "internal/control/status.go", test: "TestPortfolioCarriesFreshness",
		old: "			Targets:           ev.Targets,", new: "",
	},

	// control: повторы обращения к файлу состояния (Windows блокирует замену
	// файла, который читают).
	{
		name: "временная неудача обращения к файлу состояния не пережидается",
		file: "internal/control/statusfile.go", test: "TestRetryTransient",
		old: "		if err == nil || !transient(err) {", new: "		if true {",
	},
	{
		name: "постоянная неудача записи состояния повторяется впустую",
		file: "internal/control/statusfile.go", test: "TestRetryTransient",
		old: "		if err == nil || !transient(err) {", new: "		if err == nil {",
	},

	// control: распознавание занятого файла состояния (только Windows).
	{
		name: "занятый файл состояния не распознаётся как временная неудача",
		file: "internal/control/statusfile_windows.go", test: "TestTransientIORecognizesBusyFile",
		old:  "	return errno == errorSharingViolation || errno == errorLockViolation",
		new:  "	_ = errno\n\treturn false",
		goos: "windows",
	},
	{
		name: "отказ в доступе считается временной неудачей и прячет нехватку прав",
		file: "internal/control/statusfile_windows.go", test: "TestTransientIORecognizesBusyFile",
		old:  "	return errno == errorSharingViolation || errno == errorLockViolation",
		new:  "	return errno == errorSharingViolation || errno == errorLockViolation || errno == 5",
		goos: "windows",
	},

	// cmd: шов между пробой и контуром.
	{
		name: "признак базовой линии теряется по дороге от пробы к контуру",
		file: "cmd/evasion/probes.go", test: "TestProbeSinkPassesBaselineThrough",
		old: "		Baseline:   item.Baseline,", new: "",
	},
	{
		name: "приёмник проб принимает противоречивый план",
		file: "cmd/evasion/probes.go", test: "TestProbeSinkRejectsInconsistentPlan",
		old: "	case item.Baseline && item.StrategyID != \"\":", new: "	case false:",
	},

	// proxy: суждение об исходе соединения.
	{
		name: "исход не различает «нас оборвали» и «пользователь ушёл»",
		file: "internal/proxy/outcome.go", test: "TestClassifyConn",
		old: "if !r.serverEndedFirst {", new: "if false {",
	},
	{
		name: "неприменённая стратегия считается проверенной",
		file: "internal/proxy/outcome.go", test: "TestClassifyConn",
		old: "if !applied {", new: "if false {",
	},
	{
		name: "первый байт ответа не запоминается",
		file: "internal/proxy/outcome.go", test: "TestDownstreamWatcher",
		old: "if n > 0 && !w.got {", new: "if false {",
	},
}

func main() {
	run := harness.NewRun(
		"tests-can-fail-under-mutation",
		"каждый тест из батареи обязан упасть при соответствующей мутации кода")
	defer run.Finish()

	// Охрана исходников ставится до первой правки файла и снимается после
	// последней: прерывание с клавиатуры не должно оставлять мутацию в
	// репозитории.
	watchSignals()
	defer func() {
		if restored := restoreAll(); len(restored) > 0 {
			// Сюда попадаем только при аварийном выходе из середины батареи:
			// обычный путь снимает охрану в apply. Поэтому это сообщение —
			// признак неполадки, а не отчёт о нормальной работе.
			run.Fact("исходники возвращены после аварийного выхода: %s",
				strings.Join(restored, ", "))
		}
	}()

	root, err := repoRoot()
	if err != nil {
		run.Fail("корень репозитория не найден: %v", err)
		return
	}

	// Перед работой убеждаемся, что зелены те пакеты, которые будем портить:
	// иначе падение теста при мутации ничего не докажет — он мог падать и до
	// неё.
	//
	// Проверяются именно они, а не весь репозиторий. Разница не в скорости:
	// в `go test ./...` входят прогоны прокси, занимающие порты, и случайный
	// конфликт порта выглядел бы как «тесты не зелёные до мутаций», то есть
	// батарея обвиняла бы код за чужую неудачу. Один такой провал уже был, и
	// причину пришлось искать вручную.
	for _, pkg := range mutatedPackages() {
		if out, err := goTest(root, pkg, "", false); err != nil {
			run.Fail("пакет %s не зелёный ДО мутаций, проверка бессмысленна:\n%s", pkg, tail(out, 20))
			// Самая частая причина — след прерванного прогона батареи, а не
			// дефект кода. Отличить это глазами трудно: мутация выглядит
			// обычной строкой кода, а падение — обычным падением теста.
			// Поэтому называем подозреваемых прямо, с командой восстановления.
			if dirty := dirtyMutatedFiles(root); len(dirty) > 0 {
				run.Fact("ВНИМАНИЕ: в мутируемых файлах есть несохранённые правки — "+
					"возможно, их оставил прерванный прогон батареи (Ctrl+C не выполняет "+
					"восстановление в прежних версиях прогона):\n  %s",
					strings.Join(dirty, "\n  "))
				run.Fact("восстановить: git checkout -- %s", strings.Join(dirty, " "))
			}
			return
		}
	}
	run.Step("исходное состояние: мутируемые пакеты зелёные (%s)",
		strings.Join(mutatedPackages(), ", "))

	var decorative, unapplied, skipped int
	for _, m := range mutations {
		if m.goos != "" && m.goos != runtime.GOOS {
			skipped++
			run.Step("пропущена (нужна %s): %s", m.goos, m.name)
			continue
		}
		res := apply(root, m)
		switch res {
		case resultCaught:
			run.Step("поймана: %s", m.name)
		case resultDecorative:
			decorative++
			run.Fail("ТЕСТ НЕ ЗАМЕТИЛ мутацию «%s» (%s): он проходит при сломанном коде", m.name, m.test)
		case resultNotApplied:
			unapplied++
			run.Fail("мутация «%s» не применилась: текст в %s изменился, батарею надо обновить", m.name, m.file)
		case resultBuildFail:
			unapplied++
			run.Fail("мутация «%s» не собралась: проверка не состоялась", m.name)
		case resultTestMissing:
			unapplied++
			run.Fail("мутация «%s» указывает на тест %s, которого нет в пакете %s: "+
				"тест не запускался вовсе, и мутация ничего не проверила "+
				"(обычная причина — тест лежит в другом пакете)",
				m.name, m.test, "./"+filepath.ToSlash(filepath.Dir(m.file)))
		}
	}

	run.Fact("мутаций в батарее: %d", len(mutations))
	run.Fact("поймано: %d, декоративных тестов: %d, неприменимых мутаций: %d, пропущено по платформе: %d",
		len(mutations)-decorative-unapplied-skipped, decorative, unapplied, skipped)
	if skipped > 0 {
		// Пропуск — не провал, но и не успех: эти свойства проверены не здесь.
		// Молчать о них нельзя, иначе зелёный прогон в песочнице читался бы
		// как полная проверка.
		run.Fact("ВНИМАНИЕ: %d мутаций проверяются только на своей платформе — "+
			"зелёный прогон здесь не доказывает их свойств", skipped)
	}
}

// dirtyMutatedFiles возвращает мутируемые файлы, изменённые относительно
// индекса git.
//
// Спрашиваем git, а не сравниваем содержимое сами: батарея не знает, как
// должен выглядеть неиспорченный файл, а git знает. Если git недоступен или
// каталог не репозиторий, молча возвращаем пустой список — это диагностика,
// и падать из-за её недоступности прогон не вправе.
func dirtyMutatedFiles(root string) []string {
	files := make(map[string]bool, len(mutations))
	for _, m := range mutations {
		files[filepath.ToSlash(m.file)] = true
	}

	cmd := exec.Command("git", "status", "--porcelain", "--")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var dirty []string
	for _, line := range strings.Split(string(out), "\n") {
		// Формат: два знака состояния, пробел, путь. Пути git отдаёт со
		// слэшами на любой платформе, поэтому сравнение прямое.
		if len(line) < 4 {
			continue
		}
		name := strings.TrimSpace(line[2:])
		if files[name] {
			dirty = append(dirty, name)
		}
	}
	sort.Strings(dirty)
	return dirty
}

// mutatedPackages возвращает пакеты, которые портит батарея, в устойчивом
// порядке: вывод прогона обязан быть воспроизводимым.
func mutatedPackages() []string {
	seen := make(map[string]bool, len(mutations))
	var out []string
	for _, m := range mutations {
		pkg := "./" + filepath.ToSlash(filepath.Dir(m.file))
		if !seen[pkg] {
			seen[pkg] = true
			out = append(out, pkg)
		}
	}
	sort.Strings(out)
	return out
}

// Исходы одной мутации.
type result int

const (
	resultCaught     result = iota // тест упал, как и должен
	resultDecorative               // тест прошёл при сломанном коде
	resultNotApplied               // текст не найден: батарея устарела
	resultBuildFail                // мутация не собралась
	// resultTestMissing — тест вообще не запускался: его нет в пакете,
	// который портит мутация.
	//
	// Отдельный исход, а не разновидность декоративного, и различие
	// принципиально. `go test -run` без совпадений завершается успешно, то
	// есть выглядит точно как пройденный тест, — и батарея объявляла такую
	// мутацию «не замеченной тестом». Диагноз уводил в сторону: человек шёл
	// проверять тест, который на самом деле лежит в другом пакете.
	//
	// Поймано на себе: тесты сводки наблюдений я положил в пакет control, а
	// мутацию — в internal/scoring/table.go. Батарея гоняла тесты scoring, не
	// находила там этих имён и докладывала о двух декоративных тестах.
	resultTestMissing
)

// guarded — файлы, испорченные прямо сейчас, и их исходное содержимое.
//
// Нужен возврату по сигналу. Через defer файл восстанавливается при обычном
// завершении и при панике, но **не при Ctrl+C**: по сигналу Go завершает
// процесс, не выполняя отложенных вызовов. Этим и кончилось: прерванный прогон
// оставил в internal/control/decide.go две мутации, они пережили несколько
// git pull (ни один коммит тот файл не трогал), и через сессию проявились как
// три «падения тестов на Windows», которых в песочнице не было.
var (
	guardMu sync.Mutex
	guarded = map[string][]byte{}
)

// guard запоминает исходное содержимое файла перед порчей.
func guard(path string, orig []byte) {
	guardMu.Lock()
	defer guardMu.Unlock()
	guarded[path] = orig
}

// unguard снимает файл с охраны: он уже восстановлен.
func unguard(path string) {
	guardMu.Lock()
	defer guardMu.Unlock()
	delete(guarded, path)
}

// restoreAll возвращает все испорченные файлы в прежний вид.
//
// Вызывается и по сигналу, и в конце прогона. Повторный вызов безвреден:
// восстановленные файлы с охраны снимаются.
func restoreAll() []string {
	guardMu.Lock()
	defer guardMu.Unlock()
	var restored []string
	for path, orig := range guarded {
		if err := os.WriteFile(path, orig, 0o644); err == nil {
			restored = append(restored, path)
		} else {
			// Сообщить важнее, чем вернуть код ошибки: файл остался
			// испорченным, и человек обязан узнать об этом немедленно, иначе
			// мутация уедет в коммит.
			fmt.Fprintf(os.Stderr, "НЕ УДАЛОСЬ ВОССТАНОВИТЬ %s: %v\n", path, err)
		}
		delete(guarded, path)
	}
	sort.Strings(restored)
	return restored
}

// watchSignals возвращает испорченные файлы при прерывании с клавиатуры.
//
// Без этого Ctrl+C оставляет репозиторий с внесённой мутацией — и выясняется
// это не сразу, а когда тесты начинают падать «без причины» через сессию или
// две. Диагностика при этом уводит в сторону: падение выглядит дефектом кода,
// а не следом прерванного прогона.
func watchSignals() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-ch
		restored := restoreAll()
		fmt.Fprintf(os.Stderr, "\nпрогон прерван (%v); исходники возвращены: %d\n",
			sig, len(restored))
		for _, p := range restored {
			fmt.Fprintf(os.Stderr, "  %s\n", p)
		}
		// Код 130 — обычный код для прерывания с клавиатуры.
		os.Exit(130)
	}()
}

// apply вносит мутацию, гоняет тест и возвращает исходник в прежний вид.
//
// Возврат идёт через defer с чтением исходного содержимого в память: так файл
// восстановится при обычном завершении и при панике. Прерывание с клавиатуры
// defer не выполняет, поэтому файл дополнительно ставится под охрану
// (см. guard и watchSignals).
func apply(root string, m mutation) result {
	path := filepath.Join(root, m.file)
	orig, err := os.ReadFile(path)
	if err != nil {
		return resultNotApplied
	}
	guard(path, orig)
	defer func() {
		_ = os.WriteFile(path, orig, 0o644)
		unguard(path)
	}()

	// Образцы записаны с переводами строк в стиле Unix, а на Windows файлы
	// лежат с CRLF: многострочные образцы там просто не находились, и батарея
	// докладывала «текст изменился», хотя изменился лишь конец строки. На
	// машине владельца так провалились три мутации из двадцати трёх.
	text := string(orig)
	crlf := strings.Contains(text, "\r\n")

	if !strings.Contains(text, eol(m.old, crlf)) {
		return resultNotApplied
	}
	mutated := strings.Replace(text, eol(m.old, crlf), eol(m.new, crlf), 1)
	for _, e := range m.extra {
		if !strings.Contains(mutated, eol(e.old, crlf)) {
			return resultNotApplied
		}
		mutated = strings.Replace(mutated, eol(e.old, crlf), eol(e.new, crlf), 1)
	}
	if err := os.WriteFile(path, []byte(mutated), 0o644); err != nil {
		return resultNotApplied
	}

	pkg := "./" + filepath.ToSlash(filepath.Dir(m.file))
	out, err := goTest(root, pkg, m.test, m.race)
	switch {
	case testDidNotRun(out):
		// Тест не запускался вовсе: его имени нет в этом пакете. Проверяется
		// раньше прочего, потому что `go test -run` без совпадений завершается
		// успешно и неотличим от пройденного теста.
		return resultTestMissing
	case err == nil:
		return resultDecorative
	case strings.Contains(out, "build failed"),
		strings.Contains(out, "undefined:"),
		strings.Contains(out, "syntax error"),
		strings.Contains(out, "declared and not used"):
		return resultBuildFail
	case m.race && !strings.Contains(out, "DATA RACE"):
		// Под детектором гонок мутация обязана дать именно гонку. Падение по
		// другой причине доказывало бы другое свойство, а не то, ради
		// которого здесь стоит атомарный указатель.
		return resultDecorative
	default:
		return resultCaught
	}
}

// testDidNotRun сообщает, что под выражение -run не подошёл ни один тест.
//
// Go в этом случае завершается успешно и печатает предупреждение, то есть
// внешне ведёт себя как пройденный тест. Без этой проверки опечатка в имени
// теста или тест, лежащий в другом пакете, читались бы как «тест не заметил
// мутацию» — диагноз, уводящий в сторону.
//
// Опора на текст предупреждения, а не на код возврата: кода у этого случая
// нет. Проверяются обе формулировки, которые встречаются в выводе Go.
func testDidNotRun(out string) bool {
	return strings.Contains(out, "no tests to run") ||
		strings.Contains(out, "warning: no tests to run")
}

// eol приводит переводы строк образца к тем, что в файле.
//
// Образцы в батарее записаны по-unix, потому что так их читать удобнее. Файл
// же лежит так, как его положил git на этой машине, и подменять его стиль
// нельзя: мутация обязана менять смысл кода, а не концы строк.
func eol(s string, crlf bool) string {
	if !crlf {
		return s
	}
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// goTest гоняет тесты пакета и возвращает вывод.
func goTest(root, pkg, run string, race bool) (string, error) {
	args := []string{"test", "-count=1", "-timeout", "180s"}
	if race {
		args = append(args, "-race")
	}
	if run != "" {
		args = append(args, "-run", run)
	}
	args = append(args, pkg)

	cmd := exec.Command("go", args...)
	cmd.Dir = root
	if race {
		// Детектору гонок нужен CGO; в остальных прогонах он не нужен и
		// только замедляет сборку.
		cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// repoRoot поднимается от рабочего каталога до go.mod.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod не найден выше %s", dir)
		}
		dir = parent
	}
}

// tail возвращает последние n строк вывода: начало обычно не нужно, а полный
// вывод `go test ./...` в отчёте мешает.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
