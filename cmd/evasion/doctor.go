package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/fitting-1c/evasion/internal/control"
	"github.com/fitting-1c/evasion/internal/enginelock"
	"github.com/fitting-1c/evasion/internal/interception"
	"github.com/fitting-1c/evasion/internal/quicwatch"
	"github.com/fitting-1c/evasion/internal/vantage"
)

// doctor отвечает на вопрос «почему не работает» (5.9) и отвечает честно: прямо
// называет, чего она проверить не может. Структура вывода — согласованный с
// владельцем контракт (см. журнал): у каждой проверки одно из пяти состояний, а
// сводка checks[] ВЫВОДИТСЯ из типизированных полей одной функцией, чтобы
// знание не раздвоилось. Состояние движка вкладывается целиком, а не
// пересказывается: у проекта есть шрам от двух наборов одного знания.

// controlReachTimeout — предел на установку соединения с контрольной целью.
//
// Контрольная цель обязана работать всегда (4.5), поэтому её молчание дольше
// этого срока — само по себе находка, а не повод ждать. То же значение, что
// верхняя граница срока пробы: связность меряется тем же способом.
const controlReachTimeout = 8 * time.Second

// httpsPort — порт по умолчанию для целей, заданных голым именем. Связность
// меряется рукопожатием TCP к 443: именно этот порт несёт TLS.
const httpsPort = "443"

// checkStatus — одно из пяти состояний проверки.
//
// Пять, а не признак «хорошо/плохо»: «опрос не удался» (unknown) и «на этом
// этапе не проверяется» (not_applicable) — разные ответы, и оба отличны от
// «плохо». not_applicable прямо исполняет требование показывать недоступные
// проверки строкой, а не молчанием.
type checkStatus string

const (
	statusOK            checkStatus = "ok"
	statusWarn          checkStatus = "warn"
	statusFail          checkStatus = "fail"
	statusUnknown       checkStatus = "unknown"
	statusNotApplicable checkStatus = "not_applicable"
)

// Машинные токены причин. Это данные, а не представление (2.2): интерфейс строит
// по ним свою формулировку. Человекочитаемый вывод их тоже печатает — на этапе
// 0 CLI единственный потребитель, и прятать токен за переводом незачем.
const (
	reasonPlatformCannotCheck = "platform_cannot_check"
	reasonNoControlTargets    = "no_control_targets"
	reasonAllUnreachable      = "control_targets_unreachable"
	reasonSomeUnreachable     = "some_control_targets_unreachable"
	reasonFingerprintMissing  = "network_fingerprint_unavailable"
	reasonEngineNotRunning    = "engine_not_running"
	reasonEngineUnreadable    = "engine_state_unreadable"
	reasonBlackout            = "blackout"
	reasonRevalidationNeeded  = "revalidation_needed"
	reasonInterceptorRunning  = "interceptor_running"
	reasonSearchIncomplete    = "search_incomplete"
	reasonWindowsOnly         = "windows_only"
	reasonRequiresIntercept   = "requires_intercept_mode"
	reasonQUICInactive        = "quic_blocking_inactive"
	reasonQUICOnlyApps        = "quic_only_apps"
	reasonQUICUnreadable      = "quic_state_unreadable"
)

// check — вердикт одной проверки для сводки.
//
// Поля только вердиктные (id, состояние, причина). Подробности лежат в
// типизированных секциях отчёта, а сюда сворачиваются функцией buildChecks:
// состояние хранится в одном месте, а сводка из него выводится. Так интерфейс
// рисует обзор циклом, подробности берёт по id.
type check struct {
	ID     string      `json:"id"`
	Status checkStatus `json:"status"`
	// Reason — машинный токен причины; пусто у состояния ok.
	Reason string `json:"reason,omitempty"`
}

// doctorReport — машинно-читаемый итог проверки (2.2).
type doctorReport struct {
	// Stage — этап поставки. На этапе 0 только "proxy".
	Stage string `json:"stage"`
	// Checks — сводка вердиктов, выведенная из секций ниже.
	Checks []check `json:"checks"`

	// Privilege — права процесса и потребность в них по этапам.
	Privilege privilegeSection `json:"privilege"`
	// Vantage — точка наблюдения (6.1).
	Vantage vantageSection `json:"vantage"`
	// Connectivity — связность и RTT до контрольных целей (4.5).
	Connectivity connectivitySection `json:"connectivity"`
	// Engine — состояние движка, вложенное целиком, плюс вердикты doctor.
	Engine engineSection `json:"engine"`
	// Interception — конфликты с другими перехватчиками и границы поиска.
	Interception interceptionSection `json:"interception"`
	// QUIC — накопленный признак QUIC-only и ситуация с блокировкой QUIC (3.3).
	QUIC quicSection `json:"quic"`
	// Network — сетевые данные, относящиеся к недоступной на этапе 0 проверке
	// IPv6: наличие глобального адреса отдаётся данными, без внешних запросов.
	Network networkSection `json:"network"`
}

// privilegeSection — права процесса.
//
// Потребность задаётся данными, а не текстом: на этапе 0 права нужны только для
// raw-отправки фейков, которой в socketexec нет, поэтому запуск прав не требует.
type privilegeSection struct {
	Elevated       bool `json:"elevated"`
	Checked        bool `json:"checked"`
	RequiredStage0 bool `json:"required_stage0"`
	RequiredStage1 bool `json:"required_stage1"`
}

// vantageSection — точка наблюдения в выводе doctor.
type vantageSection struct {
	// Fields — машинно-читаемое описание из vantage.Describe.
	Fields map[string]string `json:"fields"`
	// NetworkDetectable — снят ли отпечаток интерфейсов. Ложь означает, что
	// смену сети обнаружить не удастся, а оценки прежней сети к новой
	// неприменимы — это обязано быть видно.
	NetworkDetectable bool `json:"network_detectable"`
}

// connectivitySection — связность с контрольными целями.
type connectivitySection struct {
	Targets []targetReach `json:"targets"`
	// BaseRTTMillis — наименьший RTT среди достижимых; nil, если ни одна не
	// ответила. Указатель, а не ноль: ноль означает «быстрее разрешения
	// таймера» (урок probe.pickMinRTT).
	BaseRTTMillis *int64 `json:"base_rtt_ms"`
}

// targetReach — связность с одной контрольной целью.
type targetReach struct {
	Target    string `json:"target"`
	Reachable bool   `json:"reachable"`
	RTTMillis int64  `json:"rtt_ms"`
	// Measured — RTT измерен (соединение установилось за ненулевое время).
	// Отличает «мгновенно» от «неизмеримо быстро».
	Measured bool   `json:"rtt_measured"`
	Err      string `json:"err,omitempty"`
}

// engineSection — состояние движка: вложено целиком плюс вердикты doctor.
//
// State вкладывается как есть (control.Status), а не пересказывается: пересказ
// завёл бы второй набор одного знания, а у проекта от этого шрам. doctor
// добавляет только вердикты, которых в состоянии нет: какие цели заблокированы,
// у каких нет базовой линии, и нужна ли перевалидация (5.9).
type engineSection struct {
	// Running — файл состояния найден и разобран. Ложь означает «не запущен
	// или другой --state-dir», а не пустоту как данные.
	Running bool `json:"running"`
	// Fixed — движок жив по engine.lock, но состояния не ведёт: фиксированный
	// режим без автопилота. State при этом nil.
	Fixed bool `json:"fixed,omitempty"`
	// Err — почему состояние не прочитано, кроме «файла нет». Пусто при «не
	// запущен»: это полноценный ответ, а не ошибка.
	Err string `json:"err,omitempty"`
	// State — состояние движка целиком; nil, если движок не запущен.
	State *control.Status `json:"state"`

	// DegradedTargets — цели, заблокированные прямо сейчас (базовая линия
	// измерена и ни одного успеха).
	DegradedTargets []string `json:"degraded_targets"`
	// WithoutBaseline — цели без измеренной базовой линии: по ним кандидаты не
	// повышаются, и это объяснимо только отсюда.
	WithoutBaseline []string `json:"without_baseline"`
	// RevalidationNeeded — у применяемой стратегии оценки затухли после долгого
	// перерыва, доверять им нельзя (5.9).
	RevalidationNeeded bool `json:"revalidation_needed"`
	// StaleAfter — порог устаревания оценок из конфига, строкой.
	StaleAfter string `json:"stale_after"`
}

// interceptionSection — конфликты с перехватчиками плюс границы поиска.
type interceptionSection struct {
	Result interception.Result `json:"result"`
	// KnownProcesses, KnownServices — что именно пакет умеет искать. Без них
	// «конфликтов не обнаружено» — утверждение без границ.
	KnownProcesses []string `json:"known_processes"`
	KnownServices  []string `json:"known_services"`
}

// quicSection — ситуация с QUIC: накопленный движком признак «только QUIC».
//
// Данные берутся из файла quic.json, который ведёт слой перехвата (его пишет не
// control: QUIC — этап 1, а control обязан не знать про него и не меняться между
// этапами, 4.7 п. 4). Поэтому проверка отвечает по реальным данным работающего
// движка, а не заглушкой: заглушка «requires_intercept» устарела, перехват есть.
type quicSection struct {
	// Active — файл quic.json прочитан, то есть блокировка QUIC работает и
	// копит признак. Ложь означает «блокировка выключена, либо движок не
	// запущен» — по файлу эти случаи не различить, и выдавать их за данные
	// нечего.
	Active bool `json:"active"`
	// Err — почему файл не прочитан, кроме «файла нет».
	Err string `json:"err,omitempty"`
	// Stats — накопленное по именам серверов; данные, по которым интерфейс
	// строит свой вид (2.2).
	Stats []quicwatch.SNIStat `json:"stats"`
	// QUICOnly — имена, работающие по признакам только по QUIC: для них
	// блокировка означает потерю связи, а не откат на TCP (3.3, 5.9).
	QUICOnly []string `json:"quic_only"`
}

// networkSection — сетевые данные для недоступной на этапе 0 проверки IPv6.
//
// Утечки по IPv6 в смысле 3.2 на этапе 0 не существует: прокси действует только
// на настроенные на него приложения (ограничение этапа 1.5.1, а не утечка).
// Поэтому сама проверка — not_applicable, но факт наличия глобального адреса
// отдаётся данными: он понадобится на этапе 1 и добыт без внешних запросов
// (6.2, 6.6), одним перечислением интерфейсов.
type networkSection struct {
	HasGlobalIPv6 bool `json:"has_global_ipv6"`
	Checked       bool `json:"checked"`
}

// doctorCommand собирает отчёт о состоянии окружения и движка.
//
// Код возврата согласован с владельцем (см. журнал): 0 — диагностика прошла
// (ok/warn/unknown/not_applicable); 1 — есть вердикт fail (на этапе 0 это
// недостижимость контрольных целей: без них движок слеп) либо сам doctor не
// отработал. warn нулевой намеренно: у владельца заблокированные цели и
// затухшие между запусками оценки — норма, и всегда ненулевой код не нёс бы
// информации.
func doctorCommand(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	var (
		configPath = fs.String("config", "", "путь к файлу конфигурации (JSON)")
		stateDir   = fs.String("state-dir", defaultStateDir, "каталог состояния движка")
		jsonOut    = fs.Bool("json", false, "машинно-читаемый вывод")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}

	rep := assembleReport(&configForDoctor{
		Vantage:             cfg.Vantage,
		ControlTargets:      cfg.ControlTargets,
		EstimatesStaleAfter: cfg.Autopilot.EstimatesStaleAfter,
	}, *stateDir, time.Now())

	if *jsonOut {
		if err := writeJSON(os.Stdout, rep); err != nil {
			return err
		}
	} else {
		printDoctor(os.Stdout, rep)
	}

	// Отчёт уже выведен: при вердикте fail выходим с кодом 1, но с показанным
	// отчётом. Это отличает «найден fail» (отчёт есть, код 1) от «сам doctor не
	// смог» (отчёта нет, ошибка возвращена выше и код 1 ставит main). os.Exit
	// минует defer stop() в main — на завершении процесса это безвредно.
	if exitCode(rep.Checks) != 0 {
		os.Exit(1)
	}
	return nil
}

// assembleReport собирает отчёт и выводит из него сводку checks[].
//
// now передаётся параметром: устаревание оценок считается относительно времени,
// и проверяемость требует управляемого «сейчас» (тот же приём, что в control).
func assembleReport(cfg *configForDoctor, stateDir string, now time.Time) doctorReport {
	rep := doctorReport{Stage: "proxy"}

	// Права: потребность по этапам — данные, а не измерение.
	elev, checked := elevated()
	rep.Privilege = privilegeSection{
		Elevated:       elev,
		Checked:        checked,
		RequiredStage0: false,
		RequiredStage1: true,
	}

	// Точка наблюдения: метка из конфига плюс отпечаток интерфейсов (6.2).
	van, verr := vantage.Detect(cfg.Vantage, vantage.SystemInterfaces())
	rep.Vantage = vantageSection{
		Fields:            van.Describe(),
		NetworkDetectable: verr == nil && van.Fingerprint != "",
	}

	// Связность: живой замер без стратегии по контрольным целям из конфига.
	var dialer net.Dialer
	reach := measureReach(context.Background(), dialer.DialContext, cfg.ControlTargets, controlReachTimeout)
	rep.Connectivity = connectivitySection{Targets: reach}
	if best, ok := minRTT(reach); ok {
		ms := best.Milliseconds()
		rep.Connectivity.BaseRTTMillis = &ms
	}

	// Состояние движка из файла, вложенное целиком, плюс вердикты.
	rep.Engine = engineSectionFrom(stateDir, cfg.EstimatesStaleAfter, now)

	// Конфликты с перехватчиками плюс границы поиска.
	rep.Interception = interceptionSection{
		Result:         interception.Find(),
		KnownProcesses: interception.KnownProcesses(),
		KnownServices:  interception.KnownServices(),
	}

	// QUIC-only: накопленный работающим движком признак из файла quic.json.
	rep.QUIC = quicSectionFrom(stateDir)

	// Наличие глобального адреса IPv6 — данные к недоступной проверке.
	has, nchecked := globalIPv6Present()
	rep.Network = networkSection{HasGlobalIPv6: has, Checked: nchecked}

	rep.Checks = buildChecks(rep)
	return rep
}

// configForDoctor — ровно то из конфига, что нужно doctor. Отдельный тип, чтобы
// сборку отчёта можно было проверить без чтения файла конфигурации.
type configForDoctor struct {
	Vantage             vantage.Label
	ControlTargets      []string
	EstimatesStaleAfter time.Duration
}

// buildChecks выводит сводку вердиктов из типизированных секций.
//
// Единственное место, где рождается checks[]: иначе состояние оказалось бы в
// двух местах и со временем разошлось. Порядок проверок устойчив — интерфейс
// вправе на него опереться.
func buildChecks(rep doctorReport) []check {
	return []check{
		privilegeCheck(rep.Privilege),
		connectivityCheck(rep.Connectivity),
		vantageCheck(rep.Vantage),
		engineCheck(rep.Engine),
		interceptionCheck(rep.Interception),
		// Загрузка драйвера WinDivert и утечка IPv6 на этапе 0 недоступны:
		// присутствуют строкой с причиной, а не отсутствуют молча (5.9, 3.2).
		{ID: "windivert_driver", Status: statusNotApplicable, Reason: reasonRequiresIntercept},
		// QUIC отвечает по реальным данным работающего движка (3.3): заглушка
		// «requires_intercept» снята — перехват давно есть.
		quicCheck(rep.QUIC),
		{ID: "ipv6_leak", Status: statusNotApplicable, Reason: reasonRequiresIntercept},
	}
}

// quicCheck выводит вердикт по QUIC из накопленного признака.
//
// Файл нечитаем — unknown (сбой диагностики, не находка). Блокировка не пишет
// файл — not_applicable: выключена, либо движок не запущен, и притворяться, что
// с QUIC всё в порядке (ok), нельзя. Есть QUIC-only — warn, а не fail: признак
// по накоплению эвристичен (приложение могло просто не повторить запрос), и это
// повод проверить, а не отказ работать. Иначе ok.
func quicCheck(q quicSection) check {
	if q.Err != "" {
		return check{ID: "quic", Status: statusUnknown, Reason: reasonQUICUnreadable}
	}
	if !q.Active {
		return check{ID: "quic", Status: statusNotApplicable, Reason: reasonQUICInactive}
	}
	if len(q.QUICOnly) > 0 {
		return check{ID: "quic", Status: statusWarn, Reason: reasonQUICOnlyApps}
	}
	return check{ID: "quic", Status: statusOK}
}

// privilegeCheck: на этапе 0 права не требуются, поэтому их отсутствие не беда.
// Непроверяемость платформы — unknown, а не ok: «не проверили» и «проверили,
// всё хорошо» — разные ответы.
func privilegeCheck(p privilegeSection) check {
	if !p.Checked {
		return check{ID: "privilege", Status: statusUnknown, Reason: reasonPlatformCannotCheck}
	}
	return check{ID: "privilege", Status: statusOK}
}

// connectivityCheck: fail только когда недостижимы ВСЕ цели — тогда нет ни
// базового RTT, ни измерения вреда, и движок слеп. Часть недоступных — warn.
// Целей нет вовсе — unknown, а не ok: проверить было нечем.
func connectivityCheck(c connectivitySection) check {
	if len(c.Targets) == 0 {
		return check{ID: "connectivity", Status: statusUnknown, Reason: reasonNoControlTargets}
	}
	reachable := 0
	for _, t := range c.Targets {
		if t.Reachable {
			reachable++
		}
	}
	switch {
	case reachable == 0:
		return check{ID: "connectivity", Status: statusFail, Reason: reasonAllUnreachable}
	case reachable < len(c.Targets):
		return check{ID: "connectivity", Status: statusWarn, Reason: reasonSomeUnreachable}
	default:
		return check{ID: "connectivity", Status: statusOK}
	}
}

// vantageCheck: без отпечатка сети смену сети не обнаружить — это warn, а не
// ошибка: основной способ задания точки наблюдения (метка) от отпечатка не
// зависит.
func vantageCheck(v vantageSection) check {
	if !v.NetworkDetectable {
		return check{ID: "vantage", Status: statusWarn, Reason: reasonFingerprintMissing}
	}
	return check{ID: "vantage", Status: statusOK}
}

// engineCheck: незапущенный движок — unknown, а не fail (это не поломка
// окружения). Обвал портфеля и затухшие оценки — warn (у владельца это
// штатные состояния). Нечитаемый файл — unknown с отдельной причиной.
func engineCheck(e engineSection) check {
	if !e.Running {
		if e.Err != "" {
			return check{ID: "engine", Status: statusUnknown, Reason: reasonEngineUnreadable}
		}
		return check{ID: "engine", Status: statusUnknown, Reason: reasonEngineNotRunning}
	}
	if e.State != nil && e.State.Blackout {
		return check{ID: "engine", Status: statusWarn, Reason: reasonBlackout}
	}
	if e.RevalidationNeeded {
		return check{ID: "engine", Status: statusWarn, Reason: reasonRevalidationNeeded}
	}
	return check{ID: "engine", Status: statusOK}
}

// interceptionCheck: найденный сторонний перехватчик — warn, а не fail (это
// повод проверить обстановку, а не признак слепоты движка). Неприменимость
// платформы — not_applicable. Неполный поиск — warn.
func interceptionCheck(i interceptionSection) check {
	r := i.Result
	if !r.Supported {
		return check{ID: "interception", Status: statusNotApplicable, Reason: reasonWindowsOnly}
	}
	for _, t := range r.Tools {
		// Драйвер без процесса обхода — сведение, а не конфликт (IsDriver).
		if !t.IsDriver() {
			return check{ID: "interception", Status: statusWarn, Reason: reasonInterceptorRunning}
		}
	}
	if r.Partial {
		return check{ID: "interception", Status: statusWarn, Reason: reasonSearchIncomplete}
	}
	return check{ID: "interception", Status: statusOK}
}

// exitCode выводит код возврата из сводки: 1 при любом вердикте fail, иначе 0.
func exitCode(checks []check) int {
	for _, c := range checks {
		if c.Status == statusFail {
			return 1
		}
	}
	return 0
}

// engineSectionFrom читает файл состояния и сворачивает его в секцию движка.
func engineSectionFrom(stateDir string, staleAfter time.Duration, now time.Time) engineSection {
	es := engineSection{
		StaleAfter:      staleAfter.String(),
		DegradedTargets: []string{},
		WithoutBaseline: []string{},
	}

	st, err := readStatusFile(stateDir)
	if err != nil {
		if isNotRunning(err) {
			// Файл состояния пишет только автопилот; фиксированный режим виден
			// лишь по engine.lock.
			live, _ := enginelock.ListLive(filepath.Join(stateDir, "engine.lock"), nil)
			es.Running = len(live) > 0
			es.Fixed = es.Running
			return es
		}
		es.Err = err.Error()
		return es
	}

	es.Running = true
	es.State = &st
	es.DegradedTargets = degradedTargets(st.Targets)
	es.WithoutBaseline = withoutBaseline(st.Targets)
	es.RevalidationNeeded = revalidationNeeded(st.Portfolio, staleAfter, now)
	return es
}

// quicSectionFrom читает файл quic.json и сворачивает его в секцию QUIC.
//
// Отсутствие файла — не ошибка: блокировка QUIC его не ведёт (выключена, либо
// движок не запущен). Пороги эвристики берутся из quicwatch.DefaultParams():
// это диагностический порог без второго потребителя, в конфиг пока не вынесен.
func quicSectionFrom(stateDir string) quicSection {
	qs := quicSection{Stats: []quicwatch.SNIStat{}, QUICOnly: []string{}}

	rep, err := quicwatch.ReadFile(filepath.Join(stateDir, quicFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return qs // Active = false, без ошибки.
		}
		qs.Err = err.Error()
		return qs
	}

	qs.Active = true
	if len(rep.SNIs) > 0 {
		qs.Stats = rep.SNIs
	}
	if only := rep.QUICOnly(quicwatch.DefaultParams()); len(only) > 0 {
		qs.QUICOnly = only
	}
	return qs
}

// readStatusFile читает состояние напрямую, без дружелюбной подмены ошибки,
// которую делает readStatus: doctor обязан различать «не запущен» и «не
// прочитан».
func readStatusFile(dir string) (control.Status, error) {
	return control.ReadStatusFile(filepath.Join(dir, statusFileName))
}

// isNotRunning сообщает, что состояние отсутствует потому, что движок не
// запущен, а не из-за сбоя чтения.
func isNotRunning(err error) bool {
	return os.IsNotExist(errUnwrap(err))
}

// degradedTargets возвращает цели, заблокированные прямо сейчас.
//
// Признак — измеренная базовая линия без единого успеха. Known отделяет это от
// незнания: «заблокирована наглухо» и «о цели ничего не известно» — разные
// состояния, и второе в деградацию писать нельзя.
func degradedTargets(targets []control.TargetStatus) []string {
	out := []string{}
	for _, t := range targets {
		if t.Baseline.Known && t.Baseline.Observations > 0 && t.Baseline.Successes == 0 {
			out = append(out, t.Target)
		}
	}
	return out
}

// withoutBaseline возвращает цели без измеренной базовой линии. По ним
// кандидаты не повышаются (нет превосходства над базовой линией), и объяснить
// это можно только отсюда.
func withoutBaseline(targets []control.TargetStatus) []string {
	out := []string{}
	for _, t := range targets {
		if !t.Baseline.Known {
			out = append(out, t.Target)
		}
	}
	return out
}

// revalidationNeeded сообщает, затухли ли оценки хоть у одной применяемой
// стратегии (5.9).
//
// Учитываются только допущенные к трафику (ServesLiveTraffic) и только с
// давними наблюдениями: стратегия без наблюдений не «устарела», а ещё не
// измерена, а затухшая оценка выведенной стратегии ничего не портит.
func revalidationNeeded(holdings []control.HoldingStatus, staleAfter time.Duration, now time.Time) bool {
	for _, h := range holdings {
		if h.LastObservation.IsZero() {
			continue
		}
		if h.Status.ServesLiveTraffic() && now.Sub(h.LastObservation) > staleAfter {
			return true
		}
	}
	return false
}

// measureReach проверяет связность с целями по рукопожатию TCP и измеряет RTT.
//
// dial передаётся параметром, чтобы связность проверялась без выхода в сеть.
// Голое имя дополняется портом 443.
func measureReach(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), targets []string, timeout time.Duration) []targetReach {
	out := make([]targetReach, 0, len(targets))
	for _, t := range targets {
		addr := ensurePort(t, httpsPort)
		dctx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		conn, err := dial(dctx, "tcp", addr)
		elapsed := time.Since(start)
		cancel()

		tr := targetReach{Target: addr}
		if err != nil {
			tr.Err = err.Error()
			out = append(out, tr)
			continue
		}
		_ = conn.Close()
		tr.Reachable = true
		// Ноль означает «быстрее разрешения таймера»: связь есть, но время
		// неизмеримо. Записать это измеренным нулём нельзя — выглядело бы
		// мгновенной связью при отсутствии данных.
		if elapsed > 0 {
			tr.RTTMillis = elapsed.Milliseconds()
			tr.Measured = true
		}
		out = append(out, tr)
	}
	return out
}

// minRTT выбирает наименьший измеренный RTT среди достижимых целей.
//
// Наименьшее, а не среднее: интересует свойство канала, а единственная задержка
// завысила бы оценку. Неизмеренные (нулевые) пропускаются.
func minRTT(reach []targetReach) (time.Duration, bool) {
	var best time.Duration
	found := false
	for _, r := range reach {
		if !r.Reachable || !r.Measured {
			continue
		}
		d := time.Duration(r.RTTMillis) * time.Millisecond
		if !found || d < best {
			best = d
			found = true
		}
	}
	return best, found
}

// ensurePort дополняет цель портом по умолчанию, если порт не задан.
func ensurePort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, port)
}

// globalIPv6Present сообщает, есть ли у машины глобальный адрес IPv6.
//
// Без внешних запросов — одним перечислением интерфейсов (6.6). ULA (fc00::/7)
// и адреса канала не считаются глобальными: IsGlobalUnicast в паре с IsPrivate
// отсекают их. Второе значение — удалось ли перечислить интерфейсы вообще: отказ
// не то же самое, что «глобального адреса нет».
func globalIPv6Present() (present bool, checked bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, false
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		// Только IPv6: у IPv4-адреса To4 не nil.
		if ip == nil || ip.To4() != nil {
			continue
		}
		if ip.IsGlobalUnicast() && !ip.IsPrivate() {
			present = true
		}
	}
	return present, true
}

// printDoctor выводит отчёт человекочитаемо.
//
// Отдельная ветка форматирования: подписи и порядок живут только здесь и на
// структуру --json не влияют (2.3). Токены причин печатаются как есть — на
// этапе 0 CLI единственный потребитель.
func printDoctor(w io.Writer, rep doctorReport) {
	fmt.Fprintf(w, "этап: %s\n\nсводка:\n", rep.Stage)
	for _, c := range rep.Checks {
		if c.Reason == "" {
			fmt.Fprintf(w, "  %-16s %s\n", c.ID, c.Status)
		} else {
			fmt.Fprintf(w, "  %-16s %s (%s)\n", c.ID, c.Status, c.Reason)
		}
	}

	// Права.
	switch {
	case !rep.Privilege.Checked:
		fmt.Fprintf(w, "\nправа: проверка недоступна на этой платформе\n")
	case rep.Privilege.Elevated:
		fmt.Fprintf(w, "\nправа: администратор (на этапе 0 не требуются)\n")
	default:
		fmt.Fprintf(w, "\nправа: обычные (этапа 0 достаточно; этап 1 потребует администратора)\n")
	}

	// Точка наблюдения.
	v := rep.Vantage.Fields
	fmt.Fprintf(w, "точка наблюдения: id=%s оператор=%s регион=%s доступ=%s\n",
		v["id"], v["operator"], v["region"], v["access"])

	// Связность.
	fmt.Fprintf(w, "\nконтрольные цели:\n")
	if len(rep.Connectivity.Targets) == 0 {
		fmt.Fprintf(w, "  не заданы (control_targets пуст)\n")
	}
	for _, c := range rep.Connectivity.Targets {
		switch {
		case !c.Reachable:
			fmt.Fprintf(w, "  %s — НЕДОСТУПНА: %s\n", c.Target, c.Err)
		case c.Measured:
			fmt.Fprintf(w, "  %s — доступна, RTT %d мс\n", c.Target, c.RTTMillis)
		default:
			fmt.Fprintf(w, "  %s — доступна, RTT ниже разрешения таймера\n", c.Target)
		}
	}
	if rep.Connectivity.BaseRTTMillis != nil {
		fmt.Fprintf(w, "  базовый RTT: %d мс\n", *rep.Connectivity.BaseRTTMillis)
	}

	// Движок.
	fmt.Fprintf(w, "\nдвижок:\n")
	printEngine(w, rep.Engine)

	// Перехватчики.
	fmt.Fprintf(w, "\nсторонние перехватчики:\n")
	printInterception(w, rep.Interception)

	// QUIC.
	fmt.Fprintf(w, "\nQUIC:\n")
	printQUIC(w, rep.QUIC)

	// Наличие глобального IPv6 — к недоступной на этапе 0 проверке утечки.
	if rep.Network.Checked {
		fmt.Fprintf(w, "\nглобальный адрес IPv6: %s (проверка утечки — этап 1)\n", yesNo(rep.Network.HasGlobalIPv6))
	}
}

// printEngine выводит состояние движка человекочитаемо.
func printEngine(w io.Writer, e engineSection) {
	if !e.Running {
		if e.Err != "" {
			fmt.Fprintf(w, "  состояние не прочитано: %s\n", e.Err)
			return
		}
		fmt.Fprintf(w, "  не запущен (или запущен с другим --state-dir)\n")
		return
	}
	if e.Fixed {
		fmt.Fprintf(w, "  запущен в фиксированном режиме (состояние ведёт только --auto)\n")
		return
	}
	st := e.State
	fmt.Fprintf(w, "  снимок №%d, решения от %s, данные от %s\n",
		st.SnapshotRev, st.PlannedAt.Format(time.RFC3339), st.UpdatedAt.Format(time.RFC3339))
	if st.Blackout {
		fmt.Fprintf(w, "  ТРЕВОГА: полный обвал портфеля\n")
	}
	if e.RevalidationNeeded {
		fmt.Fprintf(w, "  ВНИМАНИЕ: оценки затухли (старше %s) — нужна перевалидация\n", e.StaleAfter)
	}
	if len(e.DegradedTargets) > 0 {
		fmt.Fprintf(w, "  заблокированы сейчас: %s\n", joinComma(e.DegradedTargets))
	}
	if len(e.WithoutBaseline) > 0 {
		fmt.Fprintf(w, "  без базовой линии: %s\n", joinComma(e.WithoutBaseline))
	}
	if len(st.Portfolio) == 0 {
		fmt.Fprintf(w, "  портфель пуст\n")
		return
	}
	for _, p := range st.Portfolio {
		note := ""
		if p.LastObservation.IsZero() {
			note = " (наблюдений нет)"
		}
		fmt.Fprintf(w, "  %s %s: наблюдений %d по %d целям%s\n",
			short(p.StrategyID.String()), p.Status, p.Observations, p.Targets, note)
	}
}

// printInterception выводит находки по перехватчикам человекочитаемо.
func printInterception(w io.Writer, ir interceptionSection) {
	switch {
	case !ir.Result.Supported:
		fmt.Fprintf(w, "  поиск неприменим на этой платформе\n")
	case ir.Result.Clean():
		fmt.Fprintf(w, "  известных средств не обнаружено (проверено %d процессов, %d служб)\n",
			len(ir.KnownProcesses), len(ir.KnownServices))
	default:
		for _, t := range ir.Result.Tools {
			kind := "процесс"
			if t.Kind == interception.KindService {
				kind = "служба"
			}
			marker := ""
			if t.IsDriver() {
				marker = " (драйвер, не процесс обхода)"
			}
			fmt.Fprintf(w, "  обнаружен %s: %s%s\n", kind, t.Name, marker)
		}
	}
	if ir.Result.Partial {
		fmt.Fprintf(w, "  поиск неполон — часть средств могла остаться незамеченной:\n")
		for _, n := range ir.Result.Notes {
			fmt.Fprintf(w, "    %s\n", n)
		}
	}
}

// printQUIC выводит ситуацию с QUIC человекочитаемо.
func printQUIC(w io.Writer, q quicSection) {
	switch {
	case q.Err != "":
		fmt.Fprintf(w, "  состояние QUIC не прочитано: %s\n", q.Err)
		return
	case !q.Active:
		fmt.Fprintf(w, "  блокировка не активна (выключена, либо движок не запущен)\n")
		return
	}
	fmt.Fprintf(w, "  блокировка активна, под наблюдением имён: %d\n", len(q.Stats))
	if len(q.QUICOnly) > 0 {
		fmt.Fprintf(w, "  ВНИМАНИЕ: по признакам работают только по QUIC (блокировка = потеря связи, а не откат на TCP): %s\n",
			joinComma(q.QUICOnly))
	} else {
		fmt.Fprintf(w, "  приложений, работающих только по QUIC, не обнаружено\n")
	}
	for _, s := range q.Stats {
		fallback := "нет"
		if !s.LastTCPHello.IsZero() {
			fallback = s.LastTCPHello.Format(time.RFC3339)
		}
		fmt.Fprintf(w, "  %s: сброшено QUIC %d, последний TCP-откат %s\n", s.SNI, s.Drops, fallback)
	}
}

// joinComma соединяет имена запятой для человекочитаемого вывода.
func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
