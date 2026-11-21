package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/control"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/enginelock"
	"github.com/fitting-1c/evasion/internal/interception"
	"github.com/fitting-1c/evasion/internal/quicwatch"
)

// TestBuildChecksDerivesSummary — замок на вывод сводки из типизированных полей
// (решение владельца: состояние в одном месте, checks[] выводится из него).
// Проверяет и состав, и порядок: интерфейс вправе на порядок опереться.
func TestBuildChecksDerivesSummary(t *testing.T) {
	rep := doctorReport{
		Privilege:    privilegeSection{Checked: true},
		Connectivity: connectivitySection{Targets: []targetReach{{Target: "a", Reachable: true, Measured: true, RTTMillis: 10}}},
		Vantage:      vantageSection{NetworkDetectable: true},
		Engine:       engineSection{Running: true, State: &control.Status{}},
		Interception: interceptionSection{Result: interception.Result{Supported: true}},
	}
	checks := buildChecks(rep)

	wantOrder := []string{"privilege", "connectivity", "vantage", "engine", "interception", "windivert_driver", "quic", "ipv6_leak"}
	if len(checks) != len(wantOrder) {
		t.Fatalf("ожидалось %d проверок, получено %d", len(wantOrder), len(checks))
	}
	for i, id := range wantOrder {
		if checks[i].ID != id {
			t.Errorf("позиция %d: ожидался %q, получен %q", i, id, checks[i].ID)
		}
	}
	// Недоступные на этапе 0 проверки — not_applicable с причиной (5.9, 3.2).
	for _, id := range []string{"windivert_driver", "ipv6_leak"} {
		c := findCheck(t, checks, id)
		if c.Status != statusNotApplicable || c.Reason != reasonRequiresIntercept {
			t.Errorf("%s: ожидалось not_applicable/%s, получено %s/%s", id, reasonRequiresIntercept, c.Status, c.Reason)
		}
	}
	// QUIC без файла quic.json (блокировка не активна) — not_applicable со
	// своей причиной, а не заглушка requires_intercept.
	if c := findCheck(t, checks, "quic"); c.Status != statusNotApplicable || c.Reason != reasonQUICInactive {
		t.Errorf("quic: ожидалось not_applicable/%s, получено %s/%s", reasonQUICInactive, c.Status, c.Reason)
	}
}

// TestQUICCheckStates — вердикт по QUIC из накопленного признака: нечитаемо
// unknown, неактивно not_applicable, есть QUIC-only warn, иначе ok.
func TestQUICCheckStates(t *testing.T) {
	cases := []struct {
		name   string
		sec    quicSection
		status checkStatus
		reason string
	}{
		{"нечитаемо", quicSection{Err: "boom"}, statusUnknown, reasonQUICUnreadable},
		{"неактивно", quicSection{Active: false}, statusNotApplicable, reasonQUICInactive},
		{"только QUIC", quicSection{Active: true, QUICOnly: []string{"youtube.com"}}, statusWarn, reasonQUICOnlyApps},
		{"норма", quicSection{Active: true}, statusOK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := quicCheck(tc.sec)
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Errorf("ожидалось %s/%q, получено %s/%q", tc.status, tc.reason, got.Status, got.Reason)
			}
		})
	}
}

// TestQUICSectionFromReadsFile — секция QUIC читает quic.json и выводит
// QUIC-only; отсутствие файла — неактивна без ошибки.
func TestQUICSectionFromReadsFile(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Now()

	// Нет файла — блокировка не активна, ошибки нет.
	if qs := quicSectionFrom(dir); qs.Active || qs.Err != "" {
		t.Fatalf("без файла ожидалась неактивность без ошибки, получено %+v", qs)
	}

	// Имя с тремя сбросами и без TCP-отката — QUIC-only.
	rep := quicwatch.Report{SNIs: []quicwatch.SNIStat{{SNI: "youtube.com", Drops: 3, LastDrop: t0}}}
	if err := quicwatch.WriteFile(filepath.Join(dir, quicFileName), rep); err != nil {
		t.Fatalf("запись quic.json: %v", err)
	}
	qs := quicSectionFrom(dir)
	if !qs.Active {
		t.Fatalf("с файлом блокировка должна считаться активной")
	}
	if len(qs.QUICOnly) != 1 || qs.QUICOnly[0] != "youtube.com" {
		t.Errorf("ожидался QUIC-only youtube.com, получено %v", qs.QUICOnly)
	}
}

// TestConnectivityCheckStates закрепляет главное различение кода возврата: fail
// только при недостижимости ВСЕХ целей.
func TestConnectivityCheckStates(t *testing.T) {
	cases := []struct {
		name    string
		targets []targetReach
		status  checkStatus
		reason  string
	}{
		{"нет целей", nil, statusUnknown, reasonNoControlTargets},
		{"все недоступны", []targetReach{{Reachable: false}, {Reachable: false}}, statusFail, reasonAllUnreachable},
		{"часть недоступна", []targetReach{{Reachable: true}, {Reachable: false}}, statusWarn, reasonSomeUnreachable},
		{"все доступны", []targetReach{{Reachable: true}, {Reachable: true}}, statusOK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := connectivityCheck(connectivitySection{Targets: tc.targets})
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Errorf("ожидалось %s/%q, получено %s/%q", tc.status, tc.reason, got.Status, got.Reason)
			}
		})
	}
}

// TestEngineCheckStates — незапущенный движок unknown (не fail), обвал и
// затухание warn, нечитаемый файл unknown с отдельной причиной.
func TestEngineCheckStates(t *testing.T) {
	cases := []struct {
		name   string
		sec    engineSection
		status checkStatus
		reason string
	}{
		{"не запущен", engineSection{Running: false}, statusUnknown, reasonEngineNotRunning},
		{"нечитаем", engineSection{Running: false, Err: "boom"}, statusUnknown, reasonEngineUnreadable},
		{"обвал", engineSection{Running: true, State: &control.Status{Blackout: true}}, statusWarn, reasonBlackout},
		{"перевалидация", engineSection{Running: true, State: &control.Status{}, RevalidationNeeded: true}, statusWarn, reasonRevalidationNeeded},
		{"норма", engineSection{Running: true, State: &control.Status{}}, statusOK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := engineCheck(tc.sec)
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Errorf("ожидалось %s/%q, получено %s/%q", tc.status, tc.reason, got.Status, got.Reason)
			}
		})
	}
}

// TestInterceptionCheckStates — найденный перехватчик warn (не fail), драйвер
// без процесса конфликтом не считается, неприменимость платформы not_applicable.
func TestInterceptionCheckStates(t *testing.T) {
	proc := interception.Tool{Kind: interception.KindProcess, Name: "winws.exe"}
	driver := interception.Tool{Kind: interception.KindService, Name: "WinDivert"}

	cases := []struct {
		name   string
		res    interception.Result
		status checkStatus
		reason string
	}{
		{"не поддерживается", interception.Result{Supported: false}, statusNotApplicable, reasonWindowsOnly},
		{"чисто", interception.Result{Supported: true}, statusOK, ""},
		{"перехватчик", interception.Result{Supported: true, Tools: []interception.Tool{proc}}, statusWarn, reasonInterceptorRunning},
		{"только драйвер", interception.Result{Supported: true, Tools: []interception.Tool{driver}}, statusOK, ""},
		{"неполный поиск", interception.Result{Supported: true, Partial: true}, statusWarn, reasonSearchIncomplete},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := interceptionCheck(interceptionSection{Result: tc.res})
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Errorf("ожидалось %s/%q, получено %s/%q", tc.status, tc.reason, got.Status, got.Reason)
			}
		})
	}
}

// TestPrivilegeCheck — непроверяемость это unknown, а не ok.
func TestPrivilegeCheck(t *testing.T) {
	if c := privilegeCheck(privilegeSection{Checked: false}); c.Status != statusUnknown || c.Reason != reasonPlatformCannotCheck {
		t.Errorf("непроверено: ожидалось unknown/%s, получено %s/%s", reasonPlatformCannotCheck, c.Status, c.Reason)
	}
	if c := privilegeCheck(privilegeSection{Checked: true}); c.Status != statusOK {
		t.Errorf("проверено: ожидалось ok, получено %s", c.Status)
	}
}

// TestExitCodeFailOnly — код 1 только при вердикте fail; warn/unknown/
// not_applicable нулевые.
func TestExitCodeFailOnly(t *testing.T) {
	if got := exitCode([]check{{Status: statusWarn}, {Status: statusUnknown}, {Status: statusNotApplicable}, {Status: statusOK}}); got != 0 {
		t.Errorf("без fail ожидался 0, получено %d", got)
	}
	if got := exitCode([]check{{Status: statusWarn}, {Status: statusFail}}); got != 1 {
		t.Errorf("с fail ожидался 1, получено %d", got)
	}
}

// TestRevalidationNeeded — затухшими считаются только давние наблюдения у
// применяемых стратегий (5.9).
func TestRevalidationNeeded(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	stale := 12 * time.Hour

	active := control.HoldingStatus{Status: core.StatusActive, LastObservation: now.Add(-13 * time.Hour)}
	fresh := control.HoldingStatus{Status: core.StatusActive, LastObservation: now.Add(-1 * time.Hour)}
	never := control.HoldingStatus{Status: core.StatusActive}
	retired := control.HoldingStatus{Status: core.StatusRetired, LastObservation: now.Add(-48 * time.Hour)}

	if !revalidationNeeded([]control.HoldingStatus{active}, stale, now) {
		t.Errorf("давняя активная стратегия должна требовать перевалидации")
	}
	if revalidationNeeded([]control.HoldingStatus{fresh, never, retired}, stale, now) {
		t.Errorf("свежая/без наблюдений/выведенная перевалидации не требуют")
	}
}

// TestTargetVerdicts — заблокированные и без базовой линии цели выводятся из
// состояния.
func TestTargetVerdicts(t *testing.T) {
	targets := []control.TargetStatus{
		{Target: "blocked", Baseline: control.BaselineStatus{Known: true, Observations: 6, Successes: 0}},
		{Target: "alive", Baseline: control.BaselineStatus{Known: true, Observations: 6, Successes: 6}},
		{Target: "unknown", Baseline: control.BaselineStatus{Known: false}},
	}
	if d := degradedTargets(targets); len(d) != 1 || d[0] != "blocked" {
		t.Errorf("заблокированные: ожидалось [blocked], получено %v", d)
	}
	if wb := withoutBaseline(targets); len(wb) != 1 || wb[0] != "unknown" {
		t.Errorf("без базовой линии: ожидалось [unknown], получено %v", wb)
	}
}

// TestMeasureReachReachableAndNot — классификация связности и дополнение порта.
func TestMeasureReachReachableAndNot(t *testing.T) {
	dial := func(_ context.Context, _, addr string) (net.Conn, error) {
		if addr == "down.example:443" {
			return nil, errors.New("connection refused")
		}
		c, _ := net.Pipe()
		return c, nil
	}
	reach := measureReach(context.Background(), dial, []string{"up.example", "down.example"}, time.Second)
	if len(reach) != 2 {
		t.Fatalf("ожидалось 2 результата, получено %d", len(reach))
	}
	if reach[0].Target != "up.example:443" || !reach[0].Reachable {
		t.Errorf("up.example: ожидалась достижимость с портом 443, получено %+v", reach[0])
	}
	if reach[1].Reachable || reach[1].Err == "" {
		t.Errorf("down.example: ожидалась недостижимость с причиной, получено %+v", reach[1])
	}
}

// TestMeasureReachKeepsExplicitPort — заданный порт не подменяется.
func TestControlTargetsAcceptFirstReachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	slowStarted := make(chan struct{})
	slowStopped := make(chan struct{})
	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		switch addr {
		case "slow.example:443":
			close(slowStarted)
			<-ctx.Done()
			close(slowStopped)
			return nil, ctx.Err()
		case "fast.example:8443":
			select {
			case <-slowStarted:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			conn, peer := net.Pipe()
			_ = peer.Close()
			return conn, nil
		default:
			return nil, errors.New("unexpected target " + addr)
		}
	}
	if !checkControlTargets(ctx, dial, []string{"slow.example", "fast.example:8443"}) {
		t.Fatal("a reachable target was held behind an unreachable one")
	}
	select {
	case <-slowStopped:
	case <-ctx.Done():
		t.Fatal("slow dial was not canceled after success")
	}
}

func TestMeasureReachKeepsExplicitPort(t *testing.T) {
	dial := func(_ context.Context, _, _ string) (net.Conn, error) {
		c, _ := net.Pipe()
		return c, nil
	}
	reach := measureReach(context.Background(), dial, []string{"host.example:8443"}, time.Second)
	if reach[0].Target != "host.example:8443" {
		t.Fatalf("заданный порт изменён: %q", reach[0].Target)
	}
}

// TestMinRTTSkipsUnreachableAndUnmeasured — ноль это «неизмеримо быстро», в
// минимум не идёт (урок probe.pickMinRTT).
func TestMinRTTSkipsUnreachableAndUnmeasured(t *testing.T) {
	reach := []targetReach{
		{Reachable: false},
		{Reachable: true, Measured: false},
		{Reachable: true, Measured: true, RTTMillis: 40},
		{Reachable: true, Measured: true, RTTMillis: 120},
	}
	best, ok := minRTT(reach)
	if !ok || best != 40*time.Millisecond {
		t.Fatalf("ожидалось 40мс, получено %v (ok=%v)", best, ok)
	}
	if _, ok := minRTT([]targetReach{{Reachable: false}, {Reachable: true, Measured: false}}); ok {
		t.Errorf("при отсутствии измеримых целей минимума быть не должно")
	}
}

// TestEngineSectionFromNotRunning — отсутствие файла это «не запущен», без
// ошибки чтения.
func TestEngineSectionFromNotRunning(t *testing.T) {
	es := engineSectionFrom(t.TempDir(), 12*time.Hour, time.Now())
	if es.Running {
		t.Fatalf("без файла движок не запущен")
	}
	if es.Err != "" {
		t.Errorf("«не запущен» не должно нести ошибку чтения, получено %q", es.Err)
	}
	if es.State != nil {
		t.Errorf("без запуска состояние должно быть nil")
	}
	if es.StaleAfter == "" {
		t.Errorf("порог устаревания должен присутствовать независимо от запуска")
	}
}

// TestEngineSectionFromRunning — состояние вкладывается целиком и дополняется
// вердиктами.
func TestEngineSectionFromRunning(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()

	st := control.Status{
		SnapshotRev: 7,
		Targets: []control.TargetStatus{
			{Target: "blocked", Baseline: control.BaselineStatus{Known: true, Observations: 6, Successes: 0}},
			{Target: "unknown", Baseline: control.BaselineStatus{Known: false}},
		},
		Portfolio: []control.HoldingStatus{
			{StrategyID: core.StrategyID("a"), Status: core.StatusActive, LastObservation: now.Add(-13 * time.Hour), Observations: 30, Targets: 2},
		},
	}
	if err := control.WriteStatusFile(filepath.Join(dir, statusFileName), st); err != nil {
		t.Fatalf("запись состояния: %v", err)
	}

	es := engineSectionFrom(dir, 12*time.Hour, now)
	if !es.Running || es.State == nil {
		t.Fatalf("движок должен считаться запущенным с вложенным состоянием")
	}
	if es.State.SnapshotRev != 7 {
		t.Errorf("состояние вложено не целиком: номер снимка %d", es.State.SnapshotRev)
	}
	if !es.RevalidationNeeded {
		t.Errorf("активная стратегия старше порога — ожидалась перевалидация")
	}
	if len(es.DegradedTargets) != 1 || es.DegradedTargets[0] != "blocked" {
		t.Errorf("заблокированные: %v", es.DegradedTargets)
	}
	if len(es.WithoutBaseline) != 1 || es.WithoutBaseline[0] != "unknown" {
		t.Errorf("без базовой линии: %v", es.WithoutBaseline)
	}
}

// findCheck достаёт проверку по id.
func findCheck(t *testing.T, checks []check, id string) check {
	t.Helper()
	for _, c := range checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("проверка %q не найдена", id)
	return check{}
}

// TestEngineSectionFromFixedMode — фиксированный режим не пишет status.json:
// живой держатель engine.lock означает «запущен», а не engine_not_running.
func TestEngineSectionFromFixedMode(t *testing.T) {
	dir := t.TempDir()
	lock, err := enginelock.Acquire(enginelock.Options{Path: filepath.Join(dir, "engine.lock"), Filter: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	es := engineSectionFrom(dir, 12*time.Hour, time.Now())
	if !es.Running || !es.Fixed || es.State != nil {
		t.Fatalf("живой замок без status.json: running=%v fixed=%v state=%v", es.Running, es.Fixed, es.State)
	}
	if c := engineCheck(es); c.Status != statusOK {
		t.Errorf("ожидался ok, получено %s %s", c.Status, c.Reason)
	}
	var out bytes.Buffer
	printEngine(&out, es)

	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	if es := engineSectionFrom(dir, 12*time.Hour, time.Now()); es.Running {
		t.Errorf("после освобождения замка движок не запущен")
	}
}
