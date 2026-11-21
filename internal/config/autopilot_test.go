package config

import (
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/control"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/scoring"
)

// TestDefaultsMatchConsumers закрепляет главное свойство раздела: числа по
// умолчанию берутся у потребителей, а не повторяются в конфиге. Разойдись они —
// в движке оказалось бы два набора порогов, и какой из них действует,
// выяснялось бы опытным путём.
func TestDefaultsMatchConsumers(t *testing.T) {
	a := DefaultAutopilot()
	s := scoring.DefaultConfig()
	c := control.DefaultConfig()

	if a.Scoring() != s {
		t.Fatalf("конфигурация оценок по умолчанию разошлась с scoring.DefaultConfig:\n%+v\n%+v", a.Scoring(), s)
	}
	if a.Control() != c {
		t.Fatalf("конфигурация контура по умолчанию разошлась с control.DefaultConfig:\n%+v\n%+v", a.Control(), c)
	}
}

// TestDefaultsFollowTask проверяет сами значения по заданию (5.7). Это не
// пересказ кода: числа названы в задании, и тест ловит их тихое изменение.
func TestDefaultsFollowTask(t *testing.T) {
	a := DefaultAutopilot()
	for _, tc := range []struct {
		name string
		got  any
		want any
	}{
		{"полужизнь оценки", a.HalfLife, 6 * time.Hour},
		{"выдержка до смены", a.MinDwell, 15 * time.Minute},
		{"порог превосходства", a.SuperiorityMargin, 0.15},
		{"срыв по провалам", a.FailureStreak, 3},
		{"вес ok", a.WeightOK, 1.0},
		{"вес throttled", a.WeightThrottled, -0.7},
		{"вес fail", a.WeightFail, -1.0},
		{"вес inconclusive", a.WeightInconclusive, 0.0},
		{"вес пассивного наблюдения", a.WeightPassive, 0.3},
		{"нижняя граница объёма", a.MinObservations, 20},
		{"верхняя граница объёма", a.MaxObservations, 60},
		{"доля проверки", a.TrialPermille, 50},
		{"интервал проб", a.ProbeInterval, 12 * time.Minute},
		{"джиттер проб", a.ProbeJitter, 0.4},
		{"интервал проб при деградации", a.ProbeIntervalDegraded, 45 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("%s = %v, задание называет %v", tc.name, tc.got, tc.want)
			}
		})
	}
}

// TestZeroValuesInFileAreHonoured — нулевое значение в файле это настройка, а
// не незаполненное поле. Вес inconclusive равен нулю по заданию, и если бы
// разбор считал ноль «не задано», такую настройку нельзя было бы выразить
// вообще.
func TestZeroValuesInFileAreHonoured(t *testing.T) {
	cfg, err := parse([]byte(`{"autopilot": {"weight_inconclusive": 0, "trial_permille": 0}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Autopilot.WeightInconclusive != 0 {
		t.Fatal("нулевой вес должен сохраниться")
	}
	if cfg.Autopilot.TrialPermille != 0 {
		t.Fatal("нулевая доля проверки — законная настройка «не рисковать живым трафиком»")
	}
	// Остальные числа раздела при этом не обнулились.
	if cfg.Autopilot.HalfLife != DefaultAutopilot().HalfLife {
		t.Fatal("правка одного числа не должна обнулять остальные")
	}
}

func TestPartialSectionsKeepDefaults(t *testing.T) {
	cfg, err := parse([]byte(`{
		"autopilot": {"half_life": "2h", "min_dwell": "1m"},
		"parallelism": {"per_target": 1},
		"retention": {"rows": "72h"}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Autopilot.HalfLife != 2*time.Hour || cfg.Autopilot.MinDwell != time.Minute {
		t.Fatalf("заданные значения не применились: %+v", cfg.Autopilot)
	}
	if cfg.Autopilot.SuperiorityMargin != DefaultAutopilot().SuperiorityMargin {
		t.Fatal("незаданное значение должно остаться по умолчанию")
	}
	if cfg.Parallelism.PerTarget != 1 || cfg.Parallelism.Workers != DefaultParallelism().Workers {
		t.Fatalf("пределы параллельности = %+v", cfg.Parallelism)
	}
	if cfg.Retention.Rows != 72*time.Hour || cfg.Retention.Aggregates != DefaultRetention().Aggregates {
		t.Fatalf("сроки хранения = %+v", cfg.Retention)
	}
}

func TestDurationsAreStrings(t *testing.T) {
	// Числом продолжительность задать нельзя: единица измерения тогда
	// неочевидна, и ошибку в конфиге не видно глазами.
	if _, err := parse([]byte(`{"autopilot": {"half_life": 3600}}`)); err == nil {
		t.Fatal("продолжительность числом должна быть отвергнута")
	}
	if _, err := parse([]byte(`{"autopilot": {"half_life": "шесть часов"}}`)); err == nil {
		t.Fatal("непонятная продолжительность должна быть отвергнута")
	}
}

// TestInvalidAutopilotRejected: проверка делегирована конструкторам
// потребителей, поэтому их правила действуют и на конфиг.
func TestInvalidAutopilotRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"полужизнь ноль", `{"autopilot": {"half_life": "0s"}}`},
		{"объём наизнанку", `{"autopilot": {"min_observations": 60, "max_observations": 20}}`},
		{"вес успеха отрицательный", `{"autopilot": {"weight_ok": -1}}`},
		{"доля проверки выше потолка", `{"autopilot": {"trial_permille": 500}}`},
		{"доля при обвале ниже обычной", `{"autopilot": {"blackout_trial_permille": 10}}`},
		{"джиттер проб нулевой", `{"autopilot": {"probe_jitter": 0}}`},
		{"воркеров больше предела", `{"parallelism": {"workers": 64}}`},
		{"прогонов на цель больше воркеров", `{"parallelism": {"workers": 2, "per_target": 8}}`},
		{"бюджет решения ноль", `{"budgets": {"decision": "0s"}}`},
		{"срезы живут меньше строк", `{"retention": {"rows": "720h", "aggregates": "24h"}}`},
		{"пустая цель проб", `{"probe_targets": [""]}`},
		{"пустая контрольная цель", `{"control_targets": [""]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parse([]byte(tc.body)); err == nil {
				t.Fatalf("негодная настройка должна быть отвергнута: %s", tc.body)
			}
		})
	}
}

// TestVantageLabelFromConfig — метка точки наблюдения приходит из конфига, а не
// из внешнего запроса (6.2): определение точки наблюдения не должно само
// становиться утечкой.
func TestVantageLabelFromConfig(t *testing.T) {
	cfg, err := parse([]byte(`{"vantage": {"operator": "Билайн", "region": "RU-MOW", "access": "mobile"}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Vantage.Operator != "Билайн" || cfg.Vantage.Region != "RU-MOW" {
		t.Fatalf("метка = %+v", cfg.Vantage)
	}
	if cfg.Vantage.Access != core.AccessMobile {
		t.Fatalf("тип доступа = %v, ожидался mobile", cfg.Vantage.Access)
	}
}

func TestUnknownAutopilotKeyRejected(t *testing.T) {
	// Строгий разбор действует и во вложенных разделах: опечатка в имени
	// параметра иначе выглядела бы как молча не сработавшая настройка.
	if _, err := parse([]byte(`{"autopilot": {"half_live": "6h"}}`)); err == nil {
		t.Fatal("неизвестный ключ раздела должен быть ошибкой")
	}
}

func TestTargetsAndBudgetsParsed(t *testing.T) {
	cfg, err := parse([]byte(`{
		"probe_targets": ["www.youtube.com", "discord.com"],
		"control_targets": ["example.com"],
		"budgets": {"interesting_conn": "2us", "decision": "20us"}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.ProbeTargets) != 2 || len(cfg.ControlTargets) != 1 {
		t.Fatalf("цели = %v / %v", cfg.ProbeTargets, cfg.ControlTargets)
	}
	if cfg.Budgets.Decision != 20*time.Microsecond || cfg.Budgets.InterestingConn != 2*time.Microsecond {
		t.Fatalf("бюджеты = %+v", cfg.Budgets)
	}
}
