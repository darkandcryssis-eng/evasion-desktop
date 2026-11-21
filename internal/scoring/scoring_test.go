package scoring

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/store"
)

var (
	testKey = Key{StrategyID: "s1", Target: "www.example.com", VantageID: "v1"}
	base    = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
)

// newTable создаёт таблицу с параметрами по умолчанию.
func newTable(t *testing.T, mods ...func(*Config)) *Table {
	t.Helper()
	cfg := DefaultConfig()
	for _, m := range mods {
		m(&cfg)
	}
	tbl, err := NewTable(cfg)
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}
	return tbl
}

// baselineOf возвращает ключ базовой линии той же цели и точки наблюдения.
func baselineOf(k Key) Key { return BaselineKey(k.Target, k.VantageID) }

// observeN учитывает n наблюдений с заданным исходом, по одному в минуту.
func observeN(tbl *Table, k Key, outcome core.Outcome, n int, from time.Time) time.Time {
	at := from
	for range n {
		tbl.Observe(k, outcome, store.SourceProbe, at)
		at = at.Add(time.Minute)
	}
	return at
}

func TestConfigValidation(t *testing.T) {
	// Несогласованные пороги не ломают работу явно, а тихо меняют поведение
	// автопилота: выяснялось бы это по отсутствию результата, а не по ошибке.
	cases := []struct {
		name   string
		mod    func(*Config)
		errHas string
	}{
		{"нулевая полужизнь", func(c *Config) { c.HalfLife = 0 }, "полужизнь"},
		{"верхняя граница ниже нижней", func(c *Config) { c.MaxObservations = 5 }, "меньше нижней"},
		{"порог доли вне интервала", func(c *Config) { c.PromoteLowerBound = 1.5 }, "вне интервала"},
		{"неположительное доверие", func(c *Config) { c.ConfidenceZ = 0 }, "доверия"},
		{"нулевой срыв", func(c *Config) { c.FailureStreak = 0 }, "срыв"},
		{"неотрицательный вес провала", func(c *Config) { c.WeightFail = 1 }, "вес провала"},
		{"неположительный вес успеха", func(c *Config) { c.WeightOK = 0 }, "вес успеха"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := DefaultConfig()
			c.mod(&cfg)
			_, err := NewTable(cfg)
			if err == nil {
				t.Fatalf("ожидалась ошибка с %q", c.errHas)
			}
			if !strings.Contains(err.Error(), c.errHas) {
				t.Fatalf("ошибка %q не содержит %q", err, c.errHas)
			}
		})
	}
}

func TestDefaultConfigMatchesSpec(t *testing.T) {
	// Значения по умолчанию заданы заданием (5.5, 5.7). Тест закрепляет их,
	// чтобы правка не прошла незамеченной: подбор этих чисел — вопрос
	// наблюдения за работой движка, а не вкуса.
	c := DefaultConfig()
	if c.HalfLife != 6*time.Hour {
		t.Fatalf("полужизнь %v, задание требует 6 ч", c.HalfLife)
	}
	if c.WeightOK != 1 || c.WeightThrottled != -0.7 || c.WeightFail != -1 || c.WeightInconclusive != 0 {
		t.Fatalf("веса %v/%v/%v/%v, задание требует +1/-0.7/-1/0",
			c.WeightOK, c.WeightThrottled, c.WeightFail, c.WeightInconclusive)
	}
	if c.MinObservations != 20 || c.MaxObservations != 60 {
		t.Fatalf("границы объёма %d..%d, задание требует 20..60",
			c.MinObservations, c.MaxObservations)
	}
	if c.PromoteLowerBound != 0.8 {
		t.Fatalf("порог доли %v, задание требует 0.8", c.PromoteLowerBound)
	}
	if c.SuperiorityMargin != 0.15 {
		t.Fatalf("порог превосходства %v, задание требует 0.15", c.SuperiorityMargin)
	}
	if c.FailureStreak != 3 {
		t.Fatalf("срыв по провалам %d, задание требует 3", c.FailureStreak)
	}
}

func TestScoreDecaysByHalfLife(t *testing.T) {
	tbl := newTable(t)
	tbl.Observe(testKey, core.OutcomeOK, store.SourceProbe, base)

	fresh, ok := tbl.Estimate(testKey, base)
	if !ok {
		t.Fatal("оценка не создана")
	}
	if math.Abs(fresh.Score-1) > 1e-9 {
		t.Fatalf("свежая оценка %v, ожидалась 1", fresh.Score)
	}

	// Через полужизнь вклад обязан уменьшиться вдвое.
	half, _ := tbl.Estimate(testKey, base.Add(6*time.Hour))
	if math.Abs(half.Score-0.5) > 1e-6 {
		t.Fatalf("через полужизнь оценка %v, ожидалось 0.5", half.Score)
	}
	// Через две полужизни — вчетверо.
	quarter, _ := tbl.Estimate(testKey, base.Add(12*time.Hour))
	if math.Abs(quarter.Score-0.25) > 1e-6 {
		t.Fatalf("через две полужизни оценка %v, ожидалось 0.25", quarter.Score)
	}
}

// TestDecayAppliesWithoutNewObservations — главное свойство забывания.
//
// Решаемая задача — деградация стратегий во времени (1.1). Если оценка
// забывает прошлое только при поступлении наблюдений, то стратегия, по которой
// наблюдений больше нет, навсегда останется на прежней величине и будет
// выигрывать у свежей.
func TestDecayAppliesWithoutNewObservations(t *testing.T) {
	tbl := newTable(t)
	observeN(tbl, testKey, core.OutcomeOK, 10, base)

	atObserve, _ := tbl.Estimate(testKey, base.Add(10*time.Minute))
	muchLater, _ := tbl.Estimate(testKey, base.Add(48*time.Hour))

	if muchLater.Score >= atObserve.Score {
		t.Fatalf("оценка не забывает без новых наблюдений: было %v, стало %v",
			atObserve.Score, muchLater.Score)
	}
	if muchLater.Score >= atObserve.Score*0.01 {
		t.Fatalf("через двое суток оценка %v при исходной %v — забывание слишком слабое",
			muchLater.Score, atObserve.Score)
	}
}

func TestObserveOrderDoesNotChangeFreshContribution(t *testing.T) {
	// Затухание применяется ДО учёта вклада: иначе свежее наблюдение тоже
	// затухало бы, и вклад зависел бы от того, когда таблицу обновляли, а не
	// когда произошло событие.
	a := newTable(t)
	a.Observe(testKey, core.OutcomeOK, store.SourceProbe, base)
	a.Observe(testKey, core.OutcomeOK, store.SourceProbe, base.Add(6*time.Hour))
	got, _ := a.Estimate(testKey, base.Add(6*time.Hour))

	// Первое наблюдение затухло вдвое, второе учтено целиком: 0.5 + 1.
	if math.Abs(got.Score-1.5) > 1e-6 {
		t.Fatalf("оценка %v, ожидалось 1.5 (затухшее прошлое плюс свежий вклад)", got.Score)
	}
}

func TestPassiveObservationWeighsLess(t *testing.T) {
	// Условия пассивного наблюдения не контролируются, поэтому его вес ниже
	// (5.7). Таблица весов берётся из store — одна для всего движка.
	active := newTable(t)
	active.Observe(testKey, core.OutcomeOK, store.SourceProbe, base)
	ea, _ := active.Estimate(testKey, base)

	passive := newTable(t)
	passive.Observe(testKey, core.OutcomeOK, store.SourcePassive, base)
	ep, _ := passive.Estimate(testKey, base)

	if ep.Score >= ea.Score {
		t.Fatalf("пассивное наблюдение весит не меньше активного: %v против %v",
			ep.Score, ea.Score)
	}
	if math.Abs(ep.Score-0.3) > 1e-9 {
		t.Fatalf("вес пассивного наблюдения %v, задание требует 0.3", ep.Score)
	}
}

// TestInconclusiveDoesNotAffectRate — «не определено» не входит в знаменатель.
//
// Иначе стратегия с множеством неопределённых исходов выглядела бы неудачной,
// не будучи проверенной ни разу.
func TestInconclusiveDoesNotAffectRate(t *testing.T) {
	tbl := newTable(t)
	at := observeN(tbl, testKey, core.OutcomeOK, 3, base)
	observeN(tbl, testKey, core.OutcomeInconclusive, 7, at)

	e, _ := tbl.Estimate(testKey, base.Add(time.Hour))
	if e.Observations != 10 {
		t.Fatalf("всего наблюдений %d, ожидалось 10", e.Observations)
	}
	if e.Conclusive != 3 {
		t.Fatalf("определённых %d, ожидалось 3", e.Conclusive)
	}
	if e.Inconclusive != 7 {
		t.Fatalf("неопределённых %d, ожидалось 7", e.Inconclusive)
	}
	// Доля успехов считается только по определённым: три из трёх.
	if rate := e.SuccessRate(); math.Abs(rate-1) > 1e-9 {
		t.Fatalf("доля успехов %v, ожидалась 1 (три из трёх определённых)", rate)
	}
	// И на оценку они не влияют: вес нулевой. Проверяется сравнением с
	// таблицей, где неопределённых наблюдений не было вовсе — так не нужно
	// вычислять ожидаемую величину затухания, которую легко посчитать неверно.
	clean := newTable(t)
	observeN(clean, testKey, core.OutcomeOK, 3, base)
	ce, _ := clean.Estimate(testKey, base.Add(time.Hour))

	if math.Abs(e.Score-ce.Score) > 1e-9 {
		t.Fatalf("неопределённые исходы изменили оценку: %v против %v без них",
			e.Score, ce.Score)
	}
}

func TestInconclusiveDoesNotBreakFailStreak(t *testing.T) {
	// Неопределённое наблюдение не состоялось как проверка: оно не продолжает
	// серию провалов и не обрывает её. Иначе срыв то скрывался бы, то
	// объявлялся на пустом месте.
	tbl := newTable(t)
	tbl.Observe(testKey, core.OutcomeFail, store.SourceProbe, base)
	tbl.Observe(testKey, core.OutcomeFail, store.SourceProbe, base.Add(time.Minute))
	tbl.Observe(testKey, core.OutcomeInconclusive, store.SourceProbe, base.Add(2*time.Minute))
	if tbl.Broken(testKey) {
		t.Fatal("срыв объявлен при двух провалах и одном неопределённом")
	}
	tbl.Observe(testKey, core.OutcomeFail, store.SourceProbe, base.Add(3*time.Minute))
	if !tbl.Broken(testKey) {
		t.Fatal("срыв не объявлен при трёх провалах подряд")
	}
}

// TestShortLuckyStreakIsNotPromoted — требование 5.5 дословно.
//
// «Счёт успехов подряд не используется: короткую серию легко набрать
// случайно.» Три успеха из трёх дают наблюдённую долю 1.0, и наивная проверка
// доли повысила бы такого кандидата немедленно. Нижняя граница интервала
// честно сообщает, что данных мало.
func TestShortLuckyStreakIsNotPromoted(t *testing.T) {
	tbl := newTable(t)
	observeN(tbl, testKey, core.OutcomeOK, 3, base)

	e, _ := tbl.Estimate(testKey, base)
	if rate := e.SuccessRate(); rate != 1 {
		t.Fatalf("наблюдённая доля %v, ожидалась 1", rate)
	}

	lower := tbl.SuccessLowerBound(testKey)
	if lower >= 0.8 {
		t.Fatalf("нижняя граница при трёх из трёх равна %v: короткая серия прошла бы порог", lower)
	}

	d := tbl.EvaluatePromotion(testKey, false, false)
	if d.Ready {
		t.Fatal("кандидат с тремя успехами повышен")
	}
	if d.Reason != ReasonNotEnoughEvidence {
		t.Fatalf("причина отказа %q, ожидалась нехватка данных", d.Reason)
	}
}

func TestPromotionNeedsBothVolumeAndBound(t *testing.T) {
	// Проверяются ОБА условия. Объёма без доли недостаточно, и наоборот.
	t.Run("объём есть, доля низка", func(t *testing.T) {
		// Объём берётся с запасом на эскалацию: смена успехов на провалы даёт
		// чередование, а оно поднимает требуемый объём до верхней границы.
		// Это и выяснилось, когда тест упал с причиной «мало данных» вместо
		// ожидаемой «низкая доля»: правило сработало, а тест его не учёл.
		tbl := newTable(t)
		at := observeN(tbl, testKey, core.OutcomeOK, 35, base)
		observeN(tbl, testKey, core.OutcomeFail, 35, at)

		d := tbl.EvaluatePromotion(testKey, false, false)
		if d.Have < d.Required {
			t.Fatalf("объёма не хватило для проверки доли: есть %d, нужно %d",
				d.Have, d.Required)
		}
		if d.Ready {
			t.Fatalf("повышен при доле около половины: граница %v", d.LowerBound)
		}
		if d.Reason != ReasonLowerBoundTooLow {
			t.Fatalf("причина %q, ожидалась низкая граница", d.Reason)
		}
	})

	t.Run("доля высока, объёма мало", func(t *testing.T) {
		tbl := newTable(t)
		observeN(tbl, testKey, core.OutcomeOK, 10, base)
		d := tbl.EvaluatePromotion(testKey, false, false)
		if d.Ready {
			t.Fatal("повышен при десяти наблюдениях")
		}
		if d.Reason != ReasonNotEnoughEvidence {
			t.Fatalf("причина %q", d.Reason)
		}
	})

	t.Run("все условия выполнены", func(t *testing.T) {
		tbl := newTable(t)
		observeN(tbl, testKey, core.OutcomeOK, 25, base)
		// Третье условие — базовая линия: без стратегии цель не отвечает.
		// Иначе 25 успехов ничего не доказывают: цель могла быть доступна и
		// так.
		observeN(tbl, baselineOf(testKey), core.OutcomeFail, 10, base)

		d := tbl.EvaluatePromotion(testKey, false, false)
		if !d.Ready {
			t.Fatalf("не повышен при 25 успехах против мёртвой базовой линии: "+
				"граница %v, нужно %d, есть %d, базовая %v (известна: %v)",
				d.LowerBound, d.Required, d.Have, d.Baseline, d.BaselineKnown)
		}
	})
}

func TestRequiredObservationsEscalates(t *testing.T) {
	cfg := DefaultConfig()

	t.Run("устойчивые успехи — нижняя граница", func(t *testing.T) {
		tbl := newTable(t)
		observeN(tbl, testKey, core.OutcomeOK, 25, base)
		if got := tbl.RequiredObservations(testKey, false, false); got != cfg.MinObservations {
			t.Fatalf("требуется %d, ожидалась нижняя граница %d", got, cfg.MinObservations)
		}
	})

	t.Run("чередование исходов — верхняя граница", func(t *testing.T) {
		tbl := newTable(t)
		at := base
		for i := range 10 {
			outcome := core.OutcomeOK
			if i%2 == 1 {
				outcome = core.OutcomeFail
			}
			tbl.Observe(testKey, outcome, store.SourceProbe, at)
			at = at.Add(time.Minute)
		}
		e, _ := tbl.Estimate(testKey, at)
		if e.Alternations == 0 {
			t.Fatal("чередование не замечено")
		}
		if got := tbl.RequiredObservations(testKey, false, false); got != cfg.MaxObservations {
			t.Fatalf("при чередовании требуется %d, ожидалась верхняя граница %d",
				got, cfg.MaxObservations)
		}
	})

	t.Run("много неопределённых — верхняя граница", func(t *testing.T) {
		tbl := newTable(t)
		at := observeN(tbl, testKey, core.OutcomeOK, 5, base)
		observeN(tbl, testKey, core.OutcomeInconclusive, 5, at)
		if got := tbl.RequiredObservations(testKey, false, false); got != cfg.MaxObservations {
			t.Fatalf("при половине неопределённых требуется %d, ожидалась верхняя граница", got)
		}
	})

	t.Run("побочный вред — верхняя граница", func(t *testing.T) {
		tbl := newTable(t)
		observeN(tbl, testKey, core.OutcomeOK, 25, base)
		if got := tbl.RequiredObservations(testKey, true, false); got != cfg.MaxObservations {
			t.Fatalf("при побочном вреде требуется %d, ожидалась верхняя граница", got)
		}
	})

	t.Run("прежняя деградация — верхняя граница", func(t *testing.T) {
		tbl := newTable(t)
		observeN(tbl, testKey, core.OutcomeOK, 25, base)
		if got := tbl.RequiredObservations(testKey, false, true); got != cfg.MaxObservations {
			t.Fatalf("при прежней деградации требуется %d, ожидалась верхняя граница", got)
		}
	})
}

func TestWilsonLowerBoundProperties(t *testing.T) {
	// Свойства интервала, из-за которых он и выбран вместо обычного
	// приближения по нормальному распределению.
	t.Run("не выходит за отрезок", func(t *testing.T) {
		for _, n := range []int{1, 3, 10, 100} {
			lower := wilsonLowerBound(n, n, 1.96)
			if lower < 0 || lower > 1 {
				t.Fatalf("при %d из %d граница %v вне отрезка [0,1]", n, n, lower)
			}
			if lower >= 1 {
				t.Fatalf("при %d из %d граница равна единице: данных никогда не «достаточно полностью»", n, n)
			}
		}
	})

	t.Run("растёт с объёмом при той же доле", func(t *testing.T) {
		small := wilsonLowerBound(9, 10, 1.96)
		large := wilsonLowerBound(90, 100, 1.96)
		if large <= small {
			t.Fatalf("при той же доле граница не растёт с объёмом: %v против %v", small, large)
		}
	})

	t.Run("пустая выборка даёт ноль", func(t *testing.T) {
		if got := wilsonLowerBound(0, 0, 1.96); got != 0 {
			t.Fatalf("при отсутствии наблюдений граница %v", got)
		}
	})

	t.Run("три из трёх далеки от порога", func(t *testing.T) {
		// Именно этот случай задание велит не пропускать.
		if got := wilsonLowerBound(3, 3, 1.96); got >= 0.8 {
			t.Fatalf("три из трёх дают %v: порог 0.8 был бы пройден", got)
		}
	})
}

func TestRankIsOrderedAndStable(t *testing.T) {
	tbl := newTable(t)
	good := Key{StrategyID: "good", Target: testKey.Target, VantageID: testKey.VantageID}
	bad := Key{StrategyID: "bad", Target: testKey.Target, VantageID: testKey.VantageID}
	observeN(tbl, good, core.OutcomeOK, 5, base)
	observeN(tbl, bad, core.OutcomeFail, 5, base)

	ranked := tbl.Rank(testKey.Target, testKey.VantageID, base.Add(10*time.Minute))
	if len(ranked) != 2 {
		t.Fatalf("в списке %d стратегий", len(ranked))
	}
	if ranked[0].Key.StrategyID != "good" {
		t.Fatalf("первой идёт %q", ranked[0].Key.StrategyID)
	}

	// Устойчивость: порядок не должен меняться между вызовами, иначе выбор
	// стратегии стал бы невоспроизводимым.
	for range 20 {
		again := tbl.Rank(testKey.Target, testKey.VantageID, base.Add(10*time.Minute))
		if again[0].Key.StrategyID != ranked[0].Key.StrategyID {
			t.Fatal("порядок ранжирования неустойчив")
		}
	}
}

func TestRankSeparatesTargetAndVantage(t *testing.T) {
	// Одна стратегия имеет столько оценок, сколько пар «цель × точка
	// наблюдения» (4.5, 6.1).
	tbl := newTable(t)
	here := Key{StrategyID: "s1", Target: "a", VantageID: "v1"}
	there := Key{StrategyID: "s1", Target: "a", VantageID: "v2"}
	other := Key{StrategyID: "s1", Target: "b", VantageID: "v1"}
	observeN(tbl, here, core.OutcomeOK, 3, base)
	observeN(tbl, there, core.OutcomeFail, 3, base)
	observeN(tbl, other, core.OutcomeOK, 3, base)

	if got := tbl.Rank("a", "v1", base); len(got) != 1 || got[0].Score <= 0 {
		t.Fatalf("срез цели a в точке v1: %+v", got)
	}
	if got := tbl.Rank("a", "v2", base); len(got) != 1 || got[0].Score >= 0 {
		t.Fatalf("срез цели a в точке v2: %+v", got)
	}
}

func TestChallengerRespectsMargin(t *testing.T) {
	// Без порога превосходства автопилот менял бы стратегию на каждое
	// случайное колебание оценки (5.7).
	tbl := newTable(t, func(c *Config) { c.SuperiorityMargin = 0.5 })
	cur := Key{StrategyID: "cur", Target: "a", VantageID: "v1"}
	rival := Key{StrategyID: "rival", Target: "a", VantageID: "v1"}

	tbl.Observe(cur, core.OutcomeOK, store.SourceProbe, base)
	// Претендент лучше, но лишь на 0.3 — меньше порога 0.5.
	tbl.Observe(rival, core.OutcomeOK, store.SourceProbe, base)
	tbl.Observe(rival, core.OutcomeOK, store.SourcePassive, base)

	if _, ok := tbl.Challenger("a", "v1", "cur", base); ok {
		t.Fatal("претендент принят при превосходстве меньше порога")
	}

	// Добавляем преимущество выше порога.
	tbl.Observe(rival, core.OutcomeOK, store.SourceProbe, base)
	if ch, ok := tbl.Challenger("a", "v1", "cur", base); !ok {
		t.Fatal("претендент не принят при явном превосходстве")
	} else if ch.Key.StrategyID != "rival" {
		t.Fatalf("претендентом назван %q", ch.Key.StrategyID)
	}
}

func TestChallengerWhenNoCurrent(t *testing.T) {
	// Действующей стратегии нет: лучший берётся без порога — хуже, чем
	// ничего, он быть не может.
	tbl := newTable(t)
	k := Key{StrategyID: "any", Target: "a", VantageID: "v1"}
	tbl.Observe(k, core.OutcomeFail, store.SourceProbe, base)

	ch, ok := tbl.Challenger("a", "v1", "", base)
	if !ok {
		t.Fatal("при отсутствии действующей стратегии претендент не выбран")
	}
	if ch.Key.StrategyID != "any" {
		t.Fatalf("выбран %q", ch.Key.StrategyID)
	}
}

func TestChallengerUnknownCurrentIsNotReplaced(t *testing.T) {
	// О действующей стратегии нет наблюдений: сравнивать нечем, и подменять
	// её на этом основании нельзя. Отсутствие наблюдений по действующей
	// стратегии само означает неполадку, и решать её подменой неверно.
	tbl := newTable(t)
	rival := Key{StrategyID: "rival", Target: "a", VantageID: "v1"}
	observeN(tbl, rival, core.OutcomeOK, 5, base)

	if _, ok := tbl.Challenger("a", "v1", "неизвестная", base); ok {
		t.Fatal("действующая стратегия без наблюдений заменена")
	}
}

func TestChallengerSameAsCurrentIsNoChange(t *testing.T) {
	tbl := newTable(t)
	k := Key{StrategyID: "cur", Target: "a", VantageID: "v1"}
	observeN(tbl, k, core.OutcomeOK, 5, base)
	if _, ok := tbl.Challenger("a", "v1", "cur", base); ok {
		t.Fatal("лучшая стратегия совпадает с действующей, смена не нужна")
	}
}

func TestForgetRemovesEstimate(t *testing.T) {
	tbl := newTable(t)
	tbl.Observe(testKey, core.OutcomeOK, store.SourceProbe, base)
	if tbl.Len() != 1 {
		t.Fatalf("в таблице %d ключей", tbl.Len())
	}
	tbl.Forget(testKey)
	if tbl.Len() != 0 {
		t.Fatalf("после удаления в таблице %d ключей", tbl.Len())
	}
	if _, ok := tbl.Estimate(testKey, base); ok {
		t.Fatal("оценка осталась после удаления")
	}
}

func TestEstimateForUnknownKey(t *testing.T) {
	tbl := newTable(t)
	e, ok := tbl.Estimate(testKey, base)
	if ok {
		t.Fatal("оценка найдена для неизвестного ключа")
	}
	// Возвращаемая оценка обязана быть нейтральной: ноль не должен выглядеть
	// ни успехом, ни провалом.
	if e.Score != 0 || e.Observations != 0 {
		t.Fatalf("неизвестный ключ дал %+v", e)
	}
	if rate := e.SuccessRate(); rate != 0 {
		t.Fatalf("доля успехов неизвестного ключа %v", rate)
	}
}

func TestEvaluatePromotionWithoutEstimate(t *testing.T) {
	tbl := newTable(t)
	d := tbl.EvaluatePromotion(testKey, false, false)
	if d.Ready {
		t.Fatal("повышение разрешено без наблюдений")
	}
	if d.Reason != ReasonNoEstimate {
		t.Fatalf("причина %q, ожидалось отсутствие оценки", d.Reason)
	}
	if d.Required != DefaultConfig().MinObservations {
		t.Fatalf("требуемый объём %d", d.Required)
	}
}

func TestFreshnessVisibleByTimestamps(t *testing.T) {
	// Свежесть выражается временем последнего наблюдения, а не величиной
	// оценки (4.5): видно и сколько данных, и насколько они свежие.
	tbl := newTable(t)
	at := observeN(tbl, testKey, core.OutcomeOK, 5, base)
	e, _ := tbl.Estimate(testKey, base.Add(100*time.Hour))

	if !e.First.Equal(base) {
		t.Fatalf("первое наблюдение %v, ожидалось %v", e.First, base)
	}
	if !e.Last.Equal(at.Add(-time.Minute)) {
		t.Fatalf("последнее наблюдение %v", e.Last)
	}
	// Объём доказательств при этом не изменился: он не затухает.
	if e.Observations != 5 {
		t.Fatalf("объём наблюдений %d изменился со временем", e.Observations)
	}
}

// TestPromotionRequiresBaseline — главное свойство базовой линии: успех
// стратегии значим лишь настолько, насколько он отличается от доступности
// самой цели.
//
// Проверка написана по настоящему измерению, а не из предусмотрительности.
// Первая же проба движка прошла рукопожатие к discord.gg со стратегией, и это
// выглядело первым положительным исходом в проекте. Но та же цель отвечает и
// без стратегии — в прежних измерениях записано «discord 1/6, отвечает только
// discord.gg». Без сравнения с базовой линией бандит поднял бы оценку за чужую
// заслугу, а генератор (M7) принял бы доступные цели за доказательство
// работоспособности своих мутантов.
func TestPromotionRequiresBaseline(t *testing.T) {
	// Во всех случаях стратегия сама по себе безупречна: 25 успехов, объём и
	// граница Уилсона заведомо выше порогов. Различается только то, что
	// известно о цели без стратегии. Так проверяется именно базовая линия, а
	// не какой-нибудь другой предохранитель.
	const strategySuccesses = 25

	t.Run("базовой линии нет — повышения нет", func(t *testing.T) {
		tbl := newTable(t)
		observeN(tbl, testKey, core.OutcomeOK, strategySuccesses, base)

		d := tbl.EvaluatePromotion(testKey, false, false)
		if d.Ready {
			t.Fatal("повышен без базовой линии: неизвестно, блокируется ли цель вообще")
		}
		if d.Reason != ReasonNoBaseline {
			t.Fatalf("причина %q, ожидалась %q", d.Reason, ReasonNoBaseline)
		}
		// Отсутствие данных не должно выглядеть нулём: ноль означал бы
		// «цель заблокирована», то есть сильнейший довод в пользу стратегии.
		if d.BaselineKnown {
			t.Fatal("базовая линия не измерена, признак обязан быть ложным")
		}
	})

	t.Run("цель доступна и без стратегии — повышения нет", func(t *testing.T) {
		tbl := newTable(t)
		observeN(tbl, testKey, core.OutcomeOK, strategySuccesses, base)
		// Это и есть случай discord.gg: цель отвечает сама.
		observeN(tbl, baselineOf(testKey), core.OutcomeOK, 10, base)

		d := tbl.EvaluatePromotion(testKey, false, false)
		if d.Ready {
			t.Fatalf("повышен на доступной цели: успех принадлежит цели, а не стратегии "+
				"(граница стратегии %v, базовая %v)", d.LowerBound, d.Baseline)
		}
		if d.Reason != ReasonNoBaselineAdvantage {
			t.Fatalf("причина %q, ожидалась %q", d.Reason, ReasonNoBaselineAdvantage)
		}
	})

	t.Run("цель заблокирована — повышение идёт", func(t *testing.T) {
		tbl := newTable(t)
		observeN(tbl, testKey, core.OutcomeOK, strategySuccesses, base)
		observeN(tbl, baselineOf(testKey), core.OutcomeFail, 10, base)

		d := tbl.EvaluatePromotion(testKey, false, false)
		if !d.Ready {
			t.Fatalf("не повышен на заблокированной цели: причина %q, "+
				"граница %v, базовая %v", d.Reason, d.LowerBound, d.Baseline)
		}
		if !d.BaselineKnown || d.BaselineObservations != 10 {
			t.Fatalf("разбор базовой линии = %+v, ожидались 10 определённых наблюдений", d)
		}
	})
}

// TestBaselineVolumeRegulatesItself — объём базовой линии учитывается самой
// статистикой, без отдельного порога в конфиге.
//
// Это и есть причина, по которой сравнение идёт с ВЕРХНЕЙ границей Уилсона, а
// не с наблюдённой долей. Доля при одном провале равна нулю, то есть по ней
// цель мгновенно объявлялась бы заблокированной — а единственный провал
// случается и при обычном обрыве связи. Верхняя граница при одном наблюдении
// высока и кредита не даёт; по мере накопления провалов она опускается, и
// порог открывается сам.
//
// Проверяется именно переход: при одном провале повышения ещё нет, при двух
// уже есть. Без проверки обеих сторон тест прошёл бы и при снятом сравнении.
//
// Где именно лежит переход, зависит и от силы самого кандидата: порог
// сравнивает нижнюю границу стратегии с верхней границей базовой линии, и у
// безупречного кандидата (25 успехов из 25, граница 0.867) запас больше, чем у
// едва прошедшего порог. Связанность намеренная: утверждение «стратегия
// работает, а цель мертва» — это утверждение о РАЗНИЦЕ, и неопределённость
// обеих сторон обязана в него входить. Числа здесь измерены, а не выведены на
// бумаге: первая версия этого комментария называла переход на трёх провалах и
// была опровергнута прогоном.
func TestBaselineVolumeRegulatesItself(t *testing.T) {
	cases := []struct {
		name      string
		fails     int
		wantReady bool
	}{
		{"один провал базовой пробы — мало", 1, false},
		{"два провала — довод принят", 2, true},
		{"десять провалов — тем более", 10, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tbl := newTable(t)
			observeN(tbl, testKey, core.OutcomeOK, 25, base)
			observeN(tbl, baselineOf(testKey), core.OutcomeFail, c.fails, base)

			d := tbl.EvaluatePromotion(testKey, false, false)
			if d.Ready != c.wantReady {
				t.Fatalf("повышение = %v при %d провалах базовой пробы, ожидалось %v "+
					"(граница стратегии %v, верхняя граница базовой %v, причина %q)",
					d.Ready, c.fails, c.wantReady, d.LowerBound, d.Baseline, d.Reason)
			}
		})
	}
}

// TestBaselineStaysOutOfRanking — базовая линия не участвует в отборе
// стратегий.
//
// Свойство неочевидное и опасное при нарушении. Базовая линия лежит в той же
// таблице с пустым идентификатором, и попав в ранжирование, на доступной цели
// она получила бы оценку выше любой настоящей стратегии. Контур выбрал бы её
// как лучшую, то есть «применил» бы отсутствие стратегии и приписал бы ей
// чужой успех — ровно та подмена, против которой базовая линия и введена.
func TestBaselineStaysOutOfRanking(t *testing.T) {
	tbl := newTable(t)
	// Базовая линия нарочно успешнее стратегии: будь она в отборе, она была бы
	// первой.
	observeN(tbl, baselineOf(testKey), core.OutcomeOK, 30, base)
	observeN(tbl, testKey, core.OutcomeFail, 5, base)

	for _, r := range tbl.Rank(testKey.Target, testKey.VantageID, base) {
		if r.Key.IsBaseline() {
			t.Fatal("базовая линия попала в ранжирование: она эталон, а не участник отбора")
		}
	}

	// И через претендента — им базовая линия тоже стать не может.
	if ch, ok := tbl.Challenger(testKey.Target, testKey.VantageID, "", base); ok && ch.Key.IsBaseline() {
		t.Fatal("базовая линия предложена претендентом")
	}

	// При этом из таблицы она не исчезла: учёт ведётся, просто не в отборе.
	if _, ok := tbl.Baseline(testKey.Target, testKey.VantageID, base); !ok {
		t.Fatal("базовая линия должна учитываться, хотя в отборе не участвует")
	}
}

// TestBaselineIsNotPromotable — повысить саму базовую линию нельзя.
//
// «Применить отсутствие стратегии» означает прозрачный пропуск, и повышать
// тут нечего. Отказ обязан быть явным, а не молчаливым: тихое согласие
// означало бы, что эталон попал в отбор, и дефект вызывающего остался бы
// незамеченным (4.7 п. 2).
func TestBaselineIsNotPromotable(t *testing.T) {
	tbl := newTable(t)
	k := baselineOf(testKey)
	observeN(tbl, k, core.OutcomeOK, 40, base)

	d := tbl.EvaluatePromotion(k, false, false)
	if d.Ready {
		t.Fatal("базовая линия повышена: она не стратегия")
	}
	if d.Reason != ReasonBaselineNotPromotable {
		t.Fatalf("причина %q, ожидалась %q", d.Reason, ReasonBaselineNotPromotable)
	}
}

// TestWilsonBoundsBracketRate — границы интервала лежат по обе стороны от
// наблюдённой доли и не выходят за отрезок от нуля до единицы.
//
// Проверка арифметики, а не поведения: обе границы считаются одной функцией, и
// ошибка в знаке дала бы интервал, у которого «верхняя» граница ниже нижней.
// Заметить это по поведению движка было бы нечем — он просто перестал бы
// кого-либо повышать.
func TestWilsonBoundsBracketRate(t *testing.T) {
	const z = 1.96
	for _, c := range []struct{ successes, total int }{
		{0, 1}, {1, 1}, {0, 3}, {1, 3}, {3, 3}, {0, 10}, {5, 10}, {10, 10}, {25, 25},
	} {
		lower := wilsonLowerBound(c.successes, c.total, z)
		upper := wilsonUpperBound(c.successes, c.total, z)
		rate := float64(c.successes) / float64(c.total)

		switch {
		case lower < 0 || upper > 1:
			t.Fatalf("%d/%d: интервал [%v, %v] выходит за [0, 1]", c.successes, c.total, lower, upper)
		case lower > upper:
			t.Fatalf("%d/%d: нижняя граница %v выше верхней %v", c.successes, c.total, lower, upper)
		case rate < lower || rate > upper:
			t.Fatalf("%d/%d: доля %v вне интервала [%v, %v]", c.successes, c.total, rate, lower, upper)
		}
	}
}

// TestEvidenceTakesLatestObservation — свежесть стратегии это ПОЗДНЕЙШЕЕ из её
// наблюдений, а не произвольное.
//
// Свойство нужно требованию 5.9: по свежести портфеля doctor решает, можно ли
// доверять оценкам. Возьми сводка любое наблюдение вместо позднейшего — и
// стратегия, проверенная вчера и сегодня, выглядела бы проверенной вчера, то
// есть doctor требовал бы перевалидации на ровном месте. Либо наоборот.
//
// # Почему вызовов много
//
// Сводка обходит карту, а порядок обхода карт в Go намеренно случаен. Подмена
// «позднейшее» на «последнее встреченное» при двух ключах проходила бы
// примерно в половине прогонов — такой тест не декоративен, но хуже:
// он лжёт через раз. Поэтому целей несколько и сводка берётся много раз: при
// пяти целях и двадцати вызовах вероятность, что сломанный код каждый раз
// случайно вернёт максимум, — пять в минус двадцатой.
//
// Тот же приём уже применялся к тесту на гонку снимков: короткая проверка
// пропускала нарочно внесённую гонку, и её пришлось превратить в длинный цикл.
func TestEvidenceTakesLatestObservation(t *testing.T) {
	tbl := newTable(t)

	// Цели перечислены так, чтобы позднейшее наблюдение не было ни первым, ни
	// последним по алфавиту: иначе сломанный обход мог бы совпасть с верным
	// ответом по совпадению порядка.
	targets := []struct {
		host string
		at   time.Time
	}{
		{"b.example.com", base.Add(2 * time.Hour)},
		{"a.example.com", base},
		{"e.example.com", base.Add(1 * time.Hour)},
		{"c.example.com", base.Add(4 * time.Hour)}, // позднейшее
		{"d.example.com", base.Add(3 * time.Hour)},
	}
	want := base.Add(4 * time.Hour)

	for _, tg := range targets {
		observeN(tbl, Key{StrategyID: "s1", Target: tg.host, VantageID: "v1"},
			core.OutcomeOK, 1, tg.at)
	}

	const calls = 20
	for i := range calls {
		ev := tbl.Evidence("s1", "v1")
		if !ev.Last.Equal(want) {
			t.Fatalf("вызов %d: свежесть = %s, ожидалось позднейшее наблюдение %s",
				i, ev.Last, want)
		}
		if ev.Observations != len(targets) || ev.Targets != len(targets) {
			t.Fatalf("вызов %d: сводка = %+v, ожидалось по одному наблюдению на каждую из %d целей",
				i, ev, len(targets))
		}
	}
}

// TestEvidenceIgnoresOtherVantage — наблюдения другой сети в сводку не
// попадают.
//
// Оценка привязана к точке наблюдения (6.1), и свежесть обязана быть привязана
// так же. Иначе после переезда в другую сеть портфель выглядел бы
// свежепроверенным по наблюдениям, которые к этой сети отношения не имеют, —
// то есть doctor промолчал бы там, где обязан требовать перевалидации.
func TestEvidenceIgnoresOtherVantage(t *testing.T) {
	tbl := newTable(t)

	// observeN шагает по минуте и возвращает время ПОСЛЕ последнего
	// наблюдения, поэтому позднейшее в этой сети — на минуту раньше.
	endV1 := observeN(tbl, Key{StrategyID: "s1", Target: "a.example.com", VantageID: "v1"},
		core.OutcomeOK, 4, base)
	wantLast := endV1.Add(-time.Minute)

	// В другой сети наблюдений больше и они свежее: если сводка перестанет
	// различать сети, это заметно сразу по всем трём полям.
	observeN(tbl, Key{StrategyID: "s1", Target: "a.example.com", VantageID: "v2"},
		core.OutcomeOK, 9, base.Add(time.Hour))
	observeN(tbl, Key{StrategyID: "s1", Target: "b.example.com", VantageID: "v2"},
		core.OutcomeOK, 3, base.Add(2*time.Hour))

	ev := tbl.Evidence("s1", "v1")
	if ev.Observations != 4 {
		t.Fatalf("наблюдений %d, ожидалось 4: в сводку попали наблюдения другой сети", ev.Observations)
	}
	if ev.Targets != 1 {
		t.Fatalf("целей %d, ожидалась одна: в сводку попали цели другой сети", ev.Targets)
	}
	if !ev.Last.Equal(wantLast) {
		t.Fatalf("свежесть = %s, ожидалось %s: позднейшие наблюдения сделаны в другой сети",
			ev.Last, wantLast)
	}
}

// TestEvidenceOfBaselineIsEmpty — у базовой линии сводки нет.
//
// Базовая линия не стратегия, и просить её свежесть — признак дефекта
// вызывающего. Пустая сводка здесь не «нет данных», а «вопрос задан не о том»:
// попади базовая линия в портфель как стратегия, движок показал бы её человеку
// как нечто применимое.
func TestEvidenceOfBaselineIsEmpty(t *testing.T) {
	tbl := newTable(t)
	observeN(tbl, BaselineKey("a.example.com", "v1"), core.OutcomeFail, 5, base)

	ev := tbl.Evidence("", "v1")
	if ev.Observations != 0 || ev.Targets != 0 || !ev.Last.IsZero() {
		t.Fatalf("сводка базовой линии = %+v, ожидалась пустая: базовая линия не стратегия", ev)
	}
}

// TestPassiveDoesNotDriveFailStreak: пассивные провалы (5.10) не ведут быстрый
// контур срыва. Задание требует делать выводы по накоплению, а не по единичному
// событию, потому что ретрансмиссия бывает и от обычной потери пакета. Поэтому
// сколько бы пассивных провалов подряд ни пришло, Broken не срабатывает — но
// оценка при этом опускается, чтобы деградация копилась.
func TestPassiveDoesNotDriveFailStreak(t *testing.T) {
	tbl := newTable(t)

	// Больше порога срыва подряд, все пассивные.
	n := DefaultConfig().FailureStreak + 2
	for i := 0; i < n; i++ {
		tbl.Observe(testKey, core.OutcomeFail, store.SourcePassive, base.Add(time.Duration(i)*time.Minute))
	}

	if tbl.Broken(testKey) {
		t.Fatal("пассивные провалы не должны поднимать быстрый срыв (Broken)")
	}
	est, ok := tbl.Estimate(testKey, base.Add(time.Duration(n)*time.Minute))
	if !ok {
		t.Fatal("оценка должна существовать")
	}
	if est.FailStreak != 0 {
		t.Fatalf("FailStreak = %d, пассив не должен его вести", est.FailStreak)
	}
	if est.Score >= 0 {
		t.Fatalf("оценка = %f, пассивные провалы должны опускать её ниже нуля", est.Score)
	}
	// Наблюдения всё равно учтены: пассив — это данные, просто низкого веса.
	if est.Observations != n {
		t.Fatalf("наблюдений учтено %d, ожидалось %d", est.Observations, n)
	}
}

// TestProbeFailStillDrivesFailStreakAlongsidePassive: контролируемые провалы
// (проба) ведут быстрый срыв как прежде, даже вперемешку с пассивными. Пассив не
// должен ни ломать, ни подменять этот контур.
func TestProbeFailStillDrivesFailStreakAlongsidePassive(t *testing.T) {
	tbl := newTable(t)
	streak := DefaultConfig().FailureStreak

	at := base
	for i := 0; i < streak; i++ {
		// Пассивный провал между пробами не должен ни сбрасывать, ни наращивать
		// серию — её ведут только пробы.
		tbl.Observe(testKey, core.OutcomeFail, store.SourcePassive, at)
		at = at.Add(time.Minute)
		tbl.Observe(testKey, core.OutcomeFail, store.SourceProbe, at)
		at = at.Add(time.Minute)
	}

	if !tbl.Broken(testKey) {
		t.Fatalf("%d провалов пробы подряд должны поднять Broken", streak)
	}
}
