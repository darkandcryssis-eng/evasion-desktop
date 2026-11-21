package control

import (
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/scoring"
	"github.com/fitting-1c/evasion/internal/store"
)

// base — отсчётное время тестов. Фиксировано: время приходит входом, поэтому
// ожидать его не нужно ни секунды.
var base = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

const (
	target  = "youtube.com"
	vantage = core.VantageID("vtest")

	idA = core.StrategyID("aaaa")
	idB = core.StrategyID("bbbb")
	idC = core.StrategyID("cccc")
)

func key(id core.StrategyID) scoring.Key {
	return scoring.Key{StrategyID: id, Target: target, VantageID: vantage}
}

func newDecider(t *testing.T) *Decider {
	t.Helper()
	d, err := NewDecider(DefaultConfig())
	if err != nil {
		t.Fatalf("NewDecider: %v", err)
	}
	return d
}

func newTable(t *testing.T, cfg scoring.Config) *scoring.Table {
	t.Helper()
	tab, err := scoring.NewTable(cfg)
	if err != nil {
		t.Fatalf("scoring.NewTable: %v", err)
	}
	return tab
}

// observe добавляет n наблюдений одного исхода от активной пробы.
func observe(tab *scoring.Table, k scoring.Key, outcome core.Outcome, n int, at time.Time) {
	for range n {
		tab.Observe(k, outcome, store.SourceProbe, at)
	}
}

// proven наполняет таблицу доказательствами, достаточными для повышения:
// 25 успехов дают и объём (больше 20), и нижнюю границу около 0.87.
//
// Вместе с ними ложится базовая линия цели — десять провалов без стратегии.
// Без неё повышения не бывает вовсе, и это не особенность тестов, а правило
// движка: успех стратегии значим лишь настолько, насколько он отличается от
// доступности самой цели. «Доказана» поэтому означает «доказана на цели,
// которая без стратегии не отвечает», а не «набрала успехов».
//
// Десять провалов, а не три (минимум, при котором порог открывается): запас
// нужен, чтобы тесты проверяли своё свойство, а не стояли на границе порога
// базовой линии. Обстановка, в которой остальные предохранители заведомо
// открыты, — правило, выведенное из декоративного теста про замену
// сорвавшейся.
func proven(tab *scoring.Table, k scoring.Key, at time.Time) {
	observe(tab, k, core.OutcomeOK, 25, at)
	blocked(tab, k.Target, k.VantageID, at)
}

// blocked записывает базовую линию «цель без стратегии не отвечает».
func blocked(tab *scoring.Table, target string, v core.VantageID, at time.Time) {
	observe(tab, scoring.BaselineKey(target, v), core.OutcomeFail, 10, at)
}

// pf строит портфель, в котором перечисленные стратегии уже прошли проверку и
// допущены к полному трафику, но ни одна не применяется (ступень benched —
// резерв из 5.8). Это обычное предусловие для проверки решений о смене
// действующей стратегии: сама лестница допуска проверяется отдельно, в
// trial_test.go.
func pf(ids ...core.StrategyID) Portfolio {
	p := make(Portfolio, len(ids))
	for _, id := range ids {
		p[id] = Holding{Status: core.StatusBenched}
	}
	return p
}

func TestDecidePinBeatsEverything(t *testing.T) {
	d := newDecider(t)
	// Таблица пуста: о закреплённой стратегии не известно ровно ничего.
	tab := newTable(t, scoring.DefaultConfig())

	dec := d.Decide(tab, Input{Target: target, Vantage: vantage, Pinned: idA, Now: base})

	if dec.Action != ActionApply || dec.StrategyID != idA {
		t.Fatalf("решение = %v %q, ожидалось apply %q", dec.Action, dec.StrategyID, idA)
	}
	if dec.Reason != ReasonPinned {
		t.Fatalf("причина = %q, ожидалась %q", dec.Reason, ReasonPinned)
	}
	if dec.PromotionEvaluated {
		t.Fatal("закрепление не должно проверять порог доверия: это команда человека")
	}
}

// TestDecidePinIgnoresDwellAndBetterCandidate: закрепление держится, даже
// когда статистика предлагает другое.
func TestDecidePinIgnoresDwellAndBetterCandidate(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idB), base) // idB доказан и лучше

	dec := d.Decide(tab, Input{
		Target:  target,
		Vantage: vantage,
		State:   TargetState{Current: idA, Since: base.Add(-time.Hour)},
		Pinned:  idA,
		Now:     base,
	})

	if dec.Action != ActionKeep || dec.Reason != ReasonPinned {
		t.Fatalf("решение = %v/%q, ожидалось keep/pinned", dec.Action, dec.Reason)
	}
	if dec.Effective() != idA {
		t.Fatalf("действующая стратегия = %q, ожидалась %q", dec.Effective(), idA)
	}
	if dec.Changes() {
		t.Fatal("закрепление уже применено: смены быть не должно")
	}
}

func TestDecideFirstApplyRequiresProof(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idA), base)

	dec := d.Decide(tab, Input{Target: target, Vantage: vantage, Portfolio: pf(idA, idB, idC), Now: base})

	if dec.Action != ActionApply || dec.StrategyID != idA {
		t.Fatalf("решение = %v %q, ожидалось apply %q", dec.Action, dec.StrategyID, idA)
	}
	if dec.Reason != ReasonFirstApply {
		t.Fatalf("причина = %q, ожидалась %q", dec.Reason, ReasonFirstApply)
	}
	if !dec.PromotionEvaluated || !dec.Promotion.Ready {
		t.Fatal("порог доверия обязан быть проверен и пройден")
	}
	if !dec.Changes() {
		t.Fatal("первое применение — это смена")
	}
}

// TestDecideWithoutProofAppliesNothing — главное свойство на сегодня: пока
// доказательств мало, автопилот не трогает живой трафик (5.1, 5.5).
func TestDecideWithoutProofAppliesNothing(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	observe(tab, key(idA), core.OutcomeOK, 5, base) // пять успехов — мало

	dec := d.Decide(tab, Input{Target: target, Vantage: vantage, Portfolio: pf(idA, idB, idC), Now: base})

	if dec.Action != ActionKeep || dec.Reason != ReasonNotPromotable {
		t.Fatalf("решение = %v/%q, ожидалось keep/not_promotable", dec.Action, dec.Reason)
	}
	if dec.Effective() != "" {
		t.Fatalf("применяться не должно ничего, получено %q", dec.Effective())
	}
	// Разбор порога обязан объяснять отказ числами, иначе застой не отличить
	// от поломки.
	if !dec.PromotionEvaluated {
		t.Fatal("порог доверия обязан быть проверен")
	}
	if dec.Promotion.Have != 5 || dec.Promotion.Required != scoring.DefaultConfig().MinObservations {
		t.Fatalf("разбор порога = %d из %d, ожидалось 5 из %d",
			dec.Promotion.Have, dec.Promotion.Required, scoring.DefaultConfig().MinObservations)
	}
	if dec.Promotion.Reason != scoring.ReasonNotEnoughEvidence {
		t.Fatalf("причина отказа = %q, ожидалась %q", dec.Promotion.Reason, scoring.ReasonNotEnoughEvidence)
	}
}

// TestDecideHoldsDwell проверяет выдержку: претендент доказан и лучше, но
// действующая стратегия применена только что.
func TestDecideHoldsDwell(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idA), base)
	proven(tab, key(idB), base)
	observe(tab, key(idB), core.OutcomeOK, 10, base) // idB заметно лучше

	in := Input{
		Target:    target,
		Vantage:   vantage,
		State:     TargetState{Current: idA, Since: base.Add(-time.Minute)},
		Portfolio: pf(idA, idB, idC),
		Now:       base,
	}

	dec := d.Decide(tab, in)
	if dec.Action != ActionKeep || dec.Reason != ReasonDwell {
		t.Fatalf("решение = %v/%q, ожидалось keep/dwell", dec.Action, dec.Reason)
	}

	// Та же обстановка, но выдержка истекла — решение меняется.
	in.State.Since = base.Add(-2 * DefaultConfig().MinDwell)
	dec = d.Decide(tab, in)
	if dec.Action != ActionApply || dec.StrategyID != idB || dec.Reason != ReasonSuperior {
		t.Fatalf("после выдержки решение = %v %q/%q, ожидалось apply %q/superior",
			dec.Action, dec.StrategyID, dec.Reason, idB)
	}
}

// TestDecideBrokenBeatsDwell — порядок правил: срыв реагирует немедленно, не
// дожидаясь выдержки. Пользователь без доступа важнее опрятности графика.
func TestDecideBrokenBeatsDwell(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idA), base)
	proven(tab, key(idB), base)
	// idA срывается: три провала подряд при пороге FailureStreak = 3.
	observe(tab, key(idA), core.OutcomeFail, 3, base)

	dec := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		State:     TargetState{Current: idA, Since: base.Add(-time.Second)}, // выдержка не истекла
		Portfolio: pf(idA, idB, idC),
		Now:       base,
	})

	if dec.Action != ActionApply || dec.StrategyID != idB {
		t.Fatalf("решение = %v %q, ожидалось apply %q", dec.Action, dec.StrategyID, idB)
	}
	if dec.Reason != ReasonBrokenReplaced {
		t.Fatalf("причина = %q, ожидалась %q", dec.Reason, ReasonBrokenReplaced)
	}
}

// TestDecideBrokenWithoutReplacementDisables: держать заведомо сорвавшуюся
// стратегию хуже, чем не применять ничего.
func TestDecideBrokenWithoutReplacementDisables(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idA), base)
	observe(tab, key(idA), core.OutcomeFail, 3, base)
	// Единственный претендент не доказан.
	observe(tab, key(idB), core.OutcomeOK, 4, base)

	dec := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		State:     TargetState{Current: idA, Since: base.Add(-time.Hour)},
		Portfolio: pf(idA, idB, idC),
		Now:       base,
	})

	if dec.Action != ActionDisable || dec.Reason != ReasonBrokenDisabled {
		t.Fatalf("решение = %v/%q, ожидалось disable/broken_disabled", dec.Action, dec.Reason)
	}
	if dec.Effective() != "" {
		t.Fatalf("после снятия не должно действовать ничего, получено %q", dec.Effective())
	}
	if !dec.Changes() {
		t.Fatal("снятие стратегии — это смена")
	}
}

// TestDecideSkipsBrokenReplacement: замена сорвавшейся не может быть сама
// сорвавшейся — перебор идёт дальше по списку.
//
// Обстановка подобрана так, чтобы проверялся именно пропуск сорвавшихся.
// Первая попытка этого теста была декоративной: сорвавшемуся претенденту
// хватало 48 наблюдений, но срыв сам поднимает требуемый объём до верхней
// границы (чередование успехов и провалов — признак эскалации в
// scoring.RequiredObservations), и претендент отсеивался порогом доверия, а не
// проверкой срыва. Поэтому idB даётся 60 успехов: он проходит порог и остаётся
// отвергнутым только потому, что сорван.
func TestDecideSkipsBrokenReplacement(t *testing.T) {
	d := newDecider(t)
	cfg := scoring.DefaultConfig()
	tab := newTable(t, cfg)

	proven(tab, key(idA), base)
	observe(tab, key(idA), core.OutcomeFail, 3, base)

	// idB: по оценке выше всех и порог прошёл бы, но сорван.
	observe(tab, key(idB), core.OutcomeOK, cfg.MaxObservations, base)
	observe(tab, key(idB), core.OutcomeFail, cfg.FailureStreak, base)
	if !tab.Broken(key(idB)) {
		t.Fatal("обстановка теста негодна: idB обязан считаться сорванным")
	}
	if promo := tab.EvaluatePromotion(key(idB), false, false); !promo.Ready {
		t.Fatalf("обстановка теста негодна: idB обязан проходить порог доверия (%d из %d, граница %.3f)",
			promo.Have, promo.Required, promo.LowerBound)
	}

	proven(tab, key(idC), base)

	dec := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		State:     TargetState{Current: idA, Since: base.Add(-time.Hour)},
		Portfolio: pf(idA, idB, idC),
		Now:       base,
	})

	if dec.StrategyID != idC {
		t.Fatalf("замена = %q, ожидалась %q (idB сорван)", dec.StrategyID, idC)
	}
}

// TestDecideWaitsWhenCandidateBroken: действующая цела, а претендент сорван —
// спешить некуда, ждём.
func TestDecideWaitsWhenCandidateBroken(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idA), base)
	// idB по оценке выше, но сорван.
	proven(tab, key(idB), base)
	observe(tab, key(idB), core.OutcomeOK, 20, base)
	observe(tab, key(idB), core.OutcomeFail, 3, base)

	dec := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		State:     TargetState{Current: idA, Since: base.Add(-time.Hour)},
		Portfolio: pf(idA, idB, idC),
		Now:       base,
	})

	if dec.Action != ActionKeep || dec.Reason != ReasonCandidateBroken {
		t.Fatalf("решение = %v/%q, ожидалось keep/candidate_broken", dec.Action, dec.Reason)
	}
}

func TestDecideRefusalReasons(t *testing.T) {
	d := newDecider(t)

	t.Run("претендентов нет", func(t *testing.T) {
		tab := newTable(t, scoring.DefaultConfig())
		dec := d.Decide(tab, Input{Target: target, Vantage: vantage, Portfolio: pf(idA, idB, idC), Now: base})
		if dec.Reason != ReasonNoCandidate {
			t.Fatalf("причина = %q, ожидалась %q", dec.Reason, ReasonNoCandidate)
		}
	})

	t.Run("действующая и есть лучшая", func(t *testing.T) {
		tab := newTable(t, scoring.DefaultConfig())
		proven(tab, key(idA), base)
		observe(tab, key(idB), core.OutcomeOK, 2, base)
		dec := d.Decide(tab, Input{
			Target: target, Vantage: vantage,
			State:     TargetState{Current: idA, Since: base.Add(-time.Hour)},
			Portfolio: pf(idA, idB, idC),
			Now:       base,
		})
		if dec.Reason != ReasonCurrentIsBest {
			t.Fatalf("причина = %q, ожидалась %q", dec.Reason, ReasonCurrentIsBest)
		}
	})

	t.Run("о действующей нет наблюдений", func(t *testing.T) {
		tab := newTable(t, scoring.DefaultConfig())
		proven(tab, key(idB), base)
		dec := d.Decide(tab, Input{
			Target: target, Vantage: vantage,
			State:     TargetState{Current: idA, Since: base.Add(-time.Hour)},
			Portfolio: pf(idA, idB, idC),
			Now:       base,
		})
		if dec.Reason != ReasonNoCurrentEstimate {
			t.Fatalf("причина = %q, ожидалась %q", dec.Reason, ReasonNoCurrentEstimate)
		}
		if dec.Action != ActionKeep {
			t.Fatal("без оценки действующей менять её нельзя")
		}
	})

	t.Run("претендент недостаточно лучше", func(t *testing.T) {
		cfg := scoring.DefaultConfig()
		cfg.SuperiorityMargin = 50 // заведомо недостижимое превосходство
		tab := newTable(t, cfg)
		proven(tab, key(idA), base)
		proven(tab, key(idB), base)
		observe(tab, key(idB), core.OutcomeOK, 3, base)
		dec := d.Decide(tab, Input{
			Target: target, Vantage: vantage,
			State:     TargetState{Current: idA, Since: base.Add(-time.Hour)},
			Portfolio: pf(idA, idB, idC),
			Now:       base,
		})
		if dec.Reason != ReasonNotSuperior {
			t.Fatalf("причина = %q, ожидалась %q", dec.Reason, ReasonNotSuperior)
		}
	})

	t.Run("таблицы оценок нет", func(t *testing.T) {
		dec := d.Decide(nil, Input{Target: target, Vantage: vantage, Portfolio: pf(idA, idB, idC), Now: base})
		if dec.Action != ActionKeep || dec.Reason != ReasonNoCandidate {
			t.Fatalf("решение = %v/%q, ожидалось keep/no_candidate", dec.Action, dec.Reason)
		}
	})
}

// TestDecideInvalidStateKeeps: «применена, но неизвестно когда» — дефект
// памяти владельца. Нулевое время не подменяет отсутствие данных, и выдержку
// от него отсчитывать нельзя.
func TestDecideInvalidStateKeeps(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idB), base)

	dec := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		State:     TargetState{Current: idA}, // Since не заполнено
		Portfolio: pf(idA, idB, idC),
		Now:       base,
	})

	if dec.Action != ActionKeep || dec.Reason != ReasonInvalidState {
		t.Fatalf("решение = %v/%q, ожидалось keep/invalid_state", dec.Action, dec.Reason)
	}
}

// TestDecideHistoryRaisesBar проверяет проводку эскалации: та же
// доказательная база, что проходит порог для чистой стратегии, не проходит для
// стратегии с историей срывов на этой цели (scoring.RequiredObservations).
func TestDecideHistoryRaisesBar(t *testing.T) {
	d := newDecider(t)
	cfg := scoring.DefaultConfig()
	tab := newTable(t, cfg)
	proven(tab, key(idA), base) // 25 наблюдений: больше MinObservations

	clean := d.Decide(tab, Input{Target: target, Vantage: vantage, Portfolio: pf(idA, idB, idC), Now: base})
	if clean.Action != ActionApply {
		t.Fatalf("без истории решение = %v, ожидалось apply", clean.Action)
	}

	withHistory := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		State:     TargetState{Degraded: []core.StrategyID{idA}},
		Portfolio: pf(idA, idB, idC),
		Now:       base,
	})
	if withHistory.Action != ActionKeep || withHistory.Reason != ReasonNotPromotable {
		t.Fatalf("с историей решение = %v/%q, ожидалось keep/not_promotable",
			withHistory.Action, withHistory.Reason)
	}
	if withHistory.Promotion.Required != cfg.MaxObservations {
		t.Fatalf("требуемый объём = %d, ожидался %d (эскалация)",
			withHistory.Promotion.Required, cfg.MaxObservations)
	}

	// Побочный вред поднимает порог так же.
	withCollateral := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		State:     TargetState{Collateral: []core.StrategyID{idA}},
		Portfolio: pf(idA, idB, idC),
		Now:       base,
	})
	if withCollateral.Action != ActionKeep {
		t.Fatal("побочный вред обязан поднимать порог так же, как срыв")
	}
}

// TestDecideForgetsStaleEvidence: оценки затухают, и решение зависит от
// времени решения, а не только от набора наблюдений.
func TestDecideForgetsStaleEvidence(t *testing.T) {
	d := newDecider(t)
	cfg := scoring.DefaultConfig()
	tab := newTable(t, cfg)
	proven(tab, key(idA), base)                       // действующая, наблюдения свежие
	proven(tab, key(idB), base.Add(-20*cfg.HalfLife)) // претендент с древней историей

	dec := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		State:     TargetState{Current: idA, Since: base.Add(-time.Hour)},
		Portfolio: pf(idA, idB, idC),
		Now:       base,
	})

	if dec.Action != ActionKeep {
		t.Fatalf("решение = %v, ожидалось keep: оценка претендента затухла", dec.Action)
	}
}

func TestDecisionEffectiveAndChanges(t *testing.T) {
	for _, tc := range []struct {
		name      string
		dec       Decision
		effective core.StrategyID
		changes   bool
	}{
		{"применить новую", Decision{Action: ActionApply, StrategyID: idB, Previous: idA}, idB, true},
		{"оставить прежнюю", Decision{Action: ActionKeep, Previous: idA}, idA, false},
		{"оставить пустоту", Decision{Action: ActionKeep}, "", false},
		{"снять", Decision{Action: ActionDisable, Previous: idA}, "", true},
		{"решения нет", Decision{}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.dec.Effective(); got != tc.effective {
				t.Fatalf("Effective = %q, ожидалось %q", got, tc.effective)
			}
			if got := tc.dec.Changes(); got != tc.changes {
				t.Fatalf("Changes = %v, ожидалось %v", got, tc.changes)
			}
		})
	}
}

// TestActionZeroValueIsNotKeep: пустое решение не должно читаться как
// «оставить всё как есть» — иначе забытое поле выглядело бы осознанным
// выбором.
func TestActionZeroValueIsNotKeep(t *testing.T) {
	var a Action
	if a.Valid() {
		t.Fatal("нулевое действие не должно считаться годным")
	}
	if a.String() != "none" {
		t.Fatalf("имя нулевого действия = %q, ожидалось none", a.String())
	}
	if !ActionKeep.Valid() || !ActionApply.Valid() || !ActionDisable.Valid() {
		t.Fatal("заданные действия обязаны быть годными")
	}
}

func TestNewDeciderRejectsBadConfig(t *testing.T) {
	if _, err := NewDecider(Config{}); err == nil {
		t.Fatal("нулевая выдержка должна быть отвергнута: забытый Config не выбор")
	}
	if _, err := NewDecider(Config{MinDwell: -time.Second}); err == nil {
		t.Fatal("отрицательная выдержка должна быть отвергнута")
	}
}
