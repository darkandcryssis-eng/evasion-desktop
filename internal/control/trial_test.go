package control

import (
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/policy"
	"github.com/fitting-1c/evasion/internal/scoring"
	"github.com/fitting-1c/evasion/internal/strategy"
)

func newDeciderCfg(t *testing.T, cfg Config) *Decider {
	t.Helper()
	d, err := NewDecider(cfg)
	if err != nil {
		t.Fatalf("NewDecider: %v", err)
	}
	return d
}

// TestTrialAdmitsProvenCandidate — ступень testing из 5.1: кандидат, прошедший
// порог 5.5, получает долю реальных соединений.
func TestTrialAdmitsProvenCandidate(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idB), base)

	dec := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		Portfolio: Portfolio{idB: {Status: core.StatusCandidate}},
		Now:       base,
	})

	if dec.Trial != idB {
		t.Fatalf("проверяемая стратегия = %q, ожидалась %q", dec.Trial, idB)
	}
	if dec.TrialReason != ReasonTrialAdmitted {
		t.Fatalf("причина = %q, ожидалась %q", dec.TrialReason, ReasonTrialAdmitted)
	}
}

// TestTrialRejectsUnprovenCandidate: порог 5.5 открывает именно эту ступень,
// поэтому непроверенный кандидат на живой трафик не попадает даже долей.
func TestTrialRejectsUnprovenCandidate(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	observe(tab, key(idB), core.OutcomeOK, 5, base)

	dec := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		Portfolio: Portfolio{idB: {Status: core.StatusCandidate}},
		Now:       base,
	})

	if dec.Trial != "" {
		t.Fatalf("непроверенный кандидат не должен получать долю трафика, получена %q", dec.Trial)
	}
	// Различать «кандидатов нет» и «есть, но не доказаны» обязательно:
	// первое лечится генератором, второе — пробами.
	if dec.TrialReason != ReasonTrialNotPromotable {
		t.Fatalf("причина = %q, ожидалась %q", dec.TrialReason, ReasonTrialNotPromotable)
	}
}

// TestTrialStatusFilter закрепляет, какие ступени жизненного цикла пускаются
// на долю проверки.
//
// Обстановка с действующей стратегией выбрана нарочно: равные оценки не дают
// претенденту превзойти её, поэтому решение о полном трафике всегда «оставить»
// и проверяется именно ступень проверки, а не повышение. Без действующей
// стратегии проверенная testing-стратегия ушла бы прямо в active — что
// правильно, но проверяло бы другое.
//
// Деградировавшая стратегия в список допущенных входит: иначе срыв был бы
// тупиком и портфель истощался бы с каждым сбоем сети. Возвращается она через
// долю и с повышенным порогом объёма, а не сразу в active.
func TestTrialStatusFilter(t *testing.T) {
	d := newDecider(t)

	for _, tc := range []struct {
		name   string
		status core.Status
		trial  bool
	}{
		{"кандидат", core.StatusCandidate, true},
		{"проверяется", core.StatusTesting, true},
		{"деградировала", core.StatusDegraded, true},
		{"применяется", core.StatusActive, false},
		{"отставлена", core.StatusBenched, false},
		{"выведена", core.StatusRetired, false},
		{"статуса нет", core.StatusUnset, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tab := newTable(t, scoring.DefaultConfig())
			proven(tab, key(idA), base)
			proven(tab, key(idB), base)

			dec := d.Decide(tab, Input{
				Target:  target,
				Vantage: vantage,
				State:   TargetState{Current: idA, Since: base.Add(-time.Hour)},
				Portfolio: Portfolio{
					idA: {Status: core.StatusActive},
					idB: {Status: tc.status},
				},
				Now: base,
			})

			if dec.Action != ActionKeep {
				t.Fatalf("обстановка теста негодна: решение о полном трафике = %v, ожидалось keep", dec.Action)
			}
			if got := dec.Trial != ""; got != tc.trial {
				t.Fatalf("статус %v: проверка %v, ожидалось %v (причина %q)",
					tc.status, got, tc.trial, dec.TrialReason)
			}
		})
	}
}

// TestProvenTestingGoesActive — верхняя ступень лестницы: стратегия,
// проверенная на доле трафика, повышается до полного трафика, а не остаётся на
// доле навсегда.
func TestProvenTestingGoesActive(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idB), base)

	dec := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		Portfolio: Portfolio{idB: {Status: core.StatusTesting}},
		Now:       base,
	})

	if dec.Action != ActionApply || dec.StrategyID != idB {
		t.Fatalf("решение = %v %q, ожидалось apply %q", dec.Action, dec.StrategyID, idB)
	}
	if dec.Trial == idB {
		t.Fatal("применённая ко всему трафику стратегия не может одновременно быть проверяемой")
	}
}

// TestCandidateNeverJumpsToActive — главный запрет лестницы (5.1): порог 5.5
// открывает долю трафика, а не весь трафик. Прыжок candidate → active минул бы
// ступень проверки, то есть ровно ту защиту, ради которой она введена.
func TestCandidateNeverJumpsToActive(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idB), base)

	dec := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		Portfolio: Portfolio{idB: {Status: core.StatusCandidate}},
		Now:       base,
	})

	if dec.Action != ActionKeep {
		t.Fatalf("решение = %v, кандидат не должен получать весь трафик", dec.Action)
	}
	if dec.Reason != ReasonTrialFirst {
		t.Fatalf("причина = %q, ожидалась %q", dec.Reason, ReasonTrialFirst)
	}
	// И при этом он поставлен на долю: отказ в полном трафике — не отказ вовсе.
	if dec.Trial != idB {
		t.Fatalf("кандидат должен быть поставлен на долю проверки, получено %q", dec.Trial)
	}
}

// TestTrialNeverDuplicatesActive: делить долю между действующей стратегией и
// ею же нечего — policy такую запись и не примет.
func TestTrialNeverDuplicatesActive(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idA), base)

	dec := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		State:     TargetState{Current: idA, Since: base.Add(-time.Hour)},
		Portfolio: Portfolio{idA: {Status: core.StatusActive}},
		Now:       base,
	})

	if dec.Trial == idA {
		t.Fatal("действующая стратегия не должна попадать в ступень проверки")
	}
}

func TestTrialSuppressedByPin(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idB), base)

	dec := d.Decide(tab, Input{
		Target:    target,
		Vantage:   vantage,
		Pinned:    idA,
		Portfolio: Portfolio{idB: {Status: core.StatusCandidate}},
		Now:       base,
	})

	if dec.Trial != "" {
		t.Fatal("на закреплённой цели опыты не ставятся")
	}
	if dec.TrialReason != ReasonTrialSuppressedByPin {
		t.Fatalf("причина = %q, ожидалась %q", dec.TrialReason, ReasonTrialSuppressedByPin)
	}
}

// TestCollateralBlocksBothRungs — запрет из 4.5 и мгновенный откат из 5.1:
// вредящая стратегия не попадает ни в active, ни в долю проверки.
func TestCollateralBlocksBothRungs(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idB), base)

	in := Input{
		Target:    target,
		Vantage:   vantage,
		Portfolio: Portfolio{idB: {Status: core.StatusCandidate, Collateral: true}},
		Now:       base,
	}

	dec := d.Decide(tab, in)
	if dec.Action != ActionKeep || dec.Reason != ReasonCollateralBlocked {
		t.Fatalf("решение = %v/%q, ожидалось keep/collateral_blocked", dec.Action, dec.Reason)
	}
	if dec.Trial != "" {
		t.Fatal("вредящая стратегия не должна получать долю трафика: 5.1 требует мгновенного откатa")
	}
	// Порог доверия при этом не проверялся: вред — запрет, а не нехватка
	// доказательств, и смешивать их в журнале нельзя.
	if dec.PromotionEvaluated {
		t.Fatal("при запрете по вреду порог доверия проверять незачем")
	}

	// Разрешение владельца снимает запрет целиком (4.5). Ступень при этом
	// по-прежнему соблюдается: разрешение касается вреда, а не лестницы,
	// поэтому для полного трафика стратегия должна уже быть проверенной.
	in.Portfolio = Portfolio{idB: {Status: core.StatusTesting, Collateral: true, CollateralAllowed: true}}
	dec = d.Decide(tab, in)
	if dec.Action != ActionApply || dec.StrategyID != idB {
		t.Fatalf("с разрешением владельца решение = %v %q, ожидалось apply %q", dec.Action, dec.StrategyID, idB)
	}

	// А кандидат с разрешением идёт на долю проверки, а не сразу в active:
	// разрешение по вреду не отменяет ступеней.
	in.Portfolio = Portfolio{idB: {Status: core.StatusCandidate, Collateral: true, CollateralAllowed: true}}
	dec = d.Decide(tab, in)
	if dec.Action != ActionKeep || dec.Trial != idB {
		t.Fatalf("решение = %v, проверка %q; ожидалось keep с кандидатом на доле", dec.Action, dec.Trial)
	}
}

// TestCollateralBlocksReplacementOfBroken: менять сорвавшуюся на вредящую —
// не починка.
func TestCollateralBlocksReplacementOfBroken(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, key(idA), base)
	observe(tab, key(idA), core.OutcomeFail, 3, base)
	proven(tab, key(idB), base) // годен по оценке, но вредит
	proven(tab, key(idC), base) // годен и безвреден

	dec := d.Decide(tab, Input{
		Target:  target,
		Vantage: vantage,
		State:   TargetState{Current: idA, Since: base.Add(-time.Hour)},
		Portfolio: Portfolio{
			idA: {Status: core.StatusActive},
			idB: {Status: core.StatusBenched, Collateral: true},
			idC: {Status: core.StatusBenched},
		},
		Now: base,
	})

	if dec.StrategyID != idC {
		t.Fatalf("замена = %q, ожидалась %q (idB вредит)", dec.StrategyID, idC)
	}
}

// TestBlackoutRaisesTrialShare — 5.8: когда не работает ничего, доля
// эксперимента повышается, и это видно признаком, а не только в логе.
func TestBlackoutRaisesTrialShare(t *testing.T) {
	cfg := DefaultConfig()
	d := newDeciderCfg(t, cfg)
	cand := splitStrategy(9)
	candID := mustID(t, cand)

	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, scoring.Key{StrategyID: candID, Target: "youtube.com", VantageID: vantage}, base)

	plan := d.BuildPlan(tab, PlanInput{
		Vantage:   vantage,
		Targets:   []string{"youtube.com"},
		Portfolio: Portfolio{candID: {Strategy: cand, Status: core.StatusCandidate}},
		Now:       base,
	})

	if !plan.Blackout {
		t.Fatal("в радиусе нет действующих стратегий — это обвал портфеля")
	}
	if plan.TrialPermille != cfg.BlackoutTrialPermille {
		t.Fatalf("доля проверки = %d, ожидалась повышенная %d", plan.TrialPermille, cfg.BlackoutTrialPermille)
	}
	if plan.Entries[0].TrialPermille != cfg.BlackoutTrialPermille {
		t.Fatalf("доля в записи = %d, ожидалась %d", plan.Entries[0].TrialPermille, cfg.BlackoutTrialPermille)
	}
	// Запись обязана быть пригодной для публикации.
	if _, err := policy.NewSnapshot(vantage, 1, plan.Entries); err != nil {
		t.Fatalf("снимок из плана обязан строиться: %v", err)
	}
}

func TestNoBlackoutWhenSomethingActive(t *testing.T) {
	cfg := DefaultConfig()
	d := newDeciderCfg(t, cfg)
	s := splitStrategy(5)
	id := mustID(t, s)

	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, scoring.Key{StrategyID: id, Target: "youtube.com", VantageID: vantage}, base)

	plan := d.BuildPlan(tab, PlanInput{
		Vantage:   vantage,
		Targets:   []string{"youtube.com"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusActive}},
		States: map[string]TargetState{
			"youtube.com": {Current: id, Since: base.Add(-time.Hour)},
		},
		Now: base,
	})

	if plan.Blackout {
		t.Fatal("действующая стратегия есть — обвала нет")
	}
	if plan.TrialPermille != cfg.TrialPermille {
		t.Fatalf("доля проверки = %d, ожидалась обычная %d", plan.TrialPermille, cfg.TrialPermille)
	}
}

// TestEmptyRadiusIsNotBlackout: пустой радиус — это «нечего применять», а не
// «всё сломалось». Тревога на пустом радиусе была бы ложной.
func TestEmptyRadiusIsNotBlackout(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())

	plan := d.BuildPlan(tab, PlanInput{Vantage: vantage, Now: base})
	if plan.Blackout {
		t.Fatal("пустой радиус не является обвалом портфеля")
	}
}

// TestTrialDisabledByConfig: доля ноль — законная настройка «не рисковать
// живым трафиком», и тогда кандидат не получает соединений, а причина видна.
func TestTrialDisabledByConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrialPermille = 0
	cfg.BlackoutTrialPermille = 0
	d := newDeciderCfg(t, cfg)

	cand := splitStrategy(9)
	candID := mustID(t, cand)
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, scoring.Key{StrategyID: candID, Target: "youtube.com", VantageID: vantage}, base)

	plan := d.BuildPlan(tab, PlanInput{
		Vantage:   vantage,
		Targets:   []string{"youtube.com"},
		Portfolio: Portfolio{candID: {Strategy: cand, Status: core.StatusCandidate}},
		Now:       base,
	})

	if plan.Entries[0].Trial != nil || plan.Entries[0].TrialPermille != 0 {
		t.Fatal("при выключенной доле проверяемая стратегия не должна попадать в запись")
	}
	if plan.Decisions[0].TrialReason != ReasonTrialDisabled {
		t.Fatalf("причина = %q, ожидалась %q", plan.Decisions[0].TrialReason, ReasonTrialDisabled)
	}
	// Запись без проверки обязана остаться пригодной для публикации.
	if _, err := policy.NewSnapshot(vantage, 1, plan.Entries); err != nil {
		t.Fatalf("снимок из плана обязан строиться: %v", err)
	}
}

func TestTransitionsFollowDecisions(t *testing.T) {
	d := newDecider(t)
	active := splitStrategy(5)
	activeID := mustID(t, active)
	cand := splitStrategy(9)
	candID := mustID(t, cand)

	tab := newTable(t, scoring.DefaultConfig())
	k := func(id core.StrategyID, target string) scoring.Key {
		return scoring.Key{StrategyID: id, Target: target, VantageID: vantage}
	}

	t.Run("кандидат уходит в testing", func(t *testing.T) {
		proven(tab, k(candID, "youtube.com"), base)
		plan := d.BuildPlan(tab, PlanInput{
			Vantage:   vantage,
			Targets:   []string{"youtube.com"},
			Portfolio: Portfolio{candID: {Strategy: cand, Status: core.StatusCandidate}},
			Now:       base,
		})
		if !hasTransition(plan.Transitions, candID, core.StatusCandidate, core.StatusTesting) {
			t.Fatalf("переход candidate→testing не предложен: %+v", plan.Transitions)
		}
	})

	t.Run("применённая уходит в active, прежняя на полку", func(t *testing.T) {
		tab := newTable(t, scoring.DefaultConfig())
		proven(tab, k(activeID, "discord.com"), base)
		proven(tab, k(candID, "discord.com"), base)
		observe(tab, k(candID, "discord.com"), core.OutcomeOK, 10, base)

		plan := d.BuildPlan(tab, PlanInput{
			Vantage: vantage,
			Targets: []string{"discord.com"},
			States: map[string]TargetState{
				"discord.com": {Current: activeID, Since: base.Add(-2 * DefaultConfig().MinDwell)},
			},
			Portfolio: Portfolio{
				activeID: {Strategy: active, Status: core.StatusActive},
				candID:   {Strategy: cand, Status: core.StatusTesting},
			},
			Now: base,
		})

		if !hasTransition(plan.Transitions, candID, core.StatusTesting, core.StatusActive) {
			t.Fatalf("переход testing→active не предложен: %+v", plan.Transitions)
		}
		if !hasTransition(plan.Transitions, activeID, core.StatusActive, core.StatusBenched) {
			t.Fatalf("прежняя стратегия должна уйти на полку: %+v", plan.Transitions)
		}
	})

	t.Run("сорвавшаяся уходит в degraded", func(t *testing.T) {
		tab := newTable(t, scoring.DefaultConfig())
		proven(tab, k(activeID, "discord.com"), base)
		observe(tab, k(activeID, "discord.com"), core.OutcomeFail, 3, base)

		plan := d.BuildPlan(tab, PlanInput{
			Vantage: vantage,
			Targets: []string{"discord.com"},
			States: map[string]TargetState{
				"discord.com": {Current: activeID, Since: base.Add(-time.Hour)},
			},
			Portfolio: Portfolio{activeID: {Strategy: active, Status: core.StatusActive}},
			Now:       base,
		})

		if !hasTransition(plan.Transitions, activeID, core.StatusActive, core.StatusDegraded) {
			t.Fatalf("сорвавшаяся должна уйти в degraded, а не на полку: %+v", plan.Transitions)
		}
	})
}

func hasTransition(list []Transition, id core.StrategyID, from, to core.Status) bool {
	for _, tr := range list {
		if tr.StrategyID == id && tr.From == from && tr.To == to {
			return true
		}
	}
	return false
}

// TestMergeTakesFurthestRung: статус у стратегии один, а решений по ней
// столько, сколько целей. Сводится самая далёкая ступень, а запрет сильнее
// любого повышения.
func TestMergeTakesFurthestRung(t *testing.T) {
	merged := Merge([]Transition{
		{StrategyID: idA, Target: "a.com", To: core.StatusTesting},
		{StrategyID: idA, Target: "b.com", To: core.StatusActive},
		{StrategyID: idB, Target: "a.com", To: core.StatusActive},
		{StrategyID: idB, Target: "b.com", To: core.StatusDegraded},
	})

	if merged[idA] != core.StatusActive {
		t.Fatalf("статус idA = %v, ожидался active (самая далёкая ступень)", merged[idA])
	}
	if merged[idB] != core.StatusDegraded {
		t.Fatalf("статус idB = %v, ожидался degraded: срыв сильнее повышения", merged[idB])
	}
}

func TestConfigRejectsShareAboveCeiling(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrialPermille = 500
	if _, err := NewDecider(cfg); err == nil {
		t.Fatal("доля проверки выше жёсткого потолка 5.7 должна быть отвергнута")
	}

	cfg = DefaultConfig()
	cfg.BlackoutTrialPermille = 10 // меньше обычной
	if _, err := NewDecider(cfg); err == nil {
		t.Fatal("доля при обвале не может быть меньше обычной")
	}

	cfg = DefaultConfig()
	cfg.BlackoutTrialPermille = 1001
	if _, err := NewDecider(cfg); err == nil {
		t.Fatal("доля больше 1000 промилле бессмысленна и должна быть отвергнута")
	}
}

// TestPlanTrialsReachSnapshot — сквозная проверка: кандидат доходит от плана
// до горячей таблицы и получает свою долю соединений.
func TestPlanTrialsReachSnapshot(t *testing.T) {
	d := newDecider(t)
	active := splitStrategy(5)
	activeID := mustID(t, active)
	cand := splitStrategy(9)
	candID := mustID(t, cand)

	tab := newTable(t, scoring.DefaultConfig())
	kk := func(id core.StrategyID) scoring.Key {
		return scoring.Key{StrategyID: id, Target: "youtube.com", VantageID: vantage}
	}
	proven(tab, kk(activeID), base)
	proven(tab, kk(candID), base)

	plan := d.BuildPlan(tab, PlanInput{
		Vantage: vantage,
		Targets: []string{"youtube.com"},
		States: map[string]TargetState{
			"youtube.com": {Current: activeID, Since: base.Add(-time.Hour)},
		},
		Portfolio: Portfolio{
			activeID: {Strategy: active, Status: core.StatusActive},
			candID:   {Strategy: cand, Status: core.StatusCandidate},
		},
		Now: base,
	})

	snap, err := policy.NewSnapshot(vantage, 1, plan.Entries)
	if err != nil {
		t.Fatalf("policy.NewSnapshot: %v", err)
	}
	recs := snap.Records()
	if len(recs) != 1 {
		t.Fatalf("записей = %d, ожидалась одна", len(recs))
	}
	if recs[0].Active != activeID || recs[0].Trial != candID {
		t.Fatalf("запись = %+v, ожидались active %q и trial %q", recs[0], activeID, candID)
	}
	if recs[0].TrialPermille != DefaultConfig().TrialPermille {
		t.Fatalf("доля = %d, ожидалась %d", recs[0].TrialPermille, DefaultConfig().TrialPermille)
	}

	// И обе ветви действительно выдаются соединениям.
	var sawActive, sawTrial bool
	for range 20000 {
		sel, _ := snap.Lookup("www.youtube.com", "")
		switch sel.Strategy {
		case active:
			sawActive = true
		case cand:
			if !sel.Trial {
				t.Fatal("проверочная ветвь обязана быть помечена")
			}
			sawTrial = true
		}
	}
	if !sawActive || !sawTrial {
		t.Fatalf("обе ветви должны встречаться: действующая %v, проверочная %v", sawActive, sawTrial)
	}
}

// Проверка, что портфель отдаёт идентификаторы в устойчивом порядке: вывод
// команды portfolio обязан быть воспроизводимым.
func TestPortfolioStrategyIDsSorted(t *testing.T) {
	p := Portfolio{
		idC: {Status: core.StatusCandidate},
		idA: {Status: core.StatusActive},
		idB: {Status: core.StatusBenched},
	}
	ids := p.StrategyIDs()
	if len(ids) != 3 || ids[0] != idA || ids[1] != idB || ids[2] != idC {
		t.Fatalf("порядок = %v, ожидался отсортированный", ids)
	}
}

var _ = strategy.ComputeID
