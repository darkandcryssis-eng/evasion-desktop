package control

import (
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/policy"
	"github.com/fitting-1c/evasion/internal/scoring"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// splitStrategy — отличимая по идентификатору стратегия; разрез здесь не
// исполняется.
func splitStrategy(offset int) *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: offset, Order: strategy.FragForward},
			Left:   &strategy.Action{Kind: core.ActionSend},
			Right:  &strategy.Action{Kind: core.ActionSend},
		},
	}}}
}

func mustID(t *testing.T, s *strategy.Strategy) core.StrategyID {
	t.Helper()
	id, err := strategy.ComputeID(s)
	if err != nil {
		t.Fatalf("ComputeID: %v", err)
	}
	return id
}

// TestBuildPlanCoversEveryTarget — инвариант: у каждой цели радиуса ровно одна
// запись, в том числе у цели без стратегии.
//
// Это не формальность. Без записи-исключения на "api.youtube.com" подействовала
// бы запись "youtube.com" из того же радиуса, и «выключено» означало бы
// «применено что-то другое».
func TestBuildPlanCoversEveryTarget(t *testing.T) {
	d := newDecider(t)
	s := splitStrategy(5)
	id := mustID(t, s)

	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, scoring.Key{StrategyID: id, Target: "youtube.com", VantageID: vantage}, base)

	plan := d.BuildPlan(tab, PlanInput{
		Vantage:   vantage,
		Targets:   []string{"youtube.com", "api.youtube.com"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusActive}},
		Now:       base,
	})

	if len(plan.Entries) != 2 || len(plan.Decisions) != 2 {
		t.Fatalf("записей %d, решений %d, ожидалось по 2", len(plan.Entries), len(plan.Decisions))
	}
	// Порядок отсортирован, значит api.youtube.com идёт первой.
	if plan.Entries[0].Domain != "api.youtube.com" || plan.Entries[1].Domain != "youtube.com" {
		t.Fatalf("порядок целей = %q, %q, ожидался отсортированный",
			plan.Entries[0].Domain, plan.Entries[1].Domain)
	}
	if plan.Entries[0].Strategy != nil {
		t.Fatal("цели без доказательств должна достаться запись-исключение")
	}
	if plan.Entries[1].Strategy != s {
		t.Fatal("цели с доказанной стратегией должна достаться она")
	}

	// И главное: исключение действительно перекрывает общую запись.
	snap, err := policy.NewSnapshot(vantage, 1, plan.Entries)
	if err != nil {
		t.Fatalf("policy.NewSnapshot: %v", err)
	}
	sel, ok := snap.Lookup("api.youtube.com", "")
	if !ok {
		t.Fatal("исключение обязано считаться попаданием в таблицу")
	}
	if sel.Strategy != nil {
		t.Fatal("запись youtube.com не должна подействовать на api.youtube.com")
	}
	if sel, _ := snap.Lookup("www.youtube.com", ""); sel.Strategy != s {
		t.Fatal("поддомен youtube.com должен получить её стратегию")
	}
}

// TestBuildPlanFeedsSnapshot — сквозная проверка стыка control → policy:
// план строится, снимок публикуется, идентификатор доходит до выбора.
func TestBuildPlanFeedsSnapshot(t *testing.T) {
	d := newDecider(t)
	s := splitStrategy(7)
	id := mustID(t, s)

	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, scoring.Key{StrategyID: id, Target: "discord.com", VantageID: vantage}, base)

	plan := d.BuildPlan(tab, PlanInput{
		Vantage:   vantage,
		Targets:   []string{"discord.com"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusActive}},
		Now:       base,
	})

	snap, err := policy.NewSnapshot(vantage, 1, plan.Entries)
	if err != nil {
		t.Fatalf("policy.NewSnapshot: %v", err)
	}
	tbl := policy.NewTable()
	tbl.Install(snap)

	sel, _ := snap.Lookup("gateway.discord.com", "")
	if sel.Strategy != s {
		t.Fatal("стратегия не доехала от плана до снимка")
	}
	if sel.ID != id {
		t.Fatalf("идентификатор в снимке = %q, ожидался %q: телеметрия свяжет исход не с той стратегией", sel.ID, id)
	}
}

// TestBuildPlanUnknownStrategyDegrades: стратегия пропала из портфеля — цель
// деградирует в прозрачный пропуск, но причина видна, а остальные цели не
// страдают.
func TestBuildPlanUnknownStrategyDegrades(t *testing.T) {
	d := newDecider(t)
	alive := splitStrategy(5)
	aliveID := mustID(t, alive)
	lostID := core.StrategyID("deadbeef")

	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, scoring.Key{StrategyID: aliveID, Target: "youtube.com", VantageID: vantage}, base)

	plan := d.BuildPlan(tab, PlanInput{
		Vantage: vantage,
		Targets: []string{"youtube.com", "discord.com"},
		// discord.com ссылается на стратегию, которой в портфеле нет.
		States: map[string]TargetState{
			"discord.com": {Current: lostID, Since: base.Add(-time.Hour)},
		},
		Portfolio: Portfolio{aliveID: {Strategy: alive, Status: core.StatusActive}},
		Now:       base,
	})

	byTarget := make(map[string]Decision, len(plan.Decisions))
	for _, dec := range plan.Decisions {
		byTarget[dec.Target] = dec
	}

	lost := byTarget["discord.com"]
	if lost.Action != ActionDisable || lost.Reason != ReasonUnknownStrategy {
		t.Fatalf("решение по discord.com = %v/%q, ожидалось disable/unknown_strategy", lost.Action, lost.Reason)
	}
	if byTarget["youtube.com"].Action != ActionApply {
		t.Fatal("пропажа стратегии у одной цели не должна задевать другую")
	}
	for _, e := range plan.Entries {
		if e.Domain == "discord.com" && e.Strategy != nil {
			t.Fatal("цели с пропавшей стратегией должна достаться запись-исключение")
		}
	}
}

// TestBuildPlanNilStrategyInPortfolioDegrades: запись в портфеле есть, но она
// пустая — это тот же дефект, что отсутствие записи, и лечится так же.
func TestBuildPlanNilStrategyInPortfolioDegrades(t *testing.T) {
	d := newDecider(t)
	id := core.StrategyID("aaaa")
	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, scoring.Key{StrategyID: id, Target: "youtube.com", VantageID: vantage}, base)

	plan := d.BuildPlan(tab, PlanInput{
		Vantage:   vantage,
		Targets:   []string{"youtube.com"},
		Portfolio: Portfolio{id: {Status: core.StatusActive}},
		Now:       base,
	})

	if plan.Decisions[0].Reason != ReasonUnknownStrategy {
		t.Fatalf("причина = %q, ожидалась %q", plan.Decisions[0].Reason, ReasonUnknownStrategy)
	}
	if plan.Entries[0].Strategy != nil {
		t.Fatal("пустая стратегия не должна попадать в снимок")
	}
}

// TestBuildPlanDedupesTargets: одна цель может входить в две группы радиуса, и
// повтор не должен превращаться в повторную запись — policy такой снимок
// отвергнет.
func TestBuildPlanDedupesTargets(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())

	targets := []string{"youtube.com", "discord.com", "youtube.com"}
	plan := d.BuildPlan(tab, PlanInput{Vantage: vantage, Targets: targets, Now: base})

	if len(plan.Entries) != 2 {
		t.Fatalf("записей = %d, ожидалось 2 (повтор сведён)", len(plan.Entries))
	}
	if _, err := policy.NewSnapshot(vantage, 1, plan.Entries); err != nil {
		t.Fatalf("снимок из плана обязан строиться: %v", err)
	}

	// Вход не изменён: вызывающий отдал свой срез, а не владение им.
	// Сравнивается весь порядок, а не отдельный элемент: при сортировке на
	// месте повтор возвращается на своё место, и проверка одного элемента
	// проходила бы при изменённом срезе (первая версия теста была именно
	// такой и ничего не проверяла).
	want := []string{"youtube.com", "discord.com", "youtube.com"}
	for i := range want {
		if targets[i] != want[i] {
			t.Fatalf("срез вызывающего изменён: %v, ожидался %v", targets, want)
		}
	}
}

func TestBuildPlanEmptyRadius(t *testing.T) {
	d := newDecider(t)
	tab := newTable(t, scoring.DefaultConfig())

	plan := d.BuildPlan(tab, PlanInput{Vantage: vantage, Now: base})
	if len(plan.Entries) != 0 || len(plan.Decisions) != 0 {
		t.Fatal("пустой радиус даёт пустой план")
	}
	// Пустой снимок законен: он не совпадает ни с чем.
	snap, err := policy.NewSnapshot(vantage, 1, plan.Entries)
	if err != nil {
		t.Fatalf("policy.NewSnapshot: %v", err)
	}
	if snap.Len() != 0 {
		t.Fatalf("длина снимка = %d, ожидался пустой", snap.Len())
	}
}

// TestPlanChangesListsOnlySwitches: журналу нужны смены, а не каждый опрос.
func TestPlanChangesListsOnlySwitches(t *testing.T) {
	d := newDecider(t)
	s := splitStrategy(5)
	id := mustID(t, s)

	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, scoring.Key{StrategyID: id, Target: "youtube.com", VantageID: vantage}, base)
	proven(tab, scoring.Key{StrategyID: id, Target: "discord.com", VantageID: vantage}, base)

	plan := d.BuildPlan(tab, PlanInput{
		Vantage: vantage,
		Targets: []string{"youtube.com", "discord.com"},
		States: map[string]TargetState{
			// discord.com уже работает по этой стратегии: смены нет.
			"discord.com": {Current: id, Since: base.Add(-2 * DefaultConfig().MinDwell)},
		},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusActive}},
		Now:       base,
	})

	changes := plan.Changes()
	if len(changes) != 1 || changes[0].Target != "youtube.com" {
		t.Fatalf("смены = %v, ожидалась одна по youtube.com", changes)
	}
}

// TestBuildPlanPinsPerTarget: закрепление действует на свою цель и не
// расползается на остальные.
func TestBuildPlanPinsPerTarget(t *testing.T) {
	d := newDecider(t)
	pinned := splitStrategy(11)
	pinnedID := mustID(t, pinned)

	tab := newTable(t, scoring.DefaultConfig()) // доказательств нет ни у кого

	plan := d.BuildPlan(tab, PlanInput{
		Vantage:   vantage,
		Targets:   []string{"youtube.com", "discord.com"},
		Pins:      map[string]core.StrategyID{"youtube.com": pinnedID},
		Portfolio: Portfolio{pinnedID: {Strategy: pinned, Status: core.StatusActive}},
		Now:       base,
	})

	byTarget := make(map[string]policy.Entry, len(plan.Entries))
	for _, e := range plan.Entries {
		byTarget[e.Domain] = e
	}
	if byTarget["youtube.com"].Strategy != pinned {
		t.Fatal("закреплённая стратегия должна применяться без доказательств")
	}
	if byTarget["discord.com"].Strategy != nil {
		t.Fatal("закрепление одной цели не должно задевать другую")
	}
}

// TestBuildPlanBlackoutBootstrapsBestCandidate — при полном обвале портфеля
// лучший кандидат с успехами попадает на повышенную долю сразу, не дожидаясь
// порога 5.5 (5.8). Негодный кандидат (только провалы) не берётся.
//
// Это чинит прогрев автопилота v2: без bootstrap цель лежала прозрачным
// пропуском все минуты, пока песочница добирала 20 проверок, и youtube был
// недоступен весь прогрев — вопреки 1.1.
func TestBuildPlanBlackoutBootstrapsBestCandidate(t *testing.T) {
	d := newDecider(t)
	good := splitStrategy(5)
	goodID := mustID(t, good)
	bad := splitStrategy(9)
	badID := mustID(t, bad)

	tab := newTable(t, scoring.DefaultConfig())
	// Лучший кандидат: успехи, но МЕНЬШЕ порога (20) — обычная лестница его бы
	// на долю не пустила.
	observe(tab, scoring.Key{StrategyID: goodID, Target: "youtube.com", VantageID: vantage}, core.OutcomeOK, 6, base)
	// Негодный: только провалы — брать его нельзя даже в обвале.
	observe(tab, scoring.Key{StrategyID: badID, Target: "youtube.com", VantageID: vantage}, core.OutcomeFail, 6, base)
	blocked(tab, "youtube.com", vantage, base)

	plan := d.BuildPlan(tab, PlanInput{
		Vantage: vantage,
		Targets: []string{"youtube.com"},
		Portfolio: Portfolio{
			goodID: {Strategy: good, Status: core.StatusCandidate},
			badID:  {Strategy: bad, Status: core.StatusCandidate},
		},
		Now: base,
	})

	if !plan.Blackout {
		t.Fatal("ожидался обвал: ни одна стратегия не применяется ко всему трафику")
	}
	dec := plan.Decisions[0]
	if dec.Trial != goodID {
		t.Fatalf("на доле обвала ожидался лучший кандидат %q, получен %q (%s)", goodID, dec.Trial, dec.TrialReason)
	}
	if dec.TrialReason != ReasonBlackoutBootstrap {
		t.Fatalf("причина доли = %q, ожидалась blackout_bootstrap", dec.TrialReason)
	}
	if plan.Entries[0].TrialPermille != DefaultConfig().BlackoutTrialPermille {
		t.Fatalf("доля = %d, ожидалась обвальная %d", plan.Entries[0].TrialPermille, DefaultConfig().BlackoutTrialPermille)
	}
	if plan.Entries[0].Trial != good {
		t.Fatal("запись должна нести дерево кандидата на доле")
	}
	if plan.Entries[0].Strategy != nil {
		t.Fatal("действующей стратегии в обвале быть не должно — остальной трафик прозрачен")
	}
	// Кандидат переходит в testing: его теперь проверяют и на живом трафике.
	if st := Merge(plan.Transitions); st[goodID] != core.StatusTesting {
		t.Fatalf("ступень кандидата = %v, ожидалась testing", st[goodID])
	}
}

// TestBuildPlanNoBootstrapOutsideBlackout — вне обвала bootstrap не
// срабатывает: кандидат ниже порога на долю не попадает, лестница 5.1 цела.
func TestBuildPlanNoBootstrapOutsideBlackout(t *testing.T) {
	d := newDecider(t)
	active := splitStrategy(1)
	activeID := mustID(t, active)
	cand := splitStrategy(5)
	candID := mustID(t, cand)

	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, scoring.Key{StrategyID: activeID, Target: "youtube.com", VantageID: vantage}, base)
	// Кандидат с парой успехов, но ниже порога.
	observe(tab, scoring.Key{StrategyID: candID, Target: "youtube.com", VantageID: vantage}, core.OutcomeOK, 4, base)

	plan := d.BuildPlan(tab, PlanInput{
		Vantage: vantage,
		Targets: []string{"youtube.com"},
		States:  map[string]TargetState{"youtube.com": {Current: activeID, Since: base}},
		Portfolio: Portfolio{
			activeID: {Strategy: active, Status: core.StatusActive},
			candID:   {Strategy: cand, Status: core.StatusCandidate},
		},
		Now: base,
	})

	if plan.Blackout {
		t.Fatal("обвала быть не должно: действующая стратегия применяется")
	}
	if plan.Decisions[0].TrialReason == ReasonBlackoutBootstrap {
		t.Fatal("вне обвала bootstrap срабатывать не должен")
	}
}

// TestBuildPlanBlackoutPrefersMoreProven — на доле обвала выбирается кандидат с
// более высокой нижней границей доли успехов, а кандидат с слишком малым
// объёмом (меньше bootstrapMinConclusive) не берётся: защита от шума на первых
// пробах, из-за которого выбор на доле дёргался.
func TestBuildPlanBlackoutPrefersMoreProven(t *testing.T) {
	d := newDecider(t)
	strong := splitStrategy(1) // много успехов — высокая нижняя граница
	strongID := mustID(t, strong)
	weak := splitStrategy(5) // успехи есть, но объёма мало
	weakID := mustID(t, weak)
	tiny := splitStrategy(9) // определённых меньше порога bootstrap
	tinyID := mustID(t, tiny)

	tab := newTable(t, scoring.DefaultConfig())
	k := func(id core.StrategyID) scoring.Key {
		return scoring.Key{StrategyID: id, Target: "youtube.com", VantageID: vantage}
	}
	observe(tab, k(strongID), core.OutcomeOK, 12, base)
	observe(tab, k(weakID), core.OutcomeOK, 4, base)
	observe(tab, k(tinyID), core.OutcomeOK, 2, base) // 2 < 3 → не допускается
	blocked(tab, "youtube.com", vantage, base)

	plan := d.BuildPlan(tab, PlanInput{
		Vantage: vantage,
		Targets: []string{"youtube.com"},
		Portfolio: Portfolio{
			strongID: {Strategy: strong, Status: core.StatusCandidate},
			weakID:   {Strategy: weak, Status: core.StatusCandidate},
			tinyID:   {Strategy: tiny, Status: core.StatusCandidate},
		},
		Now: base,
	})

	if !plan.Blackout {
		t.Fatal("ожидался обвал")
	}
	if plan.Decisions[0].Trial != strongID {
		t.Fatalf("на доле ожидался наиболее доказанный %q, получен %q", strongID, plan.Decisions[0].Trial)
	}
}

// TestBuildPlanExpandsCoverageToGroup — решение по представителю группы
// разворачивается на все домены группы одной стратегией. Так вся группа
// (youtube.com + googlevideo.com + ytimg.com) обходится приёмом, доказанным
// только на youtube.com: недообследованные домены иначе остались бы голыми.
func TestBuildPlanExpandsCoverageToGroup(t *testing.T) {
	d := newDecider(t)
	s := splitStrategy(5)
	id := mustID(t, s)

	tab := newTable(t, scoring.DefaultConfig())
	proven(tab, scoring.Key{StrategyID: id, Target: "youtube.com", VantageID: vantage}, base)

	plan := d.BuildPlan(tab, PlanInput{
		Vantage:   vantage,
		Targets:   []string{"youtube.com"},
		Portfolio: Portfolio{id: {Strategy: s, Status: core.StatusActive}},
		Coverage: map[string][]string{
			"youtube.com": {"youtube.com", "googlevideo.com", "ytimg.com"},
		},
		Now: base,
	})

	// Решение одно (по представителю), а записей три — на всю группу.
	if len(plan.Decisions) != 1 {
		t.Fatalf("решений %d, ожидалось 1 (по представителю)", len(plan.Decisions))
	}
	if len(plan.Entries) != 3 {
		t.Fatalf("записей %d, ожидалось 3 (вся группа)", len(plan.Entries))
	}
	snap, err := policy.NewSnapshot(vantage, 1, plan.Entries)
	if err != nil {
		t.Fatalf("policy.NewSnapshot: %v", err)
	}
	for _, host := range []string{"www.youtube.com", "rr1.googlevideo.com", "i.ytimg.com"} {
		if sel, ok := snap.Lookup(host, ""); !ok || sel.Strategy != s {
			t.Fatalf("домен %s должен получить стратегию группы (ok=%v)", host, ok)
		}
	}
}
