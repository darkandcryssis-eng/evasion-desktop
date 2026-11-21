package desync

import (
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// fragmentDelayed строит стратегию с разрезом по смещению и паузой.
func fragmentDelayed(offset, delayMs int, order strategy.FragOrder) *strategy.Strategy {
	return &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind: core.ActionFragment,
			Params: &strategy.FragmentParams{
				Proto: strategy.FragTCP, Offset: offset, Order: order, DelayMs: delayMs,
			},
			Left:  &strategy.Action{Kind: core.ActionSend},
			Right: &strategy.Action{Kind: core.ActionSend},
		},
	}}}
}

// opSummary возвращает пары «нагрузка, пауза перед отправкой».
func opSummary(p Plan) []struct {
	payload string
	delay   time.Duration
} {
	out := make([]struct {
		payload string
		delay   time.Duration
	}, 0, len(p.Ops))
	for _, op := range p.Ops {
		out = append(out, struct {
			payload string
			delay   time.Duration
		}{string(op.Payload), op.DelayBefore})
	}
	return out
}

func TestDelayAppliesToSecondSentPart(t *testing.T) {
	plan, err := BuildPlan(fragmentDelayed(3, 250, strategy.FragForward), helloWithCuts("ABCDEFGH"))
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	got := opSummary(plan)
	if len(got) != 2 {
		t.Fatalf("операций %d, ожидалось 2", len(got))
	}
	if got[0].payload != "ABC" || got[0].delay != 0 {
		t.Fatalf("первая операция: %q пауза %v", got[0].payload, got[0].delay)
	}
	if got[1].payload != "DEFGH" || got[1].delay != 250*time.Millisecond {
		t.Fatalf("вторая операция: %q пауза %v", got[1].payload, got[1].delay)
	}
}

func TestDelayFollowsSendOrderNotTreeBranch(t *testing.T) {
	// При обратном порядке вторая ветвь уходит ПЕРВОЙ, значит пауза должна
	// достаться первой ветви — она уходит второй. Привязка паузы к ветви
	// дерева, а не к порядку отправки, поставила бы её перед самым началом
	// отправки, где она ничего не задерживает.
	plan, err := BuildPlan(fragmentDelayed(3, 250, strategy.FragReverse), helloWithCuts("ABCDEFGH"))
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	got := opSummary(plan)
	if len(got) != 2 {
		t.Fatalf("операций %d, ожидалось 2", len(got))
	}
	// Порядок обратный: сначала "DEFGH", затем "ABC" с паузой.
	if got[0].payload != "DEFGH" || got[0].delay != 0 {
		t.Fatalf("первая отправка: %q пауза %v", got[0].payload, got[0].delay)
	}
	if got[1].payload != "ABC" || got[1].delay != 250*time.Millisecond {
		t.Fatalf("вторая отправка: %q пауза %v", got[1].payload, got[1].delay)
	}
}

func TestDelayZeroMeansNoPause(t *testing.T) {
	plan, err := BuildPlan(fragmentDelayed(3, 0, strategy.FragForward), helloWithCuts("ABCDEFGH"))
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	for i, op := range plan.Ops {
		if op.DelayBefore != 0 {
			t.Fatalf("операция %d получила паузу %v при нулевой задержке", i, op.DelayBefore)
		}
	}
}

func TestNestedDelaysLandOnTheirOwnParts(t *testing.T) {
	// Обычная вложенность: паузы приходятся на разные операции.
	// Внешняя 100 мс — перед второй частью внешнего разреза, внутренняя 50 мс —
	// перед второй частью внутреннего.
	s := &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 2, DelayMs: 100},
			Left:   &strategy.Action{Kind: core.ActionSend},
			Right: &strategy.Action{
				Kind:   core.ActionFragment,
				Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 3, DelayMs: 50},
				Left:   &strategy.Action{Kind: core.ActionSend},
				Right:  &strategy.Action{Kind: core.ActionSend},
			},
		},
	}}}

	plan, err := BuildPlan(s, helloWithCuts("ABCDEFGH"))
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	got := opSummary(plan)
	// "AB" | "CDE" | "FGH": внешняя пауза перед "CDE", внутренняя перед "FGH".
	if len(got) != 3 {
		t.Fatalf("операций %d, ожидалось 3: %+v", len(got), got)
	}
	if got[0].delay != 0 {
		t.Fatalf("первая операция получила паузу %v", got[0].delay)
	}
	if got[1].payload != "CDE" || got[1].delay != 100*time.Millisecond {
		t.Fatalf("вторая операция: %q пауза %v, ожидалось CDE и 100мс", got[1].payload, got[1].delay)
	}
	if got[2].payload != "FGH" || got[2].delay != 50*time.Millisecond {
		t.Fatalf("третья операция: %q пауза %v, ожидалось FGH и 50мс", got[2].payload, got[2].delay)
	}
}

func TestNestedDelaysAccumulateOnSameOperation(t *testing.T) {
	// Случай, когда одна и та же операция получает паузу дважды, — именно он
	// требует сложения, а не замещения.
	//
	// Устроен так: внутренний разрез идёт в обратном порядке, и его вторая
	// ветвь отбрасывается. Тогда от внутреннего разреза остаётся единственная
	// операция, и она оказывается одновременно и его второй по отправке
	// частью (пауза 50 мс), и первой операцией второй группы внешнего разреза
	// (пауза 100 мс). Итог обязан быть 150 мс.
	//
	// Конфигурация выглядит вычурно, но достижима: генератор порождает
	// структуру дерева, а не осмысленные сочетания. Замещение здесь молча
	// отменяло бы задержку внутреннего разреза.
	s := &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 2, DelayMs: 100},
			Left:   &strategy.Action{Kind: core.ActionSend},
			Right: &strategy.Action{
				Kind: core.ActionFragment,
				Params: &strategy.FragmentParams{
					Proto: strategy.FragTCP, Offset: 3,
					Order: strategy.FragReverse, DelayMs: 50,
				},
				Left:  &strategy.Action{Kind: core.ActionSend},
				Right: &strategy.Action{Kind: core.ActionDrop},
			},
		},
	}}}

	plan, err := BuildPlan(s, helloWithCuts("ABCDEFGH"))
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	got := opSummary(plan)
	if len(got) != 2 {
		t.Fatalf("операций %d, ожидалось 2: %+v", len(got), got)
	}
	if got[0].payload != "AB" || got[0].delay != 0 {
		t.Fatalf("первая операция: %q пауза %v", got[0].payload, got[0].delay)
	}
	if got[1].payload != "CDE" {
		t.Fatalf("вторая операция: %q, ожидалось CDE", got[1].payload)
	}
	if want := 150 * time.Millisecond; got[1].delay != want {
		t.Fatalf("паузы не сложились: получено %v, ожидалось %v", got[1].delay, want)
	}
}

func TestDelayNotAssignedToEmptyGroup(t *testing.T) {
	// Вторая ветвь отбрасывается: задерживать нечего, и пауза не должна
	// достаться первой части.
	s := &strategy.Strategy{Rules: []strategy.Rule{{
		Direction: core.DirectionOutbound,
		Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
		Action: &strategy.Action{
			Kind:   core.ActionFragment,
			Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: 3, DelayMs: 250},
			Left:   &strategy.Action{Kind: core.ActionSend},
			Right:  &strategy.Action{Kind: core.ActionDrop},
		},
	}}}
	plan, err := BuildPlan(s, helloWithCuts("ABCDEFGH"))
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.Ops) != 1 {
		t.Fatalf("операций %d, ожидалась 1", len(plan.Ops))
	}
	if plan.Ops[0].DelayBefore != 0 {
		t.Fatalf("единственная операция получила паузу %v", plan.Ops[0].DelayBefore)
	}
}

func TestDelayRequiresCapability(t *testing.T) {
	// Пауза объявляется возможностью: исполнитель, который её не соблюдает,
	// обязан отвергнуть стратегию, а не исполнить её иначе, чем описано.
	withDelay := strategy.RequiredCapabilities(fragmentDelayed(3, 100, strategy.FragForward))
	if !withDelay.Has(core.CapDelay) {
		t.Fatal("стратегия с паузой не требует CapDelay")
	}
	without := strategy.RequiredCapabilities(fragmentDelayed(3, 0, strategy.FragForward))
	if without.Has(core.CapDelay) {
		t.Fatal("стратегия без паузы требует CapDelay")
	}
}
