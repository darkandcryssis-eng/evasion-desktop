package control

import (
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/scoring"
)

// TestFocusCandidatesConcentratesBudget — бюджет проб концентрируется:
// недообследованные кандидаты пробуются всегда, а среди ранжируемых остаются
// только probeFocusTopK лучших по нижней границе; слабейший уступает место, не
// тратя живые прогоны, пока есть лидеры (пункт 4: один контур проб не должен
// размазывать бюджет на весь портфель).
func TestFocusCandidatesConcentratesBudget(t *testing.T) {
	tab, err := scoring.NewTable(scoring.DefaultConfig())
	if err != nil {
		t.Fatalf("NewTable: %v", err)
	}

	tgt := "youtube.com"
	key := func(id core.StrategyID) scoring.Key {
		return scoring.Key{StrategyID: id, Target: tgt, VantageID: vantage}
	}

	// Ранжируемые (определённых наблюдений >= probeExploreFloor), разной силы.
	strongA := core.StrategyID("aaaaaaaa")
	strongB := core.StrategyID("bbbbbbbb")
	midC := core.StrategyID("cccccccc")
	weakD := core.StrategyID("dddddddd")
	observe(tab, key(strongA), core.OutcomeOK, 12, base)
	observe(tab, key(strongB), core.OutcomeOK, 9, base)
	observe(tab, key(strongB), core.OutcomeFail, 3, base)
	observe(tab, key(midC), core.OutcomeOK, 6, base)
	observe(tab, key(midC), core.OutcomeFail, 6, base)
	observe(tab, key(weakD), core.OutcomeOK, 1, base)
	observe(tab, key(weakD), core.OutcomeFail, 11, base)

	// Недообследованные (< probeExploreFloor) — пробуются всегда.
	freshE := core.StrategyID("eeeeeeee")
	freshF := core.StrategyID("ffffffff")
	observe(tab, key(freshE), core.OutcomeOK, 1, base) // 1 определённое < 3
	// freshF — без наблюдений вовсе.

	ids := []core.StrategyID{strongA, strongB, midC, weakD, freshE, freshF}
	got := focusCandidates(tab, tgt, vantage, base, ids)

	in := map[core.StrategyID]bool{}
	for _, id := range got {
		in[id] = true
	}

	for _, id := range []core.StrategyID{freshE, freshF} {
		if !in[id] {
			t.Errorf("недообследованный %s должен пробоваться всегда", id)
		}
	}
	for _, id := range []core.StrategyID{strongA, strongB, midC} {
		if !in[id] {
			t.Errorf("лидер %s должен быть в пробе", id)
		}
	}
	if in[weakD] {
		t.Errorf("слабейший %s не должен тратить бюджет, пока есть лидеры", weakD)
	}
	if len(got) != 5 {
		t.Fatalf("ожидалось 5 проб (2 недообследованных + 3 лидера), получено %d: %v", len(got), got)
	}
}
