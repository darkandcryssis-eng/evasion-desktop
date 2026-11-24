package proxy

import (
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

func scoreProvider(t *testing.T) (MultiGroupProvider, []core.StrategyID, []*strategy.Strategy) {
	t.Helper()
	var list []*strategy.Strategy
	for _, n := range []int{1, 2, 3, 4} {
		list = append(list, &strategy.Strategy{Rules: []strategy.Rule{{
			Direction: core.DirectionOutbound,
			Trigger:   strategy.Trigger{Match: strategy.MatchAlways},
			Action:    &strategy.Action{Kind: core.ActionFragment, Params: &strategy.FragmentParams{Proto: strategy.FragTCP, Offset: n}, Left: &strategy.Action{Kind: core.ActionSend}, Right: &strategy.Action{Kind: core.ActionSend}},
		}}})
	}
	p, err := NewMultiGroupProvider(
		[]GroupRule{{Name: "g", Matcher: exactMatcher("a.example"), Strategies: list[:3]}},
		nil, exactMatcher("none.example"))
	if err != nil {
		t.Fatal(err)
	}
	var ids []core.StrategyID
	for _, s := range list {
		id, err := strategy.ComputeID(s)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return p, ids, list
}

type exactMatcher string

func (m exactMatcher) Matches(host, sni string) bool { return host == string(m) || sni == string(m) }

func TestFailureMovesToBestScoredStrategy(t *testing.T) {
	p, ids, _ := scoreProvider(t)
	for range 3 {
		p.Record("g", ids[2], true)
	}
	p.ReportFailure("a.example", ids[0])
	if got := p.ActiveStrategies()["g"]; got != ids[2] {
		t.Fatalf("после срыва выбрана %s, ждали лучшую по счёту %s", got, ids[2])
	}
}

func TestFailureWithoutScoresKeepsRoundRobin(t *testing.T) {
	p, ids, _ := scoreProvider(t)
	p.ReportFailure("a.example", ids[0])
	if got := p.ActiveStrategies()["g"]; got != ids[1] {
		t.Fatalf("без счёта ждали следующую по порядку %s, получили %s", ids[1], got)
	}
}

func TestTrustedStrategySurvivesSingleFailure(t *testing.T) {
	p, ids, _ := scoreProvider(t)
	for range 6 {
		p.Record("g", ids[0], true)
	}
	p.ReportFailure("a.example", ids[0])
	if got := p.ActiveStrategies()["g"]; got != ids[0] {
		t.Fatalf("одиночный срыв сдвинул проверенную стратегию на %s", got)
	}
	p.ReportFailure("a.example", ids[0])
	if got := p.ActiveStrategies()["g"]; got == ids[0] {
		t.Fatal("второй срыв подряд должен сдвинуть стратегию")
	}
}

func TestAddRemoveStrategyAndOverride(t *testing.T) {
	p, ids, list := scoreProvider(t)
	if id, ok := p.AddStrategy("g", list[3]); !ok || id != ids[3] {
		t.Fatalf("AddStrategy = %s, %v", id, ok)
	}
	if _, ok := p.AddStrategy("g", list[3]); ok {
		t.Fatal("повторное добавление должно вернуть false")
	}
	if !p.SetActive("g", ids[3]) {
		t.Fatal("добавленная стратегия не назначается действующей")
	}
	if p.RemoveStrategy("g", ids[3]) {
		t.Fatal("действующую стратегию убирать нельзя")
	}
	if !p.RemoveStrategy("g", ids[0]) {
		t.Fatal("недействующая стратегия не убрана")
	}
	if got := p.ActiveStrategies()["g"]; got != ids[3] {
		t.Fatalf("после удаления действующая сменилась на %s", got)
	}
	if _, ok := p.SetHostOverride("a.example", list[1]); !ok {
		t.Fatal("назначение узлу не принято")
	}
	if got := p.Select(ConnMeta{SNI: "a.example"}).ID; got != ids[1] {
		t.Fatalf("узел получил %s, ждали назначенную %s", got, ids[1])
	}
	p.ClearHostOverride("a.example")
	if got := p.Select(ConnMeta{SNI: "a.example"}).ID; got != ids[3] {
		t.Fatalf("после снятия назначения узел получил %s", got)
	}
}
