package proxy

import (
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/strategy"
)

// Простой матчер для теста: суффикс.
type suffixMatcher struct{ sfx string }

func (m suffixMatcher) Matches(host, sni string) bool {
	s := host
	if sni != "" {
		s = sni
	}
	if len(s) < len(m.sfx) {
		return false
	}
	return s[len(s)-len(m.sfx):] == m.sfx
}

// простая стратегия для тестов — пустая без правил, но корректная.
func dummyStrategy(id string) *strategy.Strategy {
	// Любая стратегия с минимальным валидным составом; ID вычислится из
	// содержимого. Для теста ротации нам важно только, что ID разные.
	return &strategy.Strategy{
		Rules: []strategy.Rule{{
			Direction: core.DirectionOutbound,
			Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
			Action:    &strategy.Action{Kind: core.ActionSend},
			// id как label не передаётся; разность достигается через
			// добавление tamper'а, но для теста используем Rotation у
			// самого Rule — проще.
		}},
	}
}

// Создаёт N разных стратегий (с разным tamper полем для уникальности ID).
func distinctStrategies(n int) []*strategy.Strategy {
	out := make([]*strategy.Strategy, n)
	for i := 0; i < n; i++ {
		out[i] = &strategy.Strategy{
			Rules: []strategy.Rule{{
				Direction: core.DirectionOutbound,
				Trigger:   strategy.Trigger{Match: strategy.MatchClientHello},
				Action: &strategy.Action{
					Kind: core.ActionTamper,
					Params: &strategy.TamperParams{
						Field: strategy.FieldIPv4TTL,
						Mode:  strategy.TamperReplace,
						Value: uint64(10 + i), // разные значения = разные ID
					},
					Left: &strategy.Action{Kind: core.ActionSend},
				},
			}},
		}
	}
	return out
}

// Ротация: разные соединения получают разные стратегии (хотя бы 2 разных ID
// за 20 проб с разными портами).
func TestMultiGroupProviderRotation(t *testing.T) {
	strats := distinctStrategies(4)
	matcher := suffixMatcher{sfx: ".discord.media"}
	p, err := NewMultiGroupProvider(
		[]GroupRule{{
			Name:       "voice",
			Matcher:    matcher,
			Strategies: strats,
		}},
		nil,
		matcher, // fallback matcher, не используется — всё матчится
	)
	if err != nil {
		t.Fatalf("NewMultiGroupProvider: %v", err)
	}

	seen := make(map[core.StrategyID]bool)
	for port := uint16(1000); port < 1020; port++ {
		sel := p.Select(ConnMeta{SNI: "c-arn07.discord.media", LocalPort: port, IsClientHello: true})
		if sel.Strategy == nil {
			t.Fatalf("Select вернул nil на порту %d", port)
		}
		seen[sel.ID] = true
	}
	// Должны увидеть минимум 2 разные стратегии за 20 попыток с разными
	// портами — вероятность пропустить все 4 за 20 попыток ничтожна при
	// честном hash-разбросе.
	if len(seen) < 2 {
		t.Fatalf("ротация не работает: за 20 проб видно всего %d стратегий", len(seen))
	}
}

// Стабильность: один и тот же (SNI, LocalPort) всегда даёт одну стратегию.
// Это критично для TCP-ретрансмитов — повторный ClientHello должен попасть
// в ту же стратегию.
func TestMultiGroupProviderRotationStable(t *testing.T) {
	strats := distinctStrategies(4)
	matcher := suffixMatcher{sfx: ".discord.media"}
	p, _ := NewMultiGroupProvider(
		[]GroupRule{{Name: "voice", Matcher: matcher, Strategies: strats}},
		nil, matcher,
	)
	sel1 := p.Select(ConnMeta{SNI: "x.discord.media", LocalPort: 1234})
	sel2 := p.Select(ConnMeta{SNI: "x.discord.media", LocalPort: 1234})
	if sel1.ID != sel2.ID {
		t.Fatalf("ротация нестабильна: один SNI+LocalPort вернул разное: %s vs %s",
			sel1.ID, sel2.ID)
	}
}

// Одна стратегия в Strategies работает так же как Strategy (back-compat):
// все соединения получают один и тот же ID, независимо от порта.
func TestMultiGroupProviderSingleStrategyInRotation(t *testing.T) {
	strat := distinctStrategies(1)
	matcher := suffixMatcher{sfx: ".discord.media"}
	p, err := NewMultiGroupProvider(
		[]GroupRule{{Name: "voice", Matcher: matcher, Strategies: strat}},
		nil, matcher,
	)
	if err != nil {
		t.Fatalf("NewMultiGroupProvider: %v", err)
	}
	first := p.Select(ConnMeta{SNI: "x.discord.media", LocalPort: 1000}).ID
	for port := uint16(1001); port < 1010; port++ {
		sel := p.Select(ConnMeta{SNI: "x.discord.media", LocalPort: port})
		if sel.ID != first {
			t.Fatalf("с одной стратегией в Strategies все соединения должны давать один ID, получили %s vs %s",
				sel.ID, first)
		}
	}
}

// Strategy и Strategies: Strategies приоритетнее, если задано.
func TestMultiGroupProviderStrategiesPreferredOverStrategy(t *testing.T) {
	single := distinctStrategies(1)[0]
	rotation := distinctStrategies(3)
	matcher := suffixMatcher{sfx: ".discord.media"}
	p, _ := NewMultiGroupProvider(
		[]GroupRule{{
			Name:       "voice",
			Matcher:    matcher,
			Strategy:   single,
			Strategies: rotation,
		}},
		nil, matcher,
	)
	// 20 проб: ни одна не должна выдать single — только из rotation.
	for port := uint16(1000); port < 1020; port++ {
		sel := p.Select(ConnMeta{SNI: "x.discord.media", LocalPort: port})
		if sel.ID == single.ID {
			t.Fatal("при заданном Strategies, Strategy не должна использоваться")
		}
	}
}

func TestMultiGroupProviderReportFailureShiftsOnlySNI(t *testing.T) {
	matcher := suffixMatcher{sfx: ".discord.media"}
	p, err := NewMultiGroupProvider(
		[]GroupRule{{Name: "voice", Matcher: matcher, Strategies: distinctStrategies(4)}},
		nil,
		matcher,
	)
	if err != nil {
		t.Fatalf("NewMultiGroupProvider: %v", err)
	}
	meta := ConnMeta{SNI: "one.discord.media", LocalPort: 12345}
	before := p.Select(meta).ID
	otherMeta := ConnMeta{SNI: "two.discord.media", LocalPort: 12345}
	otherBefore := p.Select(otherMeta).ID
	_ = before
	p.ReportFailure(meta.SNI)
	first := p.Select(meta).ID
	for port := uint16(1000); port < 1020; port++ {
		if got := p.Select(ConnMeta{SNI: meta.SNI, LocalPort: port}).ID; got != first {
			t.Fatalf("after failure port %d got %s, want %s for every port", port, got, first)
		}
	}
	p.ReportFailure(meta.SNI)
	if second := p.Select(meta).ID; second == first {
		t.Fatalf("second failure did not shift strategy for %s: %s", meta.SNI, second)
	}
	if after := p.Select(otherMeta).ID; after != otherBefore {
		t.Fatalf("failure for %s shifted %s from %s to %s", meta.SNI, otherMeta.SNI, otherBefore, after)
	}
	p.ReportFailure("unknown.example")
}

func TestZeroValueMultiGroupProviderFailureIsSafe(t *testing.T) {
	var p MultiGroupProvider
	p.ReportFailure("example.com")
	if got := p.Select(ConnMeta{}); got.Strategy != nil {
		t.Fatalf("zero-value provider selected a strategy: %+v", got)
	}
}
