package proxy

import (
	"fmt"
	"testing"
	"time"

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

// Sticky: каждое соединение группы получает одну активную стратегию.
func TestMultiGroupProviderStickySelection(t *testing.T) {
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

	first := p.Select(ConnMeta{SNI: "c-arn07.discord.media", LocalPort: 1000, IsClientHello: true})
	if first.Strategy == nil {
		t.Fatal("Select вернул nil")
	}
	for port := uint16(1000); port < 1020; port++ {
		sel := p.Select(ConnMeta{SNI: "c-arn07.discord.media", LocalPort: port, IsClientHello: true})
		if sel.ID != first.ID {
			t.Fatalf("порт %d получил %s, ожидалась активная стратегия %s", port, sel.ID, first.ID)
		}
	}
}

// Active selection is stable across metadata for the same group.
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

func TestFallbackFailureBypassAndExpiry(t *testing.T) {
	fallback := distinctStrategies(1)[0]
	matcher := suffixMatcher{sfx: ".example.com"}
	p, err := NewMultiGroupProvider(nil, fallback, matcher)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p.rotation.now = func() time.Time { return now }
	p.SetFallbackFailureBypass(true)
	meta := ConnMeta{SNI: "api.example.com", IsClientHello: true}

	sel := p.Select(meta)
	if sel.Strategy == nil {
		t.Fatal("fallback should initially apply")
	}
	p.ReportFailure(meta.SNI, sel.ID)
	if got := p.Select(meta); got.ID != sel.ID {
		t.Fatal("one failure must not bypass the fallback")
	}
	p.ReportFailure(meta.SNI, sel.ID)
	if got := p.Select(meta); got.Strategy != nil {
		t.Fatal("two fallback failures should bypass this SNI")
	}

	now = now.Add(fallbackBypassDuration + time.Nanosecond)
	if got := p.Select(meta); got.ID != sel.ID {
		t.Fatal("expired bypass should allow fallback again")
	}
}

func TestFallbackFailureWindowAndCapacity(t *testing.T) {
	fallback := distinctStrategies(1)[0]
	matcher := suffixMatcher{sfx: ".example.com"}
	p, err := NewMultiGroupProvider(nil, fallback, matcher)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p.rotation.now = func() time.Time { return now }
	p.SetFallbackFailureBypass(true)
	first := p.Select(ConnMeta{SNI: "first.example.com", IsClientHello: true})
	p.ReportFailure("first.example.com", first.ID)
	now = now.Add(fallbackFailureWindow + time.Nanosecond)
	p.ReportFailure("first.example.com", first.ID)
	if got := p.Select(ConnMeta{SNI: "first.example.com", IsClientHello: true}); got.ID != first.ID {
		t.Fatal("failures outside the window must not trigger bypass")
	}

	for i := 0; i < fallbackFailureStateCapacity+1; i++ {
		sni := fmt.Sprintf("host-%d.example.com", i)
		p.ReportFailure(sni, first.ID)
	}
	if got := len(p.rotation.fallbackFailures); got > fallbackFailureStateCapacity {
		t.Fatalf("fallback failure map grew to %d entries", got)
	}
}

func TestFallbackBypassDoesNotAffectGroupRules(t *testing.T) {
	groupStrategy := distinctStrategies(1)[0]
	fallbackStrategy := distinctStrategies(2)[1]
	groupMatcher := suffixMatcher{sfx: ".example.com"}
	fallbackMatcher := suffixMatcher{sfx: ".com"}
	p, err := NewMultiGroupProvider(
		[]GroupRule{{Name: "group", Matcher: groupMatcher, Strategy: groupStrategy}},
		fallbackStrategy,
		fallbackMatcher,
	)
	if err != nil {
		t.Fatal(err)
	}
	p.SetFallbackFailureBypass(true)
	meta := ConnMeta{SNI: "api.example.com", IsClientHello: true}
	group := p.Select(meta)
	if group.ID == "" || group.ID == p.fallback.sel.ID {
		t.Fatal("group rule should take precedence over fallback")
	}
	p.ReportFailure(meta.SNI, group.ID)
	p.ReportFailure(meta.SNI, group.ID)
	if got := p.Select(meta); got.ID != group.ID {
		t.Fatal("fallback bypass must not alter a matching group rule")
	}
	if len(p.rotation.fallbackFailures) != 0 {
		t.Fatal("group failures must not be recorded as fallback failures")
	}
}

func TestMultiGroupProviderReportFailureAdvancesOnlyMatchingGroupAndID(t *testing.T) {
	voiceMatcher := suffixMatcher{sfx: ".discord.media"}
	updatesMatcher := suffixMatcher{sfx: ".updates.example"}
	p, err := NewMultiGroupProvider(
		[]GroupRule{
			{Name: "voice", Matcher: voiceMatcher, Strategies: distinctStrategies(4)},
			{Name: "updates", Matcher: updatesMatcher, Strategies: distinctStrategies(2)},
		},
		nil,
		voiceMatcher,
	)
	if err != nil {
		t.Fatalf("NewMultiGroupProvider: %v", err)
	}
	meta := ConnMeta{SNI: "one.discord.media", LocalPort: 12345}
	before := p.Select(meta).ID
	otherMeta := ConnMeta{SNI: "api.updates.example", LocalPort: 12345}
	otherBefore := p.Select(otherMeta).ID
	p.ReportFailure(meta.SNI, before)
	first := p.Select(meta).ID
	if first == before {
		t.Fatalf("failure did not advance strategy from %s", before)
	}
	for port := uint16(1000); port < 1020; port++ {
		if got := p.Select(ConnMeta{SNI: meta.SNI, LocalPort: port}).ID; got != first {
			t.Fatalf("after failure port %d got %s, want sticky %s", port, got, first)
		}
	}
	// A late report from a connection using the old strategy is ignored.
	p.ReportFailure(meta.SNI, before)
	if got := p.Select(meta).ID; got != first {
		t.Fatalf("stale failure changed active strategy to %s, want %s", got, first)
	}
	p.ReportFailure(meta.SNI, first)
	second := p.Select(meta).ID
	if second == first {
		t.Fatalf("current failure did not advance strategy for %s", meta.SNI)
	}
	if after := p.Select(otherMeta).ID; after != otherBefore {
		t.Fatalf("failure in voice shifted updates from %s to %s", otherBefore, after)
	}
	p.ReportFailure("unknown.example", first)
}

func TestMultiGroupProviderActiveStrategiesAndSetActive(t *testing.T) {
	matcher := suffixMatcher{sfx: ".discord.media"}
	p, err := NewMultiGroupProvider(
		[]GroupRule{{Name: "voice", Matcher: matcher, Strategies: distinctStrategies(3)}},
		nil, matcher,
	)
	if err != nil {
		t.Fatal(err)
	}
	ids := p.Rules()[0].StrategyIDs
	if got := p.ActiveStrategies()["voice"]; got != ids[0] {
		t.Fatalf("initial active = %s, want %s", got, ids[0])
	}
	if !p.SetActive("voice", ids[2]) {
		t.Fatal("SetActive rejected known strategy")
	}
	if got := p.Select(ConnMeta{SNI: "x.discord.media"}).ID; got != ids[2] {
		t.Fatalf("selected %s after SetActive, want %s", got, ids[2])
	}
	if got := p.ActiveStrategies()["voice"]; got != ids[2] {
		t.Fatalf("ActiveStrategies = %s, want %s", got, ids[2])
	}
	if p.SetActive("voice", "unknown") || p.SetActive("missing", ids[0]) {
		t.Fatal("SetActive accepted an unknown group or ID")
	}
}

func TestMultiGroupProviderExhaustionHookAndContinuedAdvancement(t *testing.T) {
	matcher := suffixMatcher{sfx: ".discord.media"}
	p, err := NewMultiGroupProvider(
		[]GroupRule{{Name: "voice", Matcher: matcher, Strategies: distinctStrategies(3)}},
		nil, matcher,
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	p.rotation.now = func() time.Time { return now }
	var exhausted []string
	p.SetOnExhausted(func(group string) { exhausted = append(exhausted, group) })
	meta := ConnMeta{SNI: "x.discord.media"}
	for i := 0; i < 3; i++ {
		p.ReportFailure(meta.SNI, p.Select(meta).ID)
	}
	if len(exhausted) != 1 || exhausted[0] != "voice" {
		t.Fatalf("exhaustion hook calls = %v", exhausted)
	}
	want := p.Rules()[0].StrategyIDs[0]
	if got := p.Select(meta).ID; got != want {
		t.Fatalf("after full cycle selected %s, want %s", got, want)
	}
	p.ReportFailure(meta.SNI, p.Select(meta).ID)
	if got := p.Select(meta).ID; got == want {
		t.Fatal("provider froze advancement while group was exhausted")
	}
	if len(exhausted) != 1 {
		t.Fatalf("exhaustion hook repeated while active: %v", exhausted)
	}
}

func TestZeroValueMultiGroupProviderFailureIsSafe(t *testing.T) {
	var p MultiGroupProvider
	p.ReportFailure("example.com", "strategy")
	if got := p.Select(ConnMeta{}); got.Strategy != nil {
		t.Fatalf("zero-value provider selected a strategy: %+v", got)
	}
}
