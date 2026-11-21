package proxy

import (
	"testing"

	"github.com/fitting-1c/evasion/internal/core"
)

// matchHosts — тестовый матчер: совпадает по точному имени host или sni.
type matchHosts map[string]bool

func (m matchHosts) Matches(host, sni string) bool { return m[host] || m[sni] }

func TestGroupProviderAppliesInsideRadius(t *testing.T) {
	s := splitStrategy(5)
	prov, err := NewGroupProvider(s, matchHosts{"youtube.com": true})
	if err != nil {
		t.Fatalf("NewGroupProvider: %v", err)
	}

	in := prov.Select(ConnMeta{Host: "youtube.com"})
	if in.Strategy == nil {
		t.Fatal("стратегия должна применяться к хосту в радиусе")
	}

	out := prov.Select(ConnMeta{Host: "example.com"})
	if out.Strategy != nil {
		t.Fatal("стратегия не должна применяться вне радиуса")
	}
}

func TestGroupProviderNilMatcherRejected(t *testing.T) {
	if _, err := NewGroupProvider(splitStrategy(5), nil); err == nil {
		t.Fatal("ожидалась ошибка на nil-матчер")
	}
}

func TestGroupProviderNoStrategyPassesThrough(t *testing.T) {
	prov, err := NewGroupProvider(nil, matchHosts{"youtube.com": true})
	if err != nil {
		t.Fatalf("NewGroupProvider: %v", err)
	}
	if prov.Select(ConnMeta{Host: "youtube.com"}).Strategy != nil {
		t.Fatal("без стратегии выбор должен быть пустым")
	}
}

// matchDomains — минимальный матчер, совпадающий по точному имени домена или
// любому его поддомену. Нужен для тестов MultiGroupProvider, где важна
// семантика «подгруппа как множество доменов», а не произвольный предикат.
type matchDomains []string

func (m matchDomains) Matches(host, sni string) bool {
	for _, d := range m {
		if match(host, d) || match(sni, d) {
			return true
		}
	}
	return false
}

func match(host, domain string) bool {
	if host == "" || domain == "" {
		return false
	}
	if host == domain {
		return true
	}
	return len(host) > len(domain)+1 && host[len(host)-len(domain)-1:] == "."+domain
}

func TestMultiGroupProviderFirstRuleWins(t *testing.T) {
	// Две подгруппы: discord_voice с одной стратегией, discord с другой.
	// Хост discord.media обязан получить первую, discord.com — вторую.
	voiceStrat := splitStrategy(5)
	ctrlStrat := splitStrategy(11)
	voiceID := mustComputeID(t, voiceStrat)
	ctrlID := mustComputeID(t, ctrlStrat)
	prov, err := NewMultiGroupProvider(
		[]GroupRule{
			{Name: "discord_voice", Matcher: matchDomains{"discord.media"}, Strategy: voiceStrat},
			{Name: "discord", Matcher: matchDomains{"discord.com", "discord.gg", "discordapp.com"}, Strategy: ctrlStrat},
		},
		nil, // fallback без стратегии
		matchDomains{"discord.media", "discord.com", "discord.gg", "discordapp.com"},
	)
	if err != nil {
		t.Fatalf("NewMultiGroupProvider: %v", err)
	}

	cases := []struct {
		host  string
		want  core.StrategyID
		label string
	}{
		{"finland1.discord.media", voiceID, "voice"},
		{"discord.com", ctrlID, "ctrl"},
		{"cdn.discordapp.com", ctrlID, "ctrl"},
	}
	for _, c := range cases {
		got := prov.Select(ConnMeta{Host: c.host, SNI: c.host})
		if got.ID != c.want {
			t.Fatalf("%s (%s): получили %s, ожидали %s", c.host, c.label, got.ID, c.want)
		}
	}
}

func TestMultiGroupProviderFallbackAppliesInRadius(t *testing.T) {
	// Подгруппа discord_voice с одной стратегией; discord.com идёт в fallback.
	voice := splitStrategy(5)
	fb := splitStrategy(11)
	voiceID := mustComputeID(t, voice)
	fbID := mustComputeID(t, fb)
	prov, err := NewMultiGroupProvider(
		[]GroupRule{
			{Name: "discord_voice", Matcher: matchDomains{"discord.media"}, Strategy: voice},
		},
		fb,
		matchDomains{"discord.media", "discord.com"},
	)
	if err != nil {
		t.Fatalf("NewMultiGroupProvider: %v", err)
	}
	// discord.com не входит в подгруппу — ждём fallback.
	got := prov.Select(ConnMeta{Host: "discord.com"})
	if got.ID != fbID {
		t.Fatalf("fallback: получили %s, ожидали %s", got.ID, fbID)
	}
	// discord.media входит — ждём voice.
	got = prov.Select(ConnMeta{Host: "my.discord.media"})
	if got.ID != voiceID {
		t.Fatalf("voice: получили %s, ожидали %s", got.ID, voiceID)
	}
}

func TestMultiGroupProviderOutsideRadiusPassesThrough(t *testing.T) {
	voice := splitStrategy(5)
	fb := splitStrategy(11)
	prov, err := NewMultiGroupProvider(
		[]GroupRule{
			{Name: "discord_voice", Matcher: matchDomains{"discord.media"}, Strategy: voice},
		},
		fb,
		matchDomains{"discord.media", "discord.com"},
	)
	if err != nil {
		t.Fatalf("NewMultiGroupProvider: %v", err)
	}
	// example.com — вне общего радиуса: не должна применяться ни одна стратегия.
	got := prov.Select(ConnMeta{Host: "example.com"})
	if got.Strategy != nil {
		t.Fatalf("вне радиуса ожидался пустой выбор, получили %s", got.ID)
	}
}

func TestMultiGroupProviderNilMatcherRejected(t *testing.T) {
	if _, err := NewMultiGroupProvider(nil, splitStrategy(5), nil); err == nil {
		t.Fatal("ожидалась ошибка на nil-матчер радиуса")
	}
}

func TestMultiGroupProviderSkipsIncompleteRules(t *testing.T) {
	// Правило без матчера или без стратегии должно быть тихо отброшено:
	// это полезно вызывающему (например, когда группа не входит в --groups
	// и его матчер оказался пустым).
	voice := splitStrategy(5)
	prov, err := NewMultiGroupProvider(
		[]GroupRule{
			{Name: "no_matcher", Strategy: voice},
			{Name: "no_strategy", Matcher: matchDomains{"discord.com"}},
			{Name: "voice", Matcher: matchDomains{"discord.media"}, Strategy: voice},
		},
		nil,
		matchDomains{"discord.media"},
	)
	if err != nil {
		t.Fatalf("NewMultiGroupProvider: %v", err)
	}
	if len(prov.Rules()) != 1 {
		t.Fatalf("ожидалось 1 правило, получили %d", len(prov.Rules()))
	}
	if prov.Rules()[0].Name != "voice" {
		t.Fatalf("имя правила: %q", prov.Rules()[0].Name)
	}
}
