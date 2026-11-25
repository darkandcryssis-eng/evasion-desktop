package telegramtune

import (
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/proxy"
)

func TestTelegramTargetMatching(t *testing.T) {
	hosts := []string{"telegram.org", "kws2.web.telegram.org", "zws4-1.web.telegram.org", "t.me", "cdn4.cdn-telegram.org"}
	for _, h := range hosts {
		if !IsTelegramHost(h) {
			t.Errorf("expected Telegram host %q", h)
		}
	}
	nonHosts := []string{"", "example.com", "nottelegram.org", "discord.com", "youtube.com"}
	for _, h := range nonHosts {
		if IsTelegramHost(h) {
			t.Errorf("unexpected Telegram host %q", h)
		}
	}
	ips := []string{"149.154.167.91", "149.154.167.220", "91.108.56.100", "91.105.192.100", "185.76.151.10", "2001:b28:f23d:f001::a"}
	for _, ip := range ips {
		if !IsTelegramIP(ip) {
			t.Errorf("expected Telegram IP %q", ip)
		}
	}
	nonIPs := []string{"", "1.1.1.1", "8.8.8.8", "127.0.0.1", "192.168.1.1"}
	for _, ip := range nonIPs {
		if IsTelegramIP(ip) {
			t.Errorf("unexpected Telegram IP %q", ip)
		}
	}
}

func TestPortfolioCompilesDistinctStrategies(t *testing.T) {
	items, err := Portfolio()
	if err != nil {
		t.Fatalf("Portfolio() error: %v", err)
	}
	if len(items) != len(Profiles) {
		t.Fatalf("got %d profiles, want %d", len(items), len(Profiles))
	}
	seen := map[core.StrategyID]string{}
	for _, item := range items {
		if item.Strategy == nil || item.Strategy.ID == "" {
			t.Fatalf("empty strategy for %s", item.Name)
		}
		if prev, dup := seen[item.Strategy.ID]; dup {
			t.Fatalf("duplicate strategy ID between %s and %s", prev, item.Name)
		}
		seen[item.Strategy.ID] = item.Name
	}
}

func TestProviderSelectAndAutoFit(t *testing.T) {
	p, err := NewProvider(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	p.now = func() time.Time { return now }

	// Non-Telegram traffic is left untouched (delegated to base, which is nil).
	if sel := p.Select(proxy.ConnMeta{SNI: "discord.com", Host: "162.159.135.232", IsClientHello: true, PayloadLength: 512}); sel.Strategy != nil {
		t.Fatalf("expected nil for non-Telegram host, got %v", sel.ID)
	}

	// Telegram SNI matches active profile 0 (overlap-vk).
	sel := p.Select(proxy.ConnMeta{SNI: "kws2.web.telegram.org", Host: "149.154.167.220", IsClientHello: true, PayloadLength: 512})
	firstName, firstID := p.ActiveProfile()
	if firstName != "overlap-vk" || sel.ID != firstID || sel.Target != GroupName {
		t.Fatalf("unexpected initial selection: name=%s sel=%+v", firstName, sel)
	}

	// Bare Telegram DC IP with short ClientHello falls back safely to split-offset.
	shortSel := p.Select(proxy.ConnMeta{Host: "149.154.167.91", IsClientHello: true, PayloadLength: 100})
	if shortSel.Strategy == nil || shortSel.ID != p.fallback.ID {
		t.Fatalf("expected split-offset fallback for short bare-IP ClientHello, got %+v", shortSel)
	}

	// Repeated failures on active profile auto-fit to the next profile.
	var transitions []string
	p.SetOnAdvance(func(fromName, toName string, _, _ core.StrategyID, _ string) {
		transitions = append(transitions, fromName+"->"+toName)
	})
	p.ReportFailure("kws2.web.telegram.org", firstID)
	if name, _ := p.ActiveProfile(); name != "overlap-vk" {
		t.Fatalf("should not advance on single failure, got %s", name)
	}
	p.ReportFailure("", firstID) // bare-IP failure still advances via owned ID
	secondName, secondID := p.ActiveProfile()
	if secondName != "overlap-yandex" || secondID == firstID {
		t.Fatalf("expected advance to overlap-yandex, got %s", secondName)
	}
	if len(transitions) != 1 || transitions[0] != "overlap-vk->overlap-yandex" {
		t.Fatalf("unexpected transitions: %v", transitions)
	}

	// Cooldown prevents burst from skipping immediately.
	p.ReportFailure("kws2.web.telegram.org", secondID)
	p.ReportFailure("kws2.web.telegram.org", secondID)
	if name, _ := p.ActiveProfile(); name != "overlap-yandex" {
		t.Fatalf("cooldown failed, advanced to %s", name)
	}

	// After cooldown, another 2 failures advance again.
	now = now.Add(defaultAdvanceCooldown + time.Second)
	p.ReportFailure("kws2.web.telegram.org", secondID)
	p.ReportFailure("kws2.web.telegram.org", secondID)
	if name, _ := p.ActiveProfile(); name != "fake-seq-disorder" {
		t.Fatalf("expected fake-seq-disorder, got %s", name)
	}

	// Restoring persisted profile by ID works.
	if !p.SetActiveByID(secondID) {
		t.Fatal("SetActiveByID failed")
	}
	if name, _ := p.ActiveProfile(); name != "overlap-yandex" {
		t.Fatalf("expected restored overlap-yandex, got %s", name)
	}
}

type recordingBaseProvider struct {
	failures []string
}

func (b *recordingBaseProvider) Select(proxy.ConnMeta) proxy.Selection { return proxy.Selection{} }
func (b *recordingBaseProvider) ReportFailure(sni string, _ core.StrategyID) {
	b.failures = append(b.failures, sni)
}

func TestNonTelegramSNIFailureWithSharedIDForwardsToBase(t *testing.T) {
	base := &recordingBaseProvider{}
	p, err := NewProvider(base)
	if err != nil {
		t.Fatal(err)
	}
	_, tgID := p.ActiveProfile()
	p.ReportFailure("discord.com", tgID)
	p.ReportFailure("discord.com", tgID)
	if len(base.failures) != 2 {
		t.Fatalf("expected 2 failures forwarded to base, got %v", base.failures)
	}
	if name, _ := p.ActiveProfile(); name != "overlap-vk" {
		t.Fatalf("Discord failure must not advance Telegram profile, got %s", name)
	}
}
