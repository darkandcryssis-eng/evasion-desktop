package telegramtune

import (
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
)

const (
	// GroupName is the rotation-store group key for Telegram bypass persistence.
	GroupName = "telegram"

	// defaultAdvanceFailures is the number of consecutive failures on the active
	// Telegram profile before auto-fitting advances to the next profile.
	defaultAdvanceFailures = 2

	// defaultAdvanceCooldown prevents a single burst of parallel Telegram
	// connections from skipping multiple profiles at once.
	defaultAdvanceCooldown = 3 * time.Second
)

// Provider wraps a base StrategyProvider with a dedicated, auto-fitting DPI
// bypass portfolio for Telegram domains and DC IP ranges.
type Provider struct {
	base      proxy.StrategyProvider
	portfolio []NamedStrategy
	fallback  proxy.Selection // safe offset-split for short or bare-IP ClientHello
	ownedIDs  map[core.StrategyID]int
	now       func() time.Time

	mu          sync.Mutex
	active      int
	failures    int
	lastAdvance time.Time
	onAdvance   func(fromName, toName string, fromID, toID core.StrategyID, sni string)
}

// NewProvider constructs a Telegram-specific auto-fitting StrategyProvider
// layered in front of base.
func NewProvider(base proxy.StrategyProvider) (*Provider, error) {
	items, err := Portfolio()
	if err != nil {
		return nil, err
	}
	owned := make(map[core.StrategyID]int, len(items))
	for i, item := range items {
		owned[item.Strategy.ID] = i
	}
	splitStrat, err := Profile("split-offset")
	if err != nil {
		return nil, err
	}
	return &Provider{
		base:      base,
		portfolio: items,
		fallback: proxy.Selection{
			Strategy: splitStrat.Strategy,
			ID:       splitStrat.Strategy.ID,
			Target:   GroupName,
		},
		ownedIDs: owned,
		now:      time.Now,
	}, nil
}

// SetOnAdvance registers a callback fired whenever auto-fitting switches the
// active Telegram bypass profile.
func (p *Provider) SetOnAdvance(fn func(fromName, toName string, fromID, toID core.StrategyID, sni string)) {
	p.mu.Lock()
	p.onAdvance = fn
	p.mu.Unlock()
}

// Select returns the active Telegram bypass strategy for any ClientHello aimed
// at Telegram domains or DC IP ranges, and delegates everything else to base.
func (p *Provider) Select(meta proxy.ConnMeta) proxy.Selection {
	if !meta.IsClientHello || !IsTelegramTarget(meta.SNI, meta.Host) {
		if p.base == nil {
			return proxy.Selection{}
		}
		return p.base.Select(meta)
	}
	p.mu.Lock()
	item := p.portfolio[p.active]
	p.mu.Unlock()

	if (item.NeedsSNI && meta.SNI == "") || (item.NeedsLongCH && meta.PayloadLength > 0 && meta.PayloadLength < strategy.MinOverlapPayload) {
		return p.fallback
	}
	return proxy.Selection{
		Strategy: item.Strategy,
		ID:       item.Strategy.ID,
		Target:   GroupName,
	}
}

// ReportFailure records a DPI stall/reset/retransmit for the given SNI and
// strategy ID. When the active Telegram strategy fails repeatedly, auto-fitting
// advances to the next profile in the portfolio.
func (p *Provider) ReportFailure(sni string, failed core.StrategyID) {
	_, isOwned := p.ownedIDs[failed]
	isTelegram := IsTelegramHost(sni)
	if !isOwned && !(failed == "" && isTelegram) {
		if reporter, ok := p.base.(intercept.FailureReporter); ok {
			reporter.ReportFailure(sni, failed)
		}
		return
	}

	var cb func(fromName, toName string, fromID, toID core.StrategyID, sni string)
	var fromItem, toItem NamedStrategy
	advanced := false

	p.mu.Lock()
	cur := p.portfolio[p.active]
	if failed != "" && failed != cur.Strategy.ID && failed != p.fallback.ID {
		p.mu.Unlock()
		return
	}
	now := p.now()
	if !p.lastAdvance.IsZero() && now.Sub(p.lastAdvance) < defaultAdvanceCooldown {
		p.mu.Unlock()
		return
	}
	p.failures++
	if p.failures >= defaultAdvanceFailures && len(p.portfolio) > 1 {
		fromItem = cur
		p.active = (p.active + 1) % len(p.portfolio)
		toItem = p.portfolio[p.active]
		p.failures = 0
		p.lastAdvance = now
		cb = p.onAdvance
		advanced = true
	}
	p.mu.Unlock()

	if advanced && cb != nil {
		cb(fromItem.Name, toItem.Name, fromItem.Strategy.ID, toItem.Strategy.ID, sni)
	}
}

// ActiveProfile returns the name and StrategyID of the currently fitted
// Telegram bypass profile.
func (p *Provider) ActiveProfile() (string, core.StrategyID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	item := p.portfolio[p.active]
	return item.Name, item.Strategy.ID
}

// SetActiveByID restores a previously persisted Telegram strategy for the
// current provider/network fingerprint.
func (p *Provider) SetActiveByID(id core.StrategyID) bool {
	idx, ok := p.ownedIDs[id]
	if !ok {
		return false
	}
	p.mu.Lock()
	p.active = idx
	p.failures = 0
	p.mu.Unlock()
	return true
}

// SetActiveByName activates a named Telegram profile.
func (p *Provider) SetActiveByName(name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, item := range p.portfolio {
		if item.Name == name {
			p.active = i
			p.failures = 0
			return true
		}
	}
	return false
}

// Reset restores the first default profile (e.g. after switching networks).
func (p *Provider) Reset() {
	p.mu.Lock()
	p.active = 0
	p.failures = 0
	p.lastAdvance = time.Time{}
	p.mu.Unlock()
}
