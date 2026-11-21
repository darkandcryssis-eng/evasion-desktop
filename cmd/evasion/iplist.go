package main

import (
	"net/netip"

	"github.com/fitting-1c/evasion/internal/iplist"
	"github.com/fitting-1c/evasion/internal/proxy"
)

// ipListProvider добавляет к обычному выбору по имени сервера выбор по адресу
// назначения: ClientHello к IP из пользовательского списка получает десинк,
// даже если его SNI не входит ни в одну группу. Выбор базового провайдера
// всегда главнее — свои стратегии Discord/YouTube список не подменяет.
type ipListProvider struct {
	base          proxy.StrategyProvider
	set           *iplist.Set
	normal, small proxy.Selection
}

func newIPListProvider(base proxy.StrategyProvider, set *iplist.Set) (proxy.StrategyProvider, error) {
	p := &ipListProvider{base: base, set: set}
	for _, small := range []bool{false, true} {
		// Та же пара, что у игрового фильтра и у zapret для ipset: перекрытие
		// по TCP seq с cover-ClientHello, а для коротких ClientHello — разрез по SNI.
		strat, err := gameStrategy("balanced", small)
		if err != nil {
			return nil, err
		}
		static, err := proxy.NewStaticProvider(strat)
		if err != nil {
			return nil, err
		}
		if small {
			p.small = static.Select(proxy.ConnMeta{})
		} else {
			p.normal = static.Select(proxy.ConnMeta{})
		}
	}
	return p, nil
}

func (p *ipListProvider) Select(meta proxy.ConnMeta) proxy.Selection {
	selected := p.base.Select(meta)
	if selected.Strategy != nil || !meta.IsClientHello {
		return selected
	}
	ip, err := netip.ParseAddr(meta.Host)
	if err != nil || !p.set.Contains(ip) {
		return selected
	}
	if meta.PayloadLength <= 681 {
		return p.small
	}
	return p.normal
}
