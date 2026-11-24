package main

import (
	"testing"

	"github.com/fitting-1c/evasion/internal/iplist"
	"github.com/fitting-1c/evasion/internal/proxy"
)

type fixedProvider struct{ sel proxy.Selection }

func (f fixedProvider) Select(proxy.ConnMeta) proxy.Selection { return f.sel }

func TestIPListProvider(t *testing.T) {
	set, err := iplist.Parse("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	p, err := newIPListProvider(fixedProvider{}, set)
	if err != nil {
		t.Fatal(err)
	}
	listed := proxy.ConnMeta{Host: "203.0.113.9", Port: 443, SNI: "unknown.example", IsClientHello: true, PayloadLength: 1800}
	big := p.Select(listed)
	if big.Strategy == nil {
		t.Fatal("ClientHello к адресу из списка остался без стратегии")
	}
	listed.PayloadLength = 300
	small := p.Select(listed)
	if small.Strategy == nil || small.ID == big.ID {
		t.Fatal("короткий ClientHello должен получить свою стратегию")
	}
	listed.SNI = ""
	if got := p.Select(listed); got.ID != big.ID {
		t.Fatal("короткий ClientHello без SNI должен получить перекрытие, а не разрез по SNI")
	}
	listed.SNI = "unknown.example"
	for name, meta := range map[string]proxy.ConnMeta{
		"чужой адрес":      {Host: "198.51.100.1", IsClientHello: true, PayloadLength: 517},
		"не ClientHello":   {Host: "203.0.113.9", PayloadLength: 517},
		"адрес неизвестен": {SNI: "unknown.example", IsClientHello: true},
	} {
		if p.Select(meta).Strategy != nil {
			t.Errorf("%s: стратегия применена", name)
		}
	}
	// Стратегия группы главнее списка.
	own := p.Select(listed)
	base, err := newIPListProvider(fixedProvider{own}, set)
	if err != nil {
		t.Fatal(err)
	}
	listed.PayloadLength = 1800
	if got := base.Select(listed); got.ID != own.ID {
		t.Fatal("список подменил стратегию базового провайдера")
	}
}
