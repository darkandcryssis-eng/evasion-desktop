package main

import (
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/gamefilter"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
	"testing"
)

func TestGameCaptureFilterCombinesPortsAndGuard(t *testing.T) {
	if gameCaptureFilter("", gameTLSGuard) != gameTLSGuard || gameCaptureFilter("ports", "") != "ports" || gameCaptureFilter("ports", gameTLSGuard) != "(ports) or ("+gameTLSGuard+")" {
		t.Fatal("capture filter combined incorrectly")
	}
}
func TestGameTLSProviderPreservesProcessAndProtocolScope(t *testing.T) {
	meta := proxy.ConnMeta{Host: "1.1.1.1", Port: 443, LocalPort: 45000, SNI: "live.albiononline.com", IsClientHello: true, PayloadLength: 2000}
	for _, tc := range []struct {
		name, mode, protocol, host string
		owned, hello               bool
		port                       uint16
		want                       bool
	}{
		{"auto", "auto", "both", "1.1.1.1", true, true, 45000, true}, {"foreign", "auto", "both", "1.1.1.1", false, true, 45000, false}, {"private", "auto", "both", "10.0.0.1", true, true, 45000, false}, {"not tls", "auto", "both", "1.1.1.1", true, false, 45000, false}, {"unknown socket", "auto", "both", "1.1.1.1", true, true, 0, false}, {"udp only", "auto", "udp", "1.1.1.1", true, true, 45000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := gamefilter.Default()
			o.Mode = tc.mode
			o.Protocol = tc.protocol
			p := gamefilter.New(o, gameTestOwner(tc.owned))
			provider, err := newGameTLSProvider(p)
			if err != nil {
				t.Fatal(err)
			}
			m := meta
			m.Host = tc.host
			m.IsClientHello = tc.hello
			m.LocalPort = tc.port
			sel := provider.Select(m)
			if (sel.Strategy != nil) != tc.want {
				t.Fatal(sel)
			}
			if tc.want && strategy.RequiredCapabilities(sel.Strategy).Has(core.CapTCPOverlap) {
				t.Fatal("automatic first handshake is not conservative")
			}
		})
	}
}
func TestGameTLSShortHelloNeverUsesOversizedOverlap(t *testing.T) {
	for _, mode := range []string{"auto", "gentle", "balanced", "strong"} {
		o := gamefilter.Default()
		o.Mode = mode
		p := gamefilter.New(o, gameTestOwner(true))
		provider, _ := newGameTLSProvider(p)
		sel := provider.Select(proxy.ConnMeta{Host: "1.1.1.1", Port: 443, LocalPort: 45000, SNI: "live.albiononline.com", IsClientHello: true, PayloadLength: 300})
		if sel.Strategy == nil || strategy.RequiredCapabilities(sel.Strategy).Has(core.CapTCPOverlap) {
			t.Fatal(mode, sel)
		}
	}
}
