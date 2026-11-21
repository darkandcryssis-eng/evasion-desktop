package main

import (
	"context"
	"errors"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/gamefilter"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
	"net/netip"
	"testing"
	"time"
)

func TestGameTLSDNSGuardOnlyUsesPublicAddresses(t *testing.T) {
	o := gamefilter.Default()
	o.Mode = "auto"
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fd00::1"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("::ffff:1.1.1.1")}, nil
	}
	ips := prepareGameTLSIPs(context.Background(), o, lookup)
	if len(ips) != 1 || ips[0].String() != "1.1.1.1" {
		t.Fatal(ips)
	}
	o.Protocol = "udp"
	if got := prepareGameTLSIPs(context.Background(), o, lookup); len(got) != 0 {
		t.Fatal("UDP-only enabled TLS", got)
	}
	o.Protocol = "both"
	o.Albion = false
	if got := prepareGameTLSIPs(context.Background(), o, lookup); len(got) != 0 {
		t.Fatal("unselected target enabled guard", got)
	}
}
func TestGameTLSDNSFailuresKeepPortFallback(t *testing.T) {
	o := gamefilter.Default()
	o.Mode = "auto"
	ips := prepareGameTLSIPs(context.Background(), o, func(context.Context, string, string) ([]netip.Addr, error) { return nil, errors.New("unavailable") })
	if len(ips) != 0 || gameCaptureFilter("port-filter", gameTLSGuard(ips)) != "port-filter" {
		t.Fatal(ips)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	ips = prepareGameTLSIPs(ctx, o, func(ctx context.Context, _, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() })
	if len(ips) != 0 {
		t.Fatal(ips)
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
