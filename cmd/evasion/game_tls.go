package main

import (
	"context"
	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/gamefilter"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/windivert"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

var albionTLSHosts = []string{"live.albiononline.com", "status.albiononline.com", "albiononline.com"}

func prepareGameTLSIPs(ctx context.Context, o gamefilter.Options, lookup func(context.Context, string, string) ([]netip.Addr, error)) []netip.Addr {
	if !o.Albion || !o.TCP() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	answers := make(chan []netip.Addr, len(albionTLSHosts))
	for _, host := range albionTLSHosts {
		go func(host string) { ips, _ := lookup(ctx, "ip", host); answers <- ips }(host)
	}
	unique := map[netip.Addr]bool{}
	for range albionTLSHosts {
		select {
		case ips := <-answers:
			for _, ip := range ips {
				ip = ip.Unmap()
				if gamefilter.Public(ip) && len(unique) < 32 {
					unique[ip] = true
				}
			}
		case <-ctx.Done():
			return sortedGameIPs(unique)
		}
	}
	return sortedGameIPs(unique)
}
func sortedGameIPs(m map[netip.Addr]bool) []netip.Addr {
	out := make([]netip.Addr, 0, len(m))
	for ip := range m {
		out = append(out, ip)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// Destination coverage prevents losing the first ClientHello before a new
// launcher socket appears in the periodic port snapshot. Ownership is checked
// again in user mode; unrelated applications are forwarded unchanged.
func gameTLSGuard(ips []netip.Addr) string {
	out, in := []string{}, []string{}
	for _, ip := range ips {
		if !gamefilter.Public(ip) {
			continue
		}
		field := "ip"
		if ip.Is6() {
			field = "ipv6"
		}
		out = append(out, field+".DstAddr == "+ip.String())
		in = append(in, field+".SrcAddr == "+ip.String())
	}
	if len(out) == 0 {
		return ""
	}
	return "not impostor and not loopback and tcp and ((outbound and tcp.DstPort == 443 and (" + strings.Join(out, " or ") + ")) or (inbound and tcp.SrcPort == 443 and (" + strings.Join(in, " or ") + ")))"
}
func gameCaptureFilter(ports, guard string) string {
	if ports == "" {
		return guard
	}
	if guard == "" {
		return ports
	}
	return "(" + ports + ") or (" + guard + ")"
}

type gameTLSSource struct {
	handle    *windivert.Handle
	owners    *gamefilter.Owners
	processor *gamefilter.Processor
	closing   *atomic.Bool
}

func (s *gameTLSSource) Recv() (capture.Packet, error) {
	pkt, err := s.handle.Recv()
	if err != nil || s.closing.Load() {
		return pkt, err
	}
	if pkt.Dir == core.DirectionOutbound {
		if d, e := packet.Dissect(pkt.Data); e == nil && d.Protocol == packet.ProtoTCP {
			payload, _ := d.Payload(pkt.Data)
			if tcp, ok := d.TCP(pkt.Data); ok {
				if tcp.Flags()&(packet.FlagSYN|packet.FlagACK) == packet.FlagSYN || len(payload) >= 3 && payload[0] == 22 && payload[1] == 3 {
					s.owners.OwnsCurrent("tcp", tcp.SrcPort())
				}
			}
		}
	}
	s.processor.Observe(pkt, s.handle)
	return pkt, nil
}

type gameTLSProvider struct {
	processor     *gamefilter.Processor
	normal, small [3]proxy.Selection
}

func newGameTLSProvider(p *gamefilter.Processor) (*gameTLSProvider, error) {
	provider := &gameTLSProvider{processor: p}
	for i, mode := range []string{"gentle", "balanced", "strong"} {
		for _, small := range []bool{false, true} {
			strat, err := gameStrategy(mode, small)
			if err != nil {
				return nil, err
			}
			static, err := proxy.NewStaticProvider(strat)
			if err != nil {
				return nil, err
			}
			selection := static.Select(proxy.ConnMeta{})
			if small {
				provider.small[i] = selection
			} else {
				provider.normal[i] = selection
			}
		}
	}
	return provider, nil
}
func (p *gameTLSProvider) Select(meta proxy.ConnMeta) proxy.Selection {
	if !p.processor.Options.TCP() || !meta.IsClientHello || meta.LocalPort == 0 {
		return proxy.Selection{}
	}
	ip, err := netip.ParseAddr(meta.Host)
	if err != nil || !gamefilter.Public(ip) || !p.processor.Owner.Owns("tcp", meta.LocalPort) {
		return proxy.Selection{}
	}
	if !p.processor.AllowTLS(meta.LocalPort, meta.Host, meta.Port) {
		return proxy.Selection{}
	}
	i := max(0, min(2, p.processor.TLSLevel(meta.LocalPort, meta.Host, meta.Port)-1))
	if meta.PayloadLength <= 681 {
		return p.small[i]
	}
	return p.normal[i]
}

type gameTLSObserver struct{ processor *gamefilter.Processor }

func (o gameTLSObserver) OnClientHelloSeen(uint64, string, bool) {}
func (o gameTLSObserver) OnStrategyApplied(uint64, string, core.StrategyID) {
	o.processor.RecordTLS(true)
}
func (o gameTLSObserver) OnStrategyFailed(uint64, string, core.StrategyID, string) {
	o.processor.RecordTLS(false)
}
func (o gameTLSObserver) OnPassiveRetransmit(uint64, string, string, core.StrategyID) {}
func newGameTLSInterceptor(h *windivert.Handle, p *gamefilter.Processor, owners *gamefilter.Owners, flows *flow.Table, logger *slog.Logger, closing *atomic.Bool) (*intercept.Engine, error) {
	provider, err := newGameTLSProvider(p)
	if err != nil {
		return nil, err
	}
	return intercept.New(intercept.Options{Source: &gameTLSSource{h, owners, p, closing}, Sink: h, Flows: flows, Provider: provider, Exec: packetexec.New(), Parse: intercept.TLSHelloParser, IncludePacketMetadata: true, Logger: logger, Observer: gameTLSObserver{p}})
}
func resolveGameTLSIPs(ctx context.Context, o gamefilter.Options) []netip.Addr {
	return prepareGameTLSIPs(ctx, o, net.DefaultResolver.LookupNetIP)
}
