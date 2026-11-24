package main

import (
	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/gamefilter"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/strategy"
	"github.com/fitting-1c/evasion/internal/windivert"
	"log/slog"
	"net/netip"
	"sync/atomic"
)

// New connections are captured before their local port reaches the periodic
// port snapshot, so the first ClientHello of a game is not lost. Ownership is
// checked in user mode; other applications are forwarded unchanged.
const gameTLSGuard = "not impostor and not loopback and outbound and tcp.DstPort == 443 and (tcp.Syn or tcp.PayloadLength > 0)"

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
	for {
		pkt, err := s.handle.Recv()
		if err != nil || s.closing.Load() {
			return pkt, err
		}
		if pkt.Dir == core.DirectionOutbound {
			if d, e := packet.Dissect(pkt.Data); e == nil && d.Protocol == packet.ProtoTCP {
				payload, _ := d.Payload(pkt.Data)
				if tcp, ok := d.TCP(pkt.Data); ok {
					owned := false
					if tcp.Flags()&(packet.FlagSYN|packet.FlagACK) == packet.FlagSYN || len(payload) >= 3 && payload[0] == 22 && payload[1] == 3 {
						owned = s.owners.OwnsCurrent("tcp", tcp.SrcPort())
					} else {
						owned = s.owners.Owns("tcp", tcp.SrcPort())
					}
					if !owned {
						// Another application's packet caught by the guard.
						if s.handle.Send(pkt) != nil {
							s.processor.RecordSendError()
						}
						continue
					}
				}
			}
		}
		s.processor.Observe(pkt, s.handle)
		return pkt, nil
	}
}

func (s *gameTLSSource) ShutdownReceive() error {
	return s.handle.ShutdownReceive()
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
	if meta.PayloadLength < strategy.MinOverlapPayload {
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
