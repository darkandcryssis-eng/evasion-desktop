package gamefilter

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/discordvoice"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/tlsfake"
)

type Ownership interface {
	Owns(protocol string, localPort uint16) bool
}
type Counters struct {
	Tunnel         bool   `json:"tunnel"`
	TunnelReceived uint64 `json:"tunnelReceived"`
	TunnelSent     uint64 `json:"tunnelSent"`

	TLSApplied  uint64 `json:"tlsApplied"`
	TLSFailed   uint64 `json:"tlsFailed"`
	TLSPrepared uint64 `json:"preparedTLSIPs"`
	Connections uint64 `json:"connections"`
	UDP         uint64 `json:"udp"`
	TCP         uint64 `json:"tcp"`
	Decoys      uint64 `json:"decoys"`
	Errors      uint64 `json:"errors"`
	Limited     uint64 `json:"limited"`
}
type flowKey struct {
	protocol      packet.Protocol
	local, remote netip.AddrPort
}
type entry struct {
	tls     bool
	allowed bool
	count   int
	stage   int
	last    time.Time
	seq     uint32
	hasSeq  bool
}
type Processor struct {
	mu           sync.Mutex
	ObserveOnly  bool
	Standalone   bool
	TLSHandled   bool
	Adaptive     bool
	observations map[flowKey]observation
	transport    map[flowKey]transportFlow
	retries      map[flowKey]retryGroup
	Options      Options
	Owner        Ownership
	Now          func() time.Time
	flows        map[flowKey]entry
	stats        Counters
	tokens       float64
	refilled     time.Time
}

func New(o Options, owner Ownership) *Processor {
	return &Processor{Options: o, Owner: owner, Now: time.Now, flows: map[flowKey]entry{}, tokens: 64, refilled: time.Now()}
}

var privateNetworks = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("240.0.0.0/4")}

func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range privateNetworks {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
func addresses(d packet.Dissection, b []byte) (netip.Addr, netip.Addr) {
	var src, dst []byte
	if h, ok := d.IPv4(b); ok {
		src, dst = h.Src(), h.Dst()
	} else if h, ok := d.IPv6(b); ok {
		src, dst = h.Src(), h.Dst()
	}
	a, _ := netip.AddrFromSlice(src)
	z, _ := netip.AddrFromSlice(dst)
	return a.Unmap(), z.Unmap()
}
func (p *Processor) reserve(k flowKey, seq uint32, tcp bool, repeats int, stages ...int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.Now()
	v, found := p.flows[k]
	if found && now.Sub(v.last) > 5*time.Minute {
		delete(p.flows, k)
		found = false
		v = entry{}
	}
	if !found {
		if len(p.flows) >= 8192 {
			for key, value := range p.flows {
				if now.Sub(value.last) > 5*time.Minute {
					delete(p.flows, key)
				}
			}
		}
		if len(p.flows) >= 8192 {
			p.stats.Limited++
			return false
		}
		p.stats.Connections++
	}
	limit, _ := p.Options.Limits()
	stage := 0
	if len(stages) > 0 {
		stage = stages[0]
		if stage > 0 {
			limit = stage
		}
	}
	v.last = now
	if v.count >= limit || tcp && v.hasSeq && v.seq == seq && (stage == 0 || v.stage >= stage) {
		p.flows[k] = v
		return false
	}
	p.tokens = min(64, p.tokens+max(0, now.Sub(p.refilled).Seconds())*32)
	p.refilled = now
	if p.tokens < float64(repeats) {
		p.stats.Limited++
		p.flows[k] = v
		return false
	}
	p.tokens -= float64(repeats)
	v.count++
	v.stage = stage
	v.seq = seq
	v.hasSeq = tcp
	p.flows[k] = v
	return true
}

// Original bytes and reinjection metadata never change. Only fake packets are emitted here.
func (p *Processor) Before(pkt capture.Packet, sink capture.PacketSink) { p.before(pkt, sink, 0) }
func (p *Processor) before(pkt capture.Packet, sink capture.PacketSink, stage int) {
	if p.Owner == nil || !p.Options.Enabled() || pkt.Dir != core.DirectionOutbound {
		return
	}
	d, err := packet.Dissect(pkt.Data)
	if err != nil || d.Truncated || d.Fragment {
		return
	}
	if d.Protocol == packet.ProtoTCP {
		if h, ok := d.TCP(pkt.Data); ok && h.Flags()&packet.FlagSYN != 0 {
			p.resetTCP(d, pkt.Data, h.SrcPort(), h.DstPort())
			return
		}
	}
	if d.PayloadLen == 0 || d.PayloadLen > 1400 && !(p.Standalone && d.Protocol == packet.ProtoTCP) {
		return
	}
	if h, ok := d.IPv4(pkt.Data); ok && (h.Flags()&1 != 0 || h.FragOffset() != 0) {
		return
	}
	if d.Version == packet.Version6 && d.L4Off != 40 {
		return
	}
	src, dst := addresses(d, pkt.Data)
	if !Public(dst) {
		return
	}
	pl, _ := d.Payload(pkt.Data)
	var sport, dport uint16
	var seq uint32
	tcp := d.Protocol == packet.ProtoTCP
	if tcp {
		if !p.Options.TCP() {
			return
		}
		h, ok := d.TCP(pkt.Data)
		if !ok || h.Flags()&(packet.FlagSYN|packet.FlagFIN|packet.FlagRST) != 0 {
			return
		}
		// TLS is handled by the normal reassembly/strategy pipeline, including large ClientHello.
		if !p.Standalone && (pl[0] == 22 || pl[0] == 23) {
			return
		}
		sport, dport, seq = h.SrcPort(), h.DstPort(), h.Seq()
	} else {
		if d.Protocol != packet.ProtoUDP || !p.Options.UDP() {
			return
		}
		h, _ := d.UDP(pkt.Data)
		sport, dport = h.SrcPort(), h.DstPort()
		if dport < 1024 || dport == 443 || discordvoice.IsIPDiscoveryRequest(pl) {
			return
		}
	}
	if !p.Owner.Owns(d.Protocol.String(), sport) {
		return
	}
	_, repeats := p.Options.Limits()
	if p.Options.Mode == "auto" {
		switch stage {
		case 1:
			repeats = 1
		case 2:
			repeats = 3
		case 3:
			repeats = 6
		default:
			return
		}
	}
	if !p.reserve(flowKey{d.Protocol, netip.AddrPortFrom(src, sport), netip.AddrPortFrom(dst, dport)}, seq, tcp, repeats, stage) {
		return
	}
	var fake []byte
	metadata := pkt.Reinject
	if tcp {
		fake = append([]byte(nil), pkt.Data...)
		if p.Standalone && pl[0] == 22 {
			fake = append(fake[:d.PayloadOff:d.PayloadOff], tlsfake.GoogleClientHello()...)
		} else if p.Standalone && d.PayloadLen > 1400 {
			fake = fake[:d.PayloadOff+1400]
		}
		if p.Standalone {
			if d.Version == packet.Version4 {
				binary.BigEndian.PutUint16(fake[2:4], uint16(len(fake)))
				fake[8] = 6
			} else {
				binary.BigEndian.PutUint16(fake[4:6], uint16(len(fake)-40))
				fake[7] = 6
			}
			d, _ = packet.Dissect(fake)
		}
		payload, _ := d.Payload(fake)
		if !(p.Standalone && pl[0] == 22) {
			for i := range payload {
				payload[i] = byte(i*37 + 17)
			}
		}
		binary.BigEndian.PutUint32(fake[d.L4Off+4:d.L4Off+8], seq-10000)
		if !d.RecomputeChecksums(fake) {
			return
		}
		if p.Standalone {
			fake[d.L4Off+16] ^= 0xff
		}
		if address, ok := metadata.(interface{ WithFinalTCPChecksums() any }); ok {
			metadata = address.WithFinalTCPChecksums()
		}
	} else {
		neutral := make([]byte, len(pl))
		for i := range neutral {
			neutral[i] = byte(i*37 + 17)
		}
		fake, err = discordvoice.BuildDecoy(pkt.Data, discordvoice.FoolBadChecksum, 6, neutral)
		if err != nil {
			return
		}
		address, ok := metadata.(interface{ WithFinalUDPChecksums() any })
		if !ok {
			return
		}
		metadata = address.WithFinalUDPChecksums()
	}
	p.mu.Lock()
	if tcp {
		p.stats.TCP++
	} else {
		p.stats.UDP++
	}
	p.mu.Unlock()
	for range repeats {
		err = sink.Send(capture.Packet{Data: fake, Dir: pkt.Dir, Reinject: metadata})
		p.mu.Lock()
		if err != nil {
			p.stats.Errors++
		} else {
			p.stats.Decoys++
		}
		p.mu.Unlock()
	}
}
func (p *Processor) Stats() Counters { p.mu.Lock(); defer p.mu.Unlock(); return p.stats }
func (p *Processor) AllowTLS(local uint16, host string, port uint16) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil || !Public(ip) {
		return false
	}
	key := flowKey{packet.ProtoTCP, netip.AddrPortFrom(netip.IPv4Unspecified(), local), netip.AddrPortFrom(ip, port)}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.Now()
	if v, ok := p.flows[key]; ok && v.tls && now.Sub(v.last) <= 5*time.Minute {
		v.last = now
		p.flows[key] = v
		return v.allowed
	}
	if len(p.flows) >= 8192 {
		for k, v := range p.flows {
			if now.Sub(v.last) > 5*time.Minute {
				delete(p.flows, k)
			}
		}
	}
	if len(p.flows) >= 8192 {
		p.stats.Limited++
		return false
	}
	p.tokens = min(64, p.tokens+max(0, now.Sub(p.refilled).Seconds())*32)
	p.refilled = now
	allowed := p.tokens >= 2
	if allowed {
		p.tokens -= 2
		p.stats.TCP++
	} else {
		p.stats.Limited++
	}
	p.stats.Connections++
	p.flows[key] = entry{last: now, tls: true, allowed: allowed}
	return allowed
}

func (p *Processor) resetTCP(d packet.Dissection, b []byte, local, remote uint16) {
	src, dst := addresses(d, b)
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.flows, flowKey{packet.ProtoTCP, netip.AddrPortFrom(src, local), netip.AddrPortFrom(dst, remote)})
	delete(p.flows, flowKey{packet.ProtoTCP, netip.AddrPortFrom(netip.IPv4Unspecified(), local), netip.AddrPortFrom(dst, remote)})
}

func (p *Processor) RecordSendError() { p.mu.Lock(); p.stats.Errors++; p.mu.Unlock() }

func (p *Processor) RecordTLS(applied bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if applied {
		p.stats.TLSApplied++
	} else {
		p.stats.TLSFailed++
	}
}
func (p *Processor) PreparedTLSIPs(n int) {
	p.mu.Lock()
	p.stats.TLSPrepared = uint64(n)
	p.mu.Unlock()
}

func (p *Processor) SetTunnel() { p.mu.Lock(); p.stats.Tunnel = true; p.mu.Unlock() }
func (p *Processor) RecordTunnelFlow(tcp bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats.Connections++
	if tcp {
		p.stats.TCP++
	} else {
		p.stats.UDP++
	}
}
func (p *Processor) ObserveTunnel(pkt capture.Packet) {
	p.Observe(pkt, nil)
	d, e := packet.Dissect(pkt.Data)
	if e != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if pkt.Dir == core.DirectionOutbound {
		p.stats.TunnelSent += uint64(d.PayloadLen)
	} else {
		p.stats.TunnelReceived += uint64(d.PayloadLen)
	}
}
