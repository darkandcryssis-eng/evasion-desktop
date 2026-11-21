package gamefilter

import (
	"encoding/binary"
	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/packet"
	"net/netip"
	"time"
)

type observation struct {
	group              flowKey
	tls                bool
	first, last, reply time.Time
	attempts           int
	helping            bool
	stage              int
}
type AdaptiveState struct {
	Stage      string `json:"stage"`
	Watching   int    `json:"watching"`
	Helping    int    `json:"helping"`
	Responsive int    `json:"responsive"`
}

// Observe uses game socket replies, never a probe to an unrelated website.
func (p *Processor) Observe(pkt capture.Packet, sink capture.PacketSink) {
	d, err := packet.Dissect(pkt.Data)
	if err != nil || d.Truncated || d.Fragment {
		return
	}
	src, dst := addresses(d, pkt.Data)
	var local, remote uint16
	outbound := pkt.Dir == core.DirectionOutbound
	switch d.Protocol {
	case packet.ProtoTCP:
		h, ok := d.TCP(pkt.Data)
		if !ok || !p.Options.TCP() {
			return
		}
		local, remote = h.SrcPort(), h.DstPort()
	case packet.ProtoUDP:
		h, ok := d.UDP(pkt.Data)
		if !ok || !p.Options.UDP() {
			return
		}
		local, remote = h.SrcPort(), h.DstPort()
	default:
		return
	}
	if !outbound {
		src, dst = dst, src
		local, remote = remote, local
	}
	if !Public(dst) || !p.Owner.Owns(d.Protocol.String(), local) {
		return
	}
	key := flowKey{d.Protocol, netip.AddrPortFrom(src, local), netip.AddrPortFrom(dst, remote)}
	group := key
	if owner, ok := p.Owner.(interface{ Identity(string, uint16) uint32 }); ok {
		pid := owner.Identity(d.Protocol.String(), local)
		if pid == 0 {
			return
		}
		var id [4]byte
		binary.BigEndian.PutUint32(id[:], pid)
		group.local = netip.AddrPortFrom(netip.AddrFrom4(id), 0)
	}
	if d.Protocol == packet.ProtoTCP && p.observeTransport(pkt, d, key, group, outbound) {
		return
	}
	if d.PayloadLen == 0 {
		if outbound && d.Protocol == packet.ProtoTCP {
			h, _ := d.TCP(pkt.Data)
			if h.Flags()&(packet.FlagSYN|packet.FlagACK) == packet.FlagSYN {
				p.resetTCP(d, pkt.Data, local, remote)
				p.mu.Lock()
				delete(p.observations, flowKey{d.Protocol, netip.AddrPortFrom(src, local), netip.AddrPortFrom(dst, remote)})
				p.mu.Unlock()
			}
		}
		return
	}
	p.mu.Lock()
	now := p.Now()
	if p.observations == nil {
		p.observations = map[flowKey]observation{}
	}
	v, found := p.observations[key]
	if !found || v.group != group || now.Sub(v.last) > 5*time.Minute {
		if !found && len(p.observations) >= 8192 {
			for k, old := range p.observations {
				if now.Sub(old.last) > 5*time.Minute {
					delete(p.observations, k)
				}
			}
			if len(p.observations) >= 8192 {
				p.mu.Unlock()
				return
			}
		}
		if found && v.group != group {
			delete(p.flows, key)
		}
		v = observation{first: now, group: group}
	}
	v.last = now
	if d.Protocol == packet.ProtoTCP {
		payload, _ := d.Payload(pkt.Data)
		if len(payload) >= 3 && (payload[0] == 21 || payload[0] == 22 || payload[0] == 23) && payload[1] == 3 {
			v.tls = true
		}
	}
	if !outbound {
		v.reply = now
		v.first = now
		v.attempts = 0
		v.helping = false
		v.stage = 0
		p.trackRetry(group, key.local, now, true)
	} else {
		v.attempts++
		v.helping = false
		v.stage = 0
		if v.reply.IsZero() || now.Sub(v.reply) > 20*time.Second {
			first, attempts := p.trackRetry(group, key.local, now, false)
			if attempts >= 3 && now.Sub(first) >= 8*time.Second {
				v.helping = true
				if p.Options.Mode == "auto" {
					v.stage = autoStage(now.Sub(first))
				}
			}
		}
	}

	p.observations[key] = v
	help := !p.Adaptive || v.helping
	if p.Options.Mode == "auto" {
		help = v.helping
	}
	stage := v.stage
	skipTLS := p.TLSHandled && v.tls
	p.mu.Unlock()
	if outbound && help && !skipTLS && !p.ObserveOnly {
		p.before(pkt, sink, stage)
	}
}
func (p *Processor) AdaptiveState() AdaptiveState {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.Now()
	s := AdaptiveState{Stage: "watching"}
	stage := 0
	for _, v := range p.observations {
		if now.Sub(v.last) > time.Minute {
			continue
		}
		if v.helping {
			s.Helping++
			stage = max(stage, v.stage)
		} else if !v.reply.IsZero() {
			s.Responsive++
		} else {
			s.Watching++
		}
	}
	switch stage {
	case 1:
		s.Stage = "gentle"
	case 2:
		s.Stage = "balanced"
	case 3:
		s.Stage = "strong"
	}
	return s
}

func autoStage(elapsed time.Duration) int {
	if elapsed >= 28*time.Second {
		return 3
	}
	if elapsed >= 16*time.Second {
		return 2
	}
	return 1
}

// Keep each socket's replies separate; only unanswered attempts contribute to
// retry learning for the same process and remote endpoint.
type pendingAttempt struct {
	local       netip.AddrPort
	first, last time.Time
	attempts    int
}
type retryGroup struct {
	last      time.Time
	pending   [8]pendingAttempt
	failedTLS int
}

func (p *Processor) trackRetry(group flowKey, local netip.AddrPort, now time.Time, reply bool) (time.Time, int) {
	if p.retries == nil {
		p.retries = map[flowKey]retryGroup{}
	}
	r, found := p.retries[group]
	if found && now.Sub(r.last) > time.Minute {
		r = retryGroup{}
	}
	if !found {
		if reply {
			return now, 0
		}
		if len(p.retries) >= 8192 {
			for k, v := range p.retries {
				if now.Sub(v.last) > time.Minute {
					delete(p.retries, k)
				}
			}
		}
		if len(p.retries) >= 8192 {
			return now, 0
		}
	}
	slot := -1
	empty := -1
	oldest := 0
	for i, v := range r.pending {
		if !v.local.IsValid() || now.Sub(v.last) > time.Minute {
			r.pending[i] = pendingAttempt{}
			empty = i
			continue
		}
		if v.local == local {
			slot = i
		}
		if v.last.Before(r.pending[oldest].last) {
			oldest = i
		}
	}
	if reply {
		if slot >= 0 {
			r.pending[slot] = pendingAttempt{}
		}
	} else {
		if slot < 0 {
			slot = empty
			if slot < 0 {
				slot = oldest
			}
			r.pending[slot] = pendingAttempt{local: local, first: now}
		}
		v := r.pending[slot]
		v.last = now
		v.attempts = min(3, v.attempts+1)
		r.pending[slot] = v
		r.last = now
	}
	first := now
	attempts := 0
	for _, v := range r.pending {
		if v.local.IsValid() {
			if v.first.Before(first) {
				first = v.first
			}
			attempts += v.attempts
		}
	}
	if attempts == 0 {
		delete(p.retries, group)
	} else {
		p.retries[group] = r
	}
	return first, attempts
}

// TCP always starts with a conservative, byte-preserving split. Escalation is
// selected for later handshakes using unanswered attempts for this endpoint.
func (p *Processor) TLSLevel(local uint16, host string, port uint16) int {
	if p.Options.Mode != "auto" {
		switch p.Options.Mode {
		case "balanced":
			return 2
		case "strong":
			return 3
		}
		return 1
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return 1
	}
	owner, ok := p.Owner.(interface{ Identity(string, uint16) uint32 })
	if !ok {
		return 1
	}
	pid := owner.Identity("tcp", local)
	if pid == 0 {
		return 1
	}
	var id [4]byte
	binary.BigEndian.PutUint32(id[:], pid)
	key := flowKey{packet.ProtoTCP, netip.AddrPortFrom(netip.AddrFrom4(id), 0), netip.AddrPortFrom(ip, port)}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.Now()
	r := p.retries[key]
	level := 1
	if now.Sub(r.last) <= time.Minute {
		level = min(3, 1+r.failedTLS)
	}
	first := now
	attempts := 0
	for _, v := range r.pending {
		if v.local.IsValid() && now.Sub(v.last) <= time.Minute {
			attempts += v.attempts
			if v.first.Before(first) {
				first = v.first
			}
		}
	}
	if attempts >= 3 && now.Sub(first) >= 8*time.Second {
		return max(level, autoStage(now.Sub(first)))
	}
	return level
}
