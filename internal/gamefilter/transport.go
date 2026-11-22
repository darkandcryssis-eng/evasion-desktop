package gamefilter

import (
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/packet"
)

type TransportState struct {
	Stage      string `json:"stage"`
	Connecting int    `json:"connecting"`
	TLSWaiting int    `json:"tlsWaiting"`
	Responding int    `json:"responding"`
	NoTCPReply int    `json:"noTCPReply"`
	NoTLSReply int    `json:"noTLSReply"`
	TLSClosed  int    `json:"tlsClosed"`
	TCPClosed  int    `json:"tcpClosed"`
}

type transportFlow struct {
	group                       flowKey
	first, last, tls, responded time.Time
	synSeq, helloAck, sent      uint32
	gap                         bool
	sawSYN, connected           bool
	closed, peerClosed, failed  bool
}

// Passive evidence from verified game sockets; ACKs are not server data.
func (p *Processor) observeTransport(pkt capture.Packet, d packet.Dissection, key, group flowKey, outbound bool) bool {
	h, ok := d.TCP(pkt.Data)
	if !ok {
		return false
	}
	payload, _ := d.Payload(pkt.Data)
	syn := outbound && h.Flags()&(packet.FlagSYN|packet.FlagACK) == packet.FlagSYN
	alert := !outbound && len(payload) >= 3 && payload[0] == 21 && payload[1] == 3
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.Now()
	if p.transport == nil {
		p.transport = map[flowKey]transportFlow{}
	}
	v, found := p.transport[key]
	if !found && !syn && len(payload) == 0 {
		return false
	}
	if !found && len(p.transport) >= 8192 {
		for k, old := range p.transport {
			if now.Sub(old.last) > time.Minute {
				delete(p.transport, k)
			}
		}
		if len(p.transport) >= 8192 {
			return false
		}
	}
	if !found || v.group != group || now.Sub(v.last) > time.Minute || syn && (!v.sawSYN || v.synSeq != h.Seq()) {
		v = transportFlow{group: group, first: now}
	}
	v.last = now
	if syn {
		v.sawSYN, v.synSeq, v.sent = true, h.Seq(), h.Seq()+1
	}
	// Bytes the game sent that were never captured (the filter did not cover
	// the port yet): what this flow carried is unknown.
	if v.sawSYN && !syn && h.Flags()&packet.FlagRST == 0 {
		if outbound {
			v.gap = v.gap || int32(h.Seq()-v.sent) > 0
			end := h.Seq() + uint32(len(payload))
			if h.Flags()&packet.FlagFIN != 0 {
				end++
			}
			if int32(end-v.sent) > 0 {
				v.sent = end
			}
		} else if h.Flags()&packet.FlagACK != 0 {
			v.gap = v.gap || int32(h.Ack()-v.sent) > 0
		}
	}
	if !outbound && h.Flags()&(packet.FlagSYN|packet.FlagACK) == packet.FlagSYN|packet.FlagACK {
		v.connected = true
	}
	// The SYN-ACK can be missed the same way; either side only sends a segment
	// without SYN or RST once the connection is established.
	if v.sawSYN && h.Flags()&(packet.FlagSYN|packet.FlagRST) == 0 {
		v.connected = true
	}
	if outbound && len(payload) >= 3 && payload[0] == 22 && payload[1] == 3 && v.tls.IsZero() {
		v.connected = true
		v.tls = now
		v.helloAck = h.Ack()
	}
	// The server's first reply can arrive before the socket's port is in the
	// capture filter. Sequence numbers still prove it was sent: the game
	// acknowledges, or the server has advanced by, more than a FIN or a TLS
	// alert since the ClientHello.
	acked := false
	if !v.tls.IsZero() && v.responded.IsZero() && h.Flags()&packet.FlagRST == 0 {
		if outbound {
			acked = h.Flags()&packet.FlagACK != 0 && int32(h.Ack()-v.helloAck) > 64
		} else {
			acked = int32(h.Seq()-v.helloAck) > 64
		}
	}
	if !outbound && len(payload) > 0 && !alert || acked {
		v.connected = true
		firstReply := v.responded.IsZero()
		v.responded = now
		if !v.tls.IsZero() {
			if firstReply {
				for oldKey, old := range p.transport {
					if oldKey != key && old.group == group && old.closed && old.responded.IsZero() {
						delete(p.transport, oldKey)
					}
				}
			}
			if r, ok := p.retries[group]; ok {
				r.failedTLS = 0
				p.retries[group] = r
			}
		}
	}
	if h.Flags()&(packet.FlagFIN|packet.FlagRST) != 0 || alert {
		v.closed = true
		v.peerClosed = v.peerClosed || !outbound
		if !v.tls.IsZero() && v.responded.IsZero() && !v.failed {
			v.failed = true
			if p.retries == nil {
				p.retries = map[flowKey]retryGroup{}
			}
			if r, exists := p.retries[group]; exists || len(p.retries) < 8192 {
				if now.Sub(r.last) > time.Minute {
					r = retryGroup{}
				}
				r.failedTLS = min(2, r.failedTLS+1)
				for i, attempt := range r.pending {
					if attempt.local == key.local {
						r.pending[i] = pendingAttempt{}
					}
				}
				r.last = now
				p.retries[group] = r
			}
		}
	}
	p.transport[key] = v
	return alert
}

func (p *Processor) TransportState() TransportState {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := TransportState{Stage: "idle"}
	now := p.Now()
	for key, v := range p.transport {
		if now.Sub(v.last) > time.Minute {
			delete(p.transport, key)
			continue
		}
		switch {
		case !v.responded.IsZero():
			if now.Sub(v.responded) < 30*time.Second {
				s.Responding++
			}
		case v.closed && v.peerClosed:
			if !v.tls.IsZero() {
				s.TLSClosed++
			} else if !v.gap {
				s.TCPClosed++
			}
		case !v.tls.IsZero():
			s.TLSWaiting++
			if now.Sub(v.tls) >= 12*time.Second {
				s.NoTLSReply++
			}
		case !v.connected && v.sawSYN:
			s.Connecting++
			if now.Sub(v.first) >= 12*time.Second {
				s.NoTCPReply++
			}
		}
	}
	switch {
	case s.NoTCPReply > 0:
		s.Stage = "tcp_unanswered"
	case s.TLSClosed > 0:
		s.Stage = "tls_closed"
	case s.NoTLSReply > 0:
		s.Stage = "tls_unanswered"
	case s.TCPClosed > 0:
		s.Stage = "tcp_closed"
	case s.Responding > 0:
		s.Stage = "exchanging"
	case s.TLSWaiting > 0:
		s.Stage = "tls_waiting"
	case s.Connecting > 0:
		s.Stage = "tcp_connecting"
	}
	return s
}
