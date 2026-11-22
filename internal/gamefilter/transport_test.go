package gamefilter

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/packet"
)

func transportPacket(t *testing.T, flags byte, data []byte, inbound bool, local uint16) capture.Packet {
	t.Helper()
	pkt := testPacket(t, true, false)
	pkt.Data = append(pkt.Data[:40:40], data...)
	binary.BigEndian.PutUint16(pkt.Data[2:4], uint16(len(pkt.Data)))
	binary.BigEndian.PutUint16(pkt.Data[20:22], local)
	pkt.Data[33] = flags
	d, _ := packet.Dissect(pkt.Data)
	d.RecomputeChecksums(pkt.Data)
	if inbound {
		return reply(t, pkt)
	}
	return pkt
}

func TestTLSRetryAfterClosedHandshakeAdvancesImmediately(t *testing.T) {
	for _, close := range []struct {
		name  string
		flags byte
		data  []byte
	}{
		{"reset", packet.FlagRST | packet.FlagACK, nil},
		{"fin", packet.FlagFIN | packet.FlagACK, nil},
		{"alert", packet.FlagACK | packet.FlagPSH, []byte{21, 3, 3, 0, 2, 2, 40}},
	} {
		t.Run(close.name, func(t *testing.T) {
			o := Default()
			o.Mode = "auto"
			p := New(o, &reconnectOwner{pid: 12345})
			p.Standalone, p.Adaptive, p.TLSHandled = true, true, true
			now := time.Now()
			p.Now = func() time.Time { return now }
			sink := &testSink{}
			for i := uint16(0); i < 3; i++ {
				local := uint16(45000) + i
				p.Observe(transportPacket(t, packet.FlagACK|packet.FlagPSH, []byte{22, 3, 3, 0, 1, 1}, false, local), sink)
				if got := p.TLSLevel(local, "1.1.1.1", 5055); got != int(i)+1 {
					t.Fatalf("handshake %d: level %d, want %d", i+1, got, i+1)
				}
				for range 2 {
					p.Observe(transportPacket(t, close.flags, close.data, true, local), sink)
				}
				now = now.Add(time.Second)
			}
		})
	}
}

func TestPassiveTransportSeparatesTCPAndTLSProgress(t *testing.T) {
	o := Default()
	o.Mode = "auto"
	p := New(o, testOwner(true))
	p.ObserveOnly = true
	now := time.Now()
	p.Now = func() time.Time { return now }
	sink := &testSink{}
	syn := transportPacket(t, packet.FlagSYN, nil, false, 45000)
	p.Observe(syn, sink)
	now = now.Add(6 * time.Second)
	p.Observe(syn, sink)
	now = now.Add(7 * time.Second)
	if s := p.TransportState(); s.NoTCPReply != 1 || s.Stage != "tcp_unanswered" {
		t.Fatal(s)
	}
	p.Observe(transportPacket(t, packet.FlagSYN|packet.FlagACK, nil, true, 45000), sink)
	if s := p.TransportState(); s.NoTCPReply != 0 {
		t.Fatal("SYNACK ignored", s)
	}
	p.Observe(transportPacket(t, packet.FlagACK|packet.FlagPSH, []byte{22, 3, 3, 0, 1, 1}, false, 45000), sink)
	p.Observe(transportPacket(t, packet.FlagACK, nil, true, 45000), sink)
	now = now.Add(13 * time.Second)
	if s := p.TransportState(); s.NoTLSReply != 1 || s.Responding != 0 || s.Stage != "tls_unanswered" {
		t.Fatal("ACK counted as server data", s)
	}
	p.Observe(transportPacket(t, packet.FlagACK|packet.FlagPSH, []byte{22, 3, 3, 0, 1, 2}, true, 45000), sink)
	if s := p.TransportState(); s.NoTLSReply != 0 || s.Responding != 1 {
		t.Fatal("server data ignored", s)
	}
	if len(sink.sent) != 0 {
		t.Fatal("passive observation changed traffic")
	}
}

func TestTLSFailureHistoryResetsAfterSuccessAndStaysProcessScoped(t *testing.T) {
	o := Default()
	o.Mode = "auto"
	owner := &reconnectOwner{pid: 12345}
	p := New(o, owner)
	p.ObserveOnly = true
	p.TLSHandled = true
	for i := uint16(0); i < 2; i++ {
		local := uint16(45000) + i
		p.Observe(transportPacket(t, packet.FlagACK|packet.FlagPSH, []byte{22, 3, 3, 0, 1, 1}, false, local), nil)
		p.Observe(transportPacket(t, packet.FlagRST|packet.FlagACK, nil, true, local), nil)
	}
	if got := p.TLSLevel(45002, "1.1.1.1", 5055); got != 3 {
		t.Fatal(got)
	}
	owner.pid++
	if got := p.TLSLevel(45002, "1.1.1.1", 5055); got != 1 {
		t.Fatal("failure leaked across PID", got)
	}
	owner.pid--
	p.Observe(transportPacket(t, packet.FlagACK|packet.FlagPSH, []byte{22, 3, 3, 0, 1, 1}, false, 45002), nil)
	p.Observe(transportPacket(t, packet.FlagACK|packet.FlagPSH, []byte{22, 3, 3, 0, 1, 2}, true, 45002), nil)
	if got := p.TLSLevel(45003, "1.1.1.1", 5055); got != 1 {
		t.Fatal("success did not reset failed TLS history", got)
	}
	if s := p.TransportState(); s.Stage != "exchanging" {
		t.Fatal("closed retry obscured successful recovery", s)
	}
}

func TestTransportIgnoresForeignSocketsAndExpiresBoundedState(t *testing.T) {
	o := Default()
	o.Mode = "auto"
	p := New(o, testOwner(false))
	pkt := transportPacket(t, packet.FlagSYN, nil, false, 45000)
	before := append([]byte(nil), pkt.Data...)
	p.Observe(pkt, nil)
	if len(p.transport) != 0 || string(before) != string(pkt.Data) {
		t.Fatal("foreign flow was changed or recorded")
	}
	p = New(o, testOwner(true))
	now := time.Now()
	p.Now = func() time.Time { return now }
	for i := uint16(0); i < 8193; i++ {
		p.Observe(transportPacket(t, packet.FlagSYN, nil, false, 10000+i), nil)
	}
	if len(p.transport) != 8192 {
		t.Fatal("transport state is not bounded", len(p.transport))
	}
	now = now.Add(61 * time.Second)
	if s := p.TransportState(); s.Stage != "idle" || len(p.transport) != 0 {
		t.Fatal("expired state remained", s)
	}
}

func TestTransportInfersUnobservedReplyFromGameACK(t *testing.T) {
	o := Default()
	o.Mode = "auto"
	p := New(o, testOwner(true))
	p.ObserveOnly = true
	now := time.Now()
	p.Now = func() time.Time { return now }
	sink := &testSink{}
	out := func(flags byte, data []byte, ack uint32) {
		pkt := transportPacket(t, flags, data, false, 45000)
		d, _ := packet.Dissect(pkt.Data)
		h, _ := d.TCP(pkt.Data)
		h.SetAck(ack)
		p.Observe(pkt, sink)
	}
	out(packet.FlagSYN, nil, 0)
	out(packet.FlagACK|packet.FlagPSH, []byte{22, 3, 3, 0, 1, 1}, 1000)
	out(packet.FlagACK, nil, 1008)
	now = now.Add(13 * time.Second)
	if s := p.TransportState(); s.NoTLSReply != 1 {
		t.Fatal("acknowledged alert and FIN counted as a reply", s)
	}
	out(packet.FlagACK, nil, 2400)
	if s := p.TransportState(); s.NoTLSReply != 0 || s.Responding != 1 {
		t.Fatal("acknowledged server data ignored", s)
	}
	// A server FIN after replies that were never captured is not a failed handshake.
	out(packet.FlagSYN, nil, 0)
	pkt := transportPacket(t, packet.FlagACK|packet.FlagPSH, []byte{22, 3, 3, 0, 1, 1}, false, 45001)
	p.Observe(pkt, sink)
	fin := transportPacket(t, packet.FlagACK|packet.FlagFIN, nil, true, 45001)
	d, _ := packet.Dissect(fin.Data)
	fh, _ := d.TCP(fin.Data)
	ph, _ := func() (packet.TCPHeader, bool) { d, _ := packet.Dissect(pkt.Data); return d.TCP(pkt.Data) }()
	fh.SetSeq(ph.Ack() + 3000)
	p.Observe(fin, sink)
	if s := p.TransportState(); s.TLSClosed != 0 {
		t.Fatal("server FIN after unobserved replies counted as a closed handshake", s)
	}
}
