package gamefilter

import (
	"encoding/binary"
	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/packet"
	"net/netip"
	"testing"
	"time"
)

func reply(t *testing.T, p capture.Packet) capture.Packet {
	t.Helper()
	b := append([]byte(nil), p.Data...)
	d, _ := packet.Dissect(b)
	for i := 0; i < 4; i++ {
		b[12+i], b[16+i] = b[16+i], b[12+i]
	}
	b[d.L4Off], b[d.L4Off+2] = b[d.L4Off+2], b[d.L4Off]
	b[d.L4Off+1], b[d.L4Off+3] = b[d.L4Off+3], b[d.L4Off+1]
	d.RecomputeChecksums(b)
	p.Data = b
	p.Dir = core.DirectionInbound
	return p
}
func TestAdaptiveWaitsForStallAndStopsAfterReply(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{true: "TCP", false: "UDP"}[tcp], func(t *testing.T) {
			o := Default()
			o.Mode = "balanced"
			p := New(o, testOwner(true))
			p.Standalone = true
			p.Adaptive = true
			now := time.Now()
			p.Now = func() time.Time { return now }
			pkt := testPacket(t, tcp, false)
			s := &testSink{}
			p.Observe(pkt, s)
			now = now.Add(4 * time.Second)
			p.Observe(pkt, s)
			if len(s.sent) != 0 {
				t.Fatal("healthy first attempt modified")
			}
			now = now.Add(5 * time.Second)
			p.Observe(pkt, s)
			if len(s.sent) != 3 || p.AdaptiveState().Helping != 1 {
				t.Fatal("no targeted help after stall", len(s.sent), p.AdaptiveState())
			}
			p.Observe(reply(t, pkt), s)
			n := len(s.sent)
			now = now.Add(time.Second)
			p.Observe(pkt, s)
			if len(s.sent) != n || p.AdaptiveState().Responsive != 1 {
				t.Fatal("continued helping after reply")
			}
		})
	}
}
func TestAdaptiveHealthyAndUnselectedNeverInject(t *testing.T) {
	for _, selected := range []bool{false, true} {
		o := Default()
		o.Mode = "strong"
		p := New(o, testOwner(selected))
		p.Standalone = true
		p.Adaptive = true
		now := time.Now()
		p.Now = func() time.Time { return now }
		pkt := testPacket(t, false, false)
		s := &testSink{}
		for range 30 {
			p.Observe(pkt, s)
			p.Observe(reply(t, pkt), s)
			now = now.Add(time.Second)
		}
		if len(s.sent) != 0 {
			t.Fatal("responsive or unselected flow touched")
		}
	}
}
func TestAdaptiveManualAndFlowIsolation(t *testing.T) {
	o := Default()
	o.Mode = "gentle"
	p := New(o, testOwner(true))
	p.Standalone = true
	s := &testSink{}
	pkt := testPacket(t, true, false)
	pkt.Data[len(pkt.Data)-80] = 22 // TLS is also handled in independent mode.
	p.Observe(pkt, s)
	if len(s.sent) != 1 {
		t.Fatal("manual TLS did not activate")
	}
	p = New(o, testOwner(true))
	p.Standalone = true
	p.Adaptive = true
	now := time.Now()
	p.Now = func() time.Time { return now }
	p.Observe(pkt, s)
	now = now.Add(10 * time.Second)
	p.Observe(pkt, s)
	p.Observe(pkt, s)
	n := len(s.sent)
	other := testPacket(t, true, false)
	d, _ := packet.Dissect(other.Data)
	binary.BigEndian.PutUint16(other.Data[d.L4Off+2:], 5056)
	d.RecomputeChecksums(other.Data)
	p.Observe(other, s)
	if len(s.sent) != n {
		t.Fatal("help leaked into another socket")
	}
}
func FuzzDecodeSocketRows(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0}, false, false)
	f.Fuzz(func(t *testing.T, b []byte, tcp, v6 bool) {
		protocol := "udp"
		if tcp {
			protocol = "tcp"
		}
		_, _ = decodeRows(b, protocol, v6)
	})
}
func FuzzObserveMalformedPackets(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		o := Default()
		o.Mode = "balanced"
		p := New(o, testOwner(true))
		p.Standalone = true
		p.Adaptive = true
		p.Observe(capture.Packet{Data: b, Dir: core.DirectionOutbound}, &testSink{})
	})
}

type reconnectOwner struct{ pid uint32 }

func (o *reconnectOwner) Owns(string, uint16) bool       { return true }
func (o *reconnectOwner) Identity(string, uint16) uint32 { return o.pid }
func TestAdaptiveCorrelatesReconnectsButSeparatesProcesses(t *testing.T) {
	o := Default()
	o.Mode = "balanced"
	owner := &reconnectOwner{pid: 12345}
	p := New(o, owner)
	p.Standalone = true
	p.Adaptive = true
	now := time.Now()
	p.Now = func() time.Time { return now }
	s := &testSink{}
	for i := range 3 {
		pkt := testPacket(t, true, false)
		d, _ := packet.Dissect(pkt.Data)
		binary.BigEndian.PutUint16(pkt.Data[d.L4Off:], uint16(45000+i))
		d.RecomputeChecksums(pkt.Data)
		p.Observe(pkt, s)
		now = now.Add(5 * time.Second)
	}
	if len(s.sent) != 3 {
		t.Fatal("retry on new local port was not recognized", len(s.sent))
	}
	n := len(s.sent)
	owner.pid = 99999
	p.Observe(testPacket(t, true, false), s)
	if len(s.sent) != n {
		t.Fatal("adaptive decision leaked into another process")
	}
}

func TestAutoModeEscalatesOncePerStageAndRecovers(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{true: "tcp", false: "udp"}[tcp], func(t *testing.T) {
			o := Default()
			o.Mode = "auto"
			p := New(o, testOwner(true))
			p.Standalone = true
			p.Adaptive = true
			start := time.Now()
			now := start
			p.Now = func() time.Time { return now }
			pkt := testPacket(t, tcp, false)
			sink := &testSink{}
			for _, seconds := range []int{0, 4, 9} {
				now = start.Add(time.Duration(seconds) * time.Second)
				p.Observe(pkt, sink)
			}
			if len(sink.sent) != 1 || p.AdaptiveState().Stage != "gentle" {
				t.Fatal("auto did not start gently", len(sink.sent), p.AdaptiveState())
			}
			now = start.Add(17 * time.Second)
			p.Observe(pkt, sink)
			if len(sink.sent) != 4 || p.AdaptiveState().Stage != "balanced" {
				t.Fatal("no balanced escalation", len(sink.sent))
			}
			now = start.Add(29 * time.Second)
			p.Observe(pkt, sink)
			if len(sink.sent) != 10 || p.AdaptiveState().Stage != "strong" {
				t.Fatal("no strong escalation", len(sink.sent))
			}
			p.Observe(pkt, sink)
			if len(sink.sent) != 10 {
				t.Fatal("unbounded repeated escalation")
			}
			p.Observe(reply(t, pkt), sink)
			now = now.Add(time.Second)
			p.Observe(pkt, sink)
			if len(sink.sent) != 10 || p.AdaptiveState().Helping != 0 {
				t.Fatal("auto continued after reply")
			}
		})
	}
}
func TestAutoModeDoesNotTouchResponsiveTraffic(t *testing.T) {
	o := Default()
	o.Mode = "auto"
	p := New(o, testOwner(true))
	p.Standalone = true
	p.Adaptive = true
	now := time.Now()
	p.Now = func() time.Time { return now }
	pkt := testPacket(t, false, false)
	sink := &testSink{}
	for range 40 {
		p.Observe(pkt, sink)
		p.Observe(reply(t, pkt), sink)
		now = now.Add(time.Second)
	}
	if len(sink.sent) != 0 {
		t.Fatal("auto changed healthy connection")
	}
}

func TestHealthyConnectionMustNotMaskStalledSibling(t *testing.T) {
	o := Default()
	o.Mode = "auto"
	p := New(o, &reconnectOwner{pid: 12345})
	p.Standalone = true
	p.Adaptive = true
	start := time.Now()
	now := start
	p.Now = func() time.Time { return now }
	stalled := testPacket(t, true, false)
	healthy := testPacket(t, true, false)
	d, _ := packet.Dissect(healthy.Data)
	binary.BigEndian.PutUint16(healthy.Data[d.L4Off:], 45001)
	d.RecomputeChecksums(healthy.Data)
	sink := &testSink{}
	for _, seconds := range []int{0, 4, 9, 17} {
		now = start.Add(time.Duration(seconds) * time.Second)
		p.Observe(stalled, sink)
		p.Observe(healthy, sink)
		p.Observe(reply(t, healthy), sink)
	}
	if p.AdaptiveState().Helping == 0 {
		t.Fatalf("stalled connection hidden by another socket: sent=%d state=%+v", len(sink.sent), p.AdaptiveState())
	}
}

func TestRetryLearningDoesNotKeepRepliedSibling(t *testing.T) {
	p := New(Default(), testOwner(true))
	now := time.Now()
	group := flowKey{}
	a := netip.MustParseAddrPort("10.0.0.1:45000")
	b := netip.MustParseAddrPort("10.0.0.1:45001")
	p.trackRetry(group, a, now, false)
	p.trackRetry(group, b, now, false)
	first, n := p.trackRetry(group, b, now.Add(time.Second), true)
	if n != 1 || !first.Equal(now) {
		t.Fatal("reply affected another flow", n, first)
	}
	_, n = p.trackRetry(group, a, now.Add(2*time.Second), true)
	if n != 0 || len(p.retries) != 0 {
		t.Fatal("answered retry state leaked")
	}
}
func TestRetryHistoryExpiresAndIsBounded(t *testing.T) {
	p := New(Default(), testOwner(true))
	now := time.Now()
	group := flowKey{}
	a := netip.MustParseAddrPort("10.0.0.1:45000")
	p.trackRetry(group, a, now, false)
	first, n := p.trackRetry(group, netip.MustParseAddrPort("10.0.0.1:45001"), now.Add(61*time.Second), false)
	if n != 1 || !first.Equal(now.Add(61*time.Second)) {
		t.Fatal("stale failures retained")
	}
	for i := range 30 {
		p.trackRetry(group, netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), uint16(46000+i)), now.Add(62*time.Second), false)
	}
	if len(p.retries) != 1 {
		t.Fatal("unbounded per-endpoint state")
	}
}

func TestFlowIdentityChangeClearsOldObservation(t *testing.T) {
	o := Default()
	o.Mode = "auto"
	owner := &reconnectOwner{pid: 1}
	p := New(o, owner)
	p.Standalone = true
	p.Adaptive = true
	start := time.Now()
	now := start
	p.Now = func() time.Time { return now }
	pkt := testPacket(t, true, false)
	sink := &testSink{}
	for _, seconds := range []int{0, 4, 9} {
		now = start.Add(time.Duration(seconds) * time.Second)
		p.Observe(pkt, sink)
	}
	if p.AdaptiveState().Helping != 1 {
		t.Fatal("fixture not stalled")
	}
	owner.pid = 2
	now = now.Add(time.Second)
	p.Observe(pkt, sink)
	if p.AdaptiveState().Helping != 0 {
		t.Fatal("previous process decision leaked into new owner")
	}
}
func TestSYNResetsConnectionBudgetButRetainsRetryLearning(t *testing.T) {
	o := Default()
	o.Mode = "auto"
	p := New(o, testOwner(true))
	p.Standalone = true
	p.Adaptive = true
	start := time.Now()
	now := start
	p.Now = func() time.Time { return now }
	pkt := testPacket(t, true, false)
	sink := &testSink{}
	for _, seconds := range []int{0, 4, 9} {
		now = start.Add(time.Duration(seconds) * time.Second)
		p.Observe(pkt, sink)
	}
	if len(sink.sent) != 1 {
		t.Fatal("fixture missing help")
	}
	syn := pkt
	syn.Data = append([]byte(nil), pkt.Data[:40]...)
	binary.BigEndian.PutUint16(syn.Data[2:4], 40)
	syn.Data[33] = packet.FlagSYN
	d, _ := packet.Dissect(syn.Data)
	d.RecomputeChecksums(syn.Data)
	p.Observe(syn, sink)
	if len(p.flows) != 0 || len(p.observations) != 0 {
		t.Fatal("old tuple retained across SYN")
	}
	now = now.Add(time.Second)
	p.Observe(pkt, sink)
	if len(sink.sent) != 2 {
		t.Fatal("retry learning or fresh budget lost", len(sink.sent))
	}
}
func TestRetryEndpointTableCapacityAndExpiry(t *testing.T) {
	p := New(Default(), testOwner(true))
	now := time.Now()
	local := netip.MustParseAddrPort("10.0.0.1:45000")
	for i := range 8192 {
		group := flowKey{remote: netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), uint16(1024+i))}
		p.trackRetry(group, local, now, false)
	}
	extra := flowKey{remote: netip.MustParseAddrPort("1.1.1.1:65534")}
	_, n := p.trackRetry(extra, local, now, false)
	if len(p.retries) != 8192 || n != 0 {
		t.Fatal("retry table limit exceeded")
	}
	_, n = p.trackRetry(extra, local, now.Add(61*time.Second), false)
	if n != 1 || len(p.retries) != 1 {
		t.Fatal("retry table did not reclaim expired entries")
	}
}

func TestExpiredRetryHistoryDoesNotReuseOldHelpStage(t *testing.T) {
	o := Default()
	o.Mode = "auto"
	p := New(o, testOwner(true))
	p.Standalone = true
	p.Adaptive = true
	start := time.Now()
	now := start
	p.Now = func() time.Time { return now }
	pkt := testPacket(t, true, false)
	sink := &testSink{}
	for _, seconds := range []int{0, 4, 9} {
		now = start.Add(time.Duration(seconds) * time.Second)
		p.Observe(pkt, sink)
	}
	if p.AdaptiveState().Helping != 1 {
		t.Fatal("fixture not stalled")
	}
	now = now.Add(61 * time.Second)
	p.Observe(pkt, sink)
	if p.AdaptiveState().Helping != 0 || p.AdaptiveState().Stage != "watching" || len(sink.sent) != 1 {
		t.Fatal("expired retry reused old stage", p.AdaptiveState())
	}
}

func TestRealTLSHandlingDoesNotAlsoInjectRawFakes(t *testing.T) {
	o := Default()
	o.Mode = "auto"
	p := New(o, testOwner(true))
	p.Standalone = true
	p.Adaptive = true
	p.TLSHandled = true
	start := time.Now()
	now := start
	p.Now = func() time.Time { return now }
	pkt := testPacket(t, true, false)
	pkt.Data[40] = 22
	pkt.Data[41] = 3
	pkt.Data[42] = 3
	sink := &testSink{}
	for _, seconds := range []int{0, 4, 9, 17, 29} {
		now = start.Add(time.Duration(seconds) * time.Second)
		p.Observe(pkt, sink)
	}
	if len(sink.sent) != 0 {
		t.Fatal("double processing of TLS", len(sink.sent))
	}
	if p.AdaptiveState().Helping != 1 {
		t.Fatal("observation did not continue")
	}
}

func TestTLSLevelUsesOnlyUnansweredAttemptsForSameProcessAndEndpoint(t *testing.T) {
	o := Default()
	o.Mode = "auto"
	owner := &reconnectOwner{pid: 12345}
	p := New(o, owner)
	p.Standalone, p.Adaptive, p.TLSHandled = true, true, true
	start := time.Now()
	now := start
	p.Now = func() time.Time { return now }
	pkt := testPacket(t, true, false)
	pkt.Data[40], pkt.Data[41], pkt.Data[42] = 22, 3, 3
	d, _ := packet.Dissect(pkt.Data)
	_, remote := addresses(d, pkt.Data)
	h, _ := d.TCP(pkt.Data)
	local, port := h.SrcPort(), h.DstPort()
	sink := &testSink{}
	for i, seconds := range []int{0, 4, 9, 17, 29} {
		now = start.Add(time.Duration(seconds) * time.Second)
		p.Observe(pkt, sink)
		if got, want := p.TLSLevel(local, remote.String(), port), []int{1, 1, 1, 2, 3}[i]; got != want {
			t.Fatalf("after %ds: level %d, want %d", seconds, got, want)
		}
	}
	if got := p.TLSLevel(local, remote.String(), port+1); got != 1 {
		t.Fatal("another endpoint inherited escalation", got)
	}
	owner.pid++
	if got := p.TLSLevel(local, remote.String(), port); got != 1 {
		t.Fatal("another process inherited escalation", got)
	}
	owner.pid--
	now = now.Add(61 * time.Second)
	if got := p.TLSLevel(local, remote.String(), port); got != 1 {
		t.Fatal("expired history inherited escalation", got)
	}
	now = start.Add(30 * time.Second)
	p.Observe(reply(t, pkt), sink)
	if got := p.TLSLevel(local, remote.String(), port); got != 1 {
		t.Fatal("answered endpoint kept escalation", got)
	}
}
