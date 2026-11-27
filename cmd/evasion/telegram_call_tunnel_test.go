package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/tunnel"
)

func TestBuildInboundUDPPacketIPv4AndIPv6(t *testing.T) {
	payload := []byte("stun-response-payload")

	raw4, ok := buildInboundUDPPacket(
		netip.MustParseAddrPort("91.108.16.100:599"),
		netip.MustParseAddrPort("192.168.1.50:54321"),
		payload,
	)
	if !ok {
		t.Fatal("buildInboundUDPPacket IPv4 failed")
	}
	d4, err := packet.Dissect(raw4)
	if err != nil {
		t.Fatalf("Dissect IPv4: %v", err)
	}
	if d4.Version != packet.Version4 || d4.Protocol != packet.ProtoUDP {
		t.Fatalf("unexpected IPv4 dissection: v=%v proto=%v", d4.Version, d4.Protocol)
	}
	if got := raw4[d4.PayloadOff : d4.PayloadOff+d4.PayloadLen]; !bytes.Equal(got, payload) {
		t.Fatalf("IPv4 payload mismatch: got %q, want %q", got, payload)
	}
	h4, _ := d4.IPv4(raw4)
	if h4.Checksum() == 0 || h4.Checksum() != packet.IPv4HeaderChecksum(raw4[:20]) {
		t.Fatalf("IPv4 header checksum invalid: got 0x%x, want 0x%x", h4.Checksum(), packet.IPv4HeaderChecksum(raw4[:20]))
	}
	u4, _ := d4.UDP(raw4)
	if u4.Checksum() == 0 {
		t.Fatal("IPv4 UDP checksum not computed")
	}

	raw6, ok := buildInboundUDPPacket(
		netip.MustParseAddrPort("[2001:67c:4e8::1]:599"),
		netip.MustParseAddrPort("[2001:db8::50]:54321"),
		payload,
	)
	if !ok {
		t.Fatal("buildInboundUDPPacket IPv6 failed")
	}
	d6, err := packet.Dissect(raw6)
	if err != nil {
		t.Fatalf("Dissect IPv6: %v", err)
	}
	if d6.Version != packet.Version6 || d6.Protocol != packet.ProtoUDP {
		t.Fatalf("unexpected IPv6 dissection: v=%v proto=%v", d6.Version, d6.Protocol)
	}
	if got := raw6[d6.PayloadOff : d6.PayloadOff+d6.PayloadLen]; !bytes.Equal(got, payload) {
		t.Fatalf("IPv6 payload mismatch: got %q, want %q", got, payload)
	}
	u6, _ := d6.UDP(raw6)
	if u6.Checksum() == 0 {
		t.Fatal("IPv6 UDP checksum not computed")
	}
}

type fakeTunnelOwner struct {
	ports map[string]bool
}

func (o fakeTunnelOwner) OwnsUDP(ip netip.Addr, port uint16) bool {
	return o.ports[netip.AddrPortFrom(ip.Unmap(), port).String()]
}

func TestIsTelegramTunnelPacketFiltering(t *testing.T) {
	owner := fakeTunnelOwner{
		ports: map[string]bool{"192.168.1.50:54321": true},
	}

	cases := []struct {
		name string
		src  string
		dst  string
		want bool
	}{
		{"telegram CIDR", "192.168.1.50:40000", "91.108.16.100:599", true},
		{"telegram owned P2P", "192.168.1.50:54321", "85.21.10.20:33445", true},
		{"telegram owned QUIC 443 excluded", "192.168.1.50:54321", "91.108.16.100:443", false},
		{"telegram owned DNS 53 excluded", "192.168.1.50:54321", "8.8.8.8:53", false},
		{"telegram owned LAN excluded", "192.168.1.50:54321", "192.168.1.1:50000", false},
		{"foreign app excluded", "192.168.1.50:40000", "85.21.10.20:33445", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, ok := buildInboundUDPPacket(
				netip.MustParseAddrPort(tc.src),
				netip.MustParseAddrPort(tc.dst),
				[]byte("hello"),
			)
			if !ok {
				t.Fatal("build packet failed")
			}
			d, err := packet.Dissect(raw)
			if err != nil {
				t.Fatalf("Dissect: %v", err)
			}
			_, _, _, _, _, got := isTelegramTunnelPacket(d, raw, owner)
			if got != tc.want {
				t.Fatalf("isTelegramTunnelPacket(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

type fakePacketConn struct {
	mu       sync.Mutex
	closed   bool
	writeErr error
	written  []struct {
		data []byte
		addr net.Addr
	}
	inCh chan struct {
		data []byte
		addr net.Addr
	}
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{
		inCh: make(chan struct {
			data []byte
			addr net.Addr
		}, 16),
	}
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	item, ok := <-f.inCh
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(p, item.data)
	return n, item.addr, nil
}

func (f *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, net.ErrClosed
	}
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	cp := append([]byte(nil), p...)
	f.written = append(f.written, struct {
		data []byte
		addr net.Addr
	}{data: cp, addr: addr})
	return len(p), nil
}

func (f *fakePacketConn) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.inCh)
	}
	return nil
}

func (f *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(172, 16, 0, 2), Port: 40000}
}
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

type fakeUDPTunnel struct {
	mu            sync.Mutex
	conns         []*fakePacketConn
	closed        bool
	firstWriteErr error
}

func (f *fakeUDPTunnel) ListenUDP(bool) (net.PacketConn, error) {
	pc := newFakePacketConn()
	f.mu.Lock()
	if len(f.conns) == 0 {
		pc.writeErr = f.firstWriteErr
	}
	f.conns = append(f.conns, pc)
	f.mu.Unlock()
	return pc, nil
}

func (f *fakeUDPTunnel) Endpoint() string { return "162.159.192.1:2408" }
func (f *fakeUDPTunnel) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

type fakeTunnelHandle struct {
	recvCh      chan capture.Packet
	sendCh      chan capture.Packet
	closed      chan struct{}
	once        sync.Once
	shutdownErr error
}

func newFakeTunnelHandle() *fakeTunnelHandle {
	return &fakeTunnelHandle{
		recvCh: make(chan capture.Packet, 16),
		sendCh: make(chan capture.Packet, 16),
		closed: make(chan struct{}),
	}
}

func (h *fakeTunnelHandle) Recv() (capture.Packet, error) {
	select {
	case <-h.closed:
		return capture.Packet{}, errors.New("closed")
	case pkt := <-h.recvCh:
		return pkt, nil
	}
}

func (h *fakeTunnelHandle) Send(pkt capture.Packet) error {
	h.sendCh <- pkt
	return nil
}

func (h *fakeTunnelHandle) ShutdownReceive() error {
	if h.shutdownErr != nil {
		return h.shutdownErr
	}
	return h.Close()
}

func (h *fakeTunnelHandle) Close() error {
	h.once.Do(func() { close(h.closed) })
	return nil
}

func TestTelegramCallTunnelRelaysAndPassesThrough(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fakeTn := &fakeUDPTunnel{}
	fakeHandle := newFakeTunnelHandle()

	tt := newTelegramCallTunnel(ctx, fakeTunnelOwner{}, nil)
	tt.supported = true
	tt.openTunnel = func(context.Context, map[string]struct{}) (tgUDPTunnel, error) { return fakeTn, nil }
	tt.openHandle = func(string) (tgTunnelConn, error) { return fakeHandle, nil }
	defer tt.Close()

	tt.NotifyUnanswered()

	deadline := time.Now().Add(2 * time.Second)
	for !tt.Stats().Active && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !tt.Stats().Active {
		t.Fatal("expected tunnel to become active")
	}

	// 1. Non-Telegram UDP packet must pass through outbound unchanged.
	foreignRaw, _ := buildInboundUDPPacket(
		netip.MustParseAddrPort("192.168.1.50:40000"),
		netip.MustParseAddrPort("8.8.4.4:50000"),
		[]byte("discord"),
	)
	fakeHandle.recvCh <- capture.Packet{Data: foreignRaw, Dir: core.DirectionOutbound}

	select {
	case out := <-fakeHandle.sendCh:
		if out.Dir != core.DirectionOutbound || !bytes.Equal(out.Data, foreignRaw) {
			t.Fatalf("foreign packet not passed through unchanged")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for foreign passthrough")
	}

	// 2. Two Telegram reflector packets from the same local socket share one PacketConn (Cone NAT).
	tgRaw1, _ := buildInboundUDPPacket(
		netip.MustParseAddrPort("192.168.1.50:54321"),
		netip.MustParseAddrPort("91.108.16.100:599"),
		[]byte("stun-req-1"),
	)
	tgRaw2, _ := buildInboundUDPPacket(
		netip.MustParseAddrPort("192.168.1.50:54321"),
		netip.MustParseAddrPort("149.154.167.50:596"),
		[]byte("stun-req-2"),
	)
	fakeHandle.recvCh <- capture.Packet{Data: tgRaw1, Dir: core.DirectionOutbound}
	fakeHandle.recvCh <- capture.Packet{Data: tgRaw2, Dir: core.DirectionOutbound}

	deadline = time.Now().Add(2 * time.Second)
	for tt.Stats().Sent < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if st := tt.Stats(); st.Sent != 2 || st.Sockets != 1 {
		t.Fatalf("unexpected stats after 2 sends: %+v", st)
	}

	fakeTn.mu.Lock()
	if len(fakeTn.conns) != 1 {
		fakeTn.mu.Unlock()
		t.Fatalf("expected 1 PacketConn (Cone NAT), got %d", len(fakeTn.conns))
	}
	pc := fakeTn.conns[0]
	fakeTn.mu.Unlock()

	// 3. Inject reply from Telegram reflector through WARP -> must arrive inbound to Telegram socket.
	pc.inCh <- struct {
		data []byte
		addr net.Addr
	}{
		data: []byte("stun-ok"),
		addr: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("91.108.16.100:599")),
	}

	select {
	case inPkt := <-fakeHandle.sendCh:
		if inPkt.Dir != core.DirectionInbound {
			t.Fatalf("expected inbound direction, got %v", inPkt.Dir)
		}
		d, err := packet.Dissect(inPkt.Data)
		if err != nil {
			t.Fatalf("Dissect inbound: %v", err)
		}
		srcIP := packetSrcIP(inPkt.Data, d)
		dstIP := packetDstIP(inPkt.Data, d)
		if srcIP != netip.MustParseAddr("91.108.16.100") || dstIP != netip.MustParseAddr("192.168.1.50") {
			t.Fatalf("unexpected inbound IPs: src=%v dst=%v", srcIP, dstIP)
		}
		gotPayload := inPkt.Data[d.PayloadOff : d.PayloadOff+d.PayloadLen]
		if !bytes.Equal(gotPayload, []byte("stun-ok")) {
			t.Fatalf("unexpected inbound payload: %q", gotPayload)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for inbound reply packet")
	}

	tt.Close()
	if tt.Stats().Active {
		t.Fatal("expected tunnel to be inactive after Close")
	}
}

func TestTelegramCallTunnelPreservesPacketOnFailedWrite(t *testing.T) {
	fakeTn := &fakeUDPTunnel{firstWriteErr: errors.New("relay write rejected")}
	handle := newFakeTunnelHandle()
	tt := newTelegramCallTunnel(t.Context(), fakeTunnelOwner{}, nil)
	tt.supported = true
	tt.openTunnel = func(context.Context, map[string]struct{}) (tgUDPTunnel, error) { return fakeTn, nil }
	tt.openHandle = func(string) (tgTunnelConn, error) { return handle, nil }
	defer tt.Close()
	tt.NotifyUnanswered()

	src := netip.MustParseAddrPort("192.168.1.50:54321")
	dst := netip.MustParseAddrPort("91.108.16.100:599")
	raw, _ := buildInboundUDPPacket(src, dst, []byte("call request"))
	pkt := capture.Packet{Data: raw, Dir: core.DirectionOutbound}
	handle.recvCh <- pkt
	select {
	case out := <-handle.sendCh:
		if out.Dir != pkt.Dir || !bytes.Equal(out.Data, pkt.Data) {
			t.Fatal("the failed datagram was changed")
		}
	case <-time.After(time.Second):
		t.Fatal("the original datagram was lost after a failed write")
	}
	if st := tt.Stats(); st.Sent != 0 || st.Sockets != 0 {
		t.Fatalf("failed relay write counted or its socket leaked: %+v", st)
	}

	handle.recvCh <- pkt
	// The following unrelated packet arrives on sendCh after the retry was processed.
	foreign, _ := buildInboundUDPPacket(src, netip.MustParseAddrPort("8.8.4.4:40000"), []byte("other UDP"))
	handle.recvCh <- capture.Packet{Data: foreign, Dir: core.DirectionOutbound}
	select {
	case out := <-handle.sendCh:
		if !bytes.Equal(out.Data, foreign) {
			t.Fatal("the successfully relayed datagram was also sent directly")
		}
	case <-time.After(time.Second):
		t.Fatal("unrelated UDP stopped after the write failure")
	}
	if st := tt.Stats(); st.Sent != 1 || st.Sockets != 1 {
		t.Fatalf("the next datagram did not use a fresh relay socket: %+v", st)
	}
}

type checkedFakeUDPTunnel struct {
	fakeUDPTunnel
	endpoint string
	probeErr error
	probes   atomic.Int32
}

func (f *checkedFakeUDPTunnel) Endpoint() string { return f.endpoint }

func (f *checkedFakeUDPTunnel) ProbeUDP(ctx context.Context) error {
	f.probes.Add(1)
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= telegramCallProbeWait {
		return errors.New("startup probe did not receive the normal readiness budget")
	}
	return f.probeErr
}

func TestTelegramCallTunnelRechecksUDPBeforeCapture(t *testing.T) {
	probeTimeout := errors.New("no UDP response after selecting peer")
	for _, tc := range []struct {
		name      string
		firstErr  error
		secondErr error
		wantOpens int32
		active    bool
	}{
		{name: "first peer still responds", wantOpens: 1, active: true},
		{name: "first peer stopped responding", firstErr: probeTimeout, wantOpens: 2, active: true},
		{name: "both peers stopped responding", firstErr: probeTimeout, secondErr: probeTimeout, wantOpens: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := &checkedFakeUDPTunnel{endpoint: "192.0.2.1:2408", probeErr: tc.firstErr}
			second := &checkedFakeUDPTunnel{endpoint: "192.0.2.2:2408", probeErr: tc.secondErr}
			handle := newFakeTunnelHandle()
			tt := newTelegramCallTunnel(t.Context(), fakeTunnelOwner{}, nil)
			tt.supported = true
			var opens, captures atomic.Int32
			var firstClosedBeforeRetry atomic.Bool
			tt.openTunnel = func(ctx context.Context, deprioritized map[string]struct{}) (tgUDPTunnel, error) {
				switch opens.Add(1) {
				case 1:
					return first, nil
				case 2:
					_, deprioritizeFirst := deprioritized[first.Endpoint()]
					_, retryBounded := ctx.Deadline()
					first.mu.Lock()
					firstClosedBeforeRetry.Store(first.closed && deprioritizeFirst && retryBounded)
					first.mu.Unlock()
					return second, nil
				default:
					return nil, errors.New("too many attempts")
				}
			}
			tt.openHandle = func(string) (tgTunnelConn, error) {
				captures.Add(1)
				if tc.firstErr == nil && first.probes.Load() != 1 || tc.firstErr != nil && second.probes.Load() != 1 {
					return nil, errors.New("capture started before the chosen peer was verified")
				}
				return handle, nil
			}
			defer tt.Close()
			tt.NotifyUnanswered()
			deadline := time.Now().Add(time.Second)
			for tt.Stats().Opening && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			st := tt.Stats()
			if st.Opening || st.Active != tc.active || opens.Load() != tc.wantOpens || first.probes.Load() != 1 {
				t.Fatalf("unexpected relay startup: stats=%+v opens=%d, first probes=%d", st, opens.Load(), first.probes.Load())
			}
			if tc.firstErr != nil && (!firstClosedBeforeRetry.Load() || second.probes.Load() != 1) {
				t.Fatal("the first peer was not closed and deprioritized before a bounded retry")
			}
			if !tc.active {
				second.mu.Lock()
				secondClosed := second.closed
				second.mu.Unlock()
				if !secondClosed || captures.Load() != 0 || st.Failures != 1 {
					t.Fatalf("an unhealthy relay intercepted packets or leaked: %+v", st)
				}
			}
		})
	}
}

func TestTelegramCallTunnelRetryBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	now := time.Now()
	tt := newTelegramCallTunnel(ctx, nil, nil)
	tt.supported = true
	tt.now = func() time.Time { return now }
	tt.openTunnel = func(context.Context, map[string]struct{}) (tgUDPTunnel, error) {
		calls.Add(1)
		return nil, errors.New("warp blocked")
	}
	defer tt.Close()

	tt.NotifyUnanswered()
	deadline := time.Now().Add(time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// Wait for opening flag to clear.
	for tt.Stats().Opening && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// Second call within retry window must be suppressed.
	tt.NotifyUnanswered()
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("expected backoff to suppress second open attempt, got %d calls", calls.Load())
	}
}

func TestTelegramCallTunnelReleasesDeadTunnel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fakeTn := &fakeUDPTunnel{}
	fakeHandle := newFakeTunnelHandle()

	var nowMu sync.Mutex
	curNow := time.Now()
	tt := newTelegramCallTunnel(ctx, fakeTunnelOwner{}, nil)
	tt.supported = true
	tt.now = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curNow
	}
	var (
		openCalls atomic.Int32
		lastExcl  map[string]struct{}
		exclMu    sync.Mutex
	)
	tt.openTunnel = func(_ context.Context, exclude map[string]struct{}) (tgUDPTunnel, error) {
		openCalls.Add(1)
		exclMu.Lock()
		lastExcl = exclude
		exclMu.Unlock()
		return fakeTn, nil
	}
	tt.openHandle = func(string) (tgTunnelConn, error) { return fakeHandle, nil }
	defer tt.Close()

	tt.NotifyUnanswered()
	deadline := time.Now().Add(2 * time.Second)
	for !tt.Stats().Active && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !tt.Stats().Active {
		t.Fatal("expected tunnel to become active")
	}

	tgRaw, _ := buildInboundUDPPacket(
		netip.MustParseAddrPort("192.168.1.50:54321"),
		netip.MustParseAddrPort("91.108.16.100:599"),
		[]byte("stun-req"),
	)
	fakeHandle.recvCh <- capture.Packet{Data: tgRaw, Dir: core.DirectionOutbound}
	for tt.Stats().Sent < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// Advance clock past dead window and send remaining unanswered packets.
	nowMu.Lock()
	curNow = curNow.Add(telegramCallWARPDeadWindow + time.Second)
	nowMu.Unlock()
	for i := 1; i < telegramCallWARPDeadPackets; i++ {
		fakeHandle.recvCh <- capture.Packet{Data: tgRaw, Dir: core.DirectionOutbound}
	}

	deadline = time.Now().Add(2 * time.Second)
	for tt.Stats().Active && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if tt.Stats().Active {
		t.Fatal("expected dead WARP tunnel to release capture and become inactive")
	}

	// After the short dead-tunnel retry delay, NotifyUnanswered should reopen
	// WARP and exclude the dead peer from the candidate list.
	nowMu.Lock()
	curNow = curNow.Add(telegramCallWARPDeadRetry + time.Second)
	nowMu.Unlock()
	fakeHandle = newFakeTunnelHandle()
	tt.NotifyUnanswered()
	deadline = time.Now().Add(2 * time.Second)
	for openCalls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if openCalls.Load() < 2 {
		t.Fatalf("expected fast failover reopen after %v, got %d opens", telegramCallWARPDeadRetry, openCalls.Load())
	}
	exclMu.Lock()
	_, excluded := lastExcl[fakeTn.Endpoint()]
	exclMu.Unlock()
	if !excluded {
		t.Fatalf("expected dead peer %q to be excluded on failover, got %v", fakeTn.Endpoint(), lastExcl)
	}
}

type relayHealthFakeTunnel struct {
	fakeUDPTunnel
	probe func(context.Context) error
}

func (f *relayHealthFakeTunnel) ProbeUDP(ctx context.Context) error { return f.probe(ctx) }

type telegramRelayLogWriter func([]byte) (int, error)

func (f telegramRelayLogWriter) Write(p []byte) (int, error) { return f(p) }

func TestTelegramCallTunnelObservesStallsWithoutAnotherPacket(t *testing.T) {
	for _, tc := range []struct {
		name       string
		initialRx  bool
		lateRx     bool
		sent       int
		controlErr error
	}{
		{name: "early failure", sent: telegramCallWARPDeadPackets, controlErr: errors.New("no control reply")},
		{name: "short attempt still releases dead capture", sent: 2, controlErr: errors.New("no control reply")},
		{name: "healthy control keeps normal window", sent: telegramCallWARPDeadPackets},
		{name: "reply while a failed probe was pending", lateRx: true, sent: telegramCallWARPDeadPackets, controlErr: errors.New("no control reply")},
		{name: "previously responsive path gets grace", initialRx: true, sent: telegramCallWARPDeadPackets},
		{name: "previously responsive path with failed control", initialRx: true, sent: telegramCallWARPDeadPackets, controlErr: errors.New("no control reply")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var clock atomic.Int64
			start := time.Now().UnixNano()
			clock.Store(start)
			probeStarted, completeProbe := make(chan struct{}), make(chan struct{})
			var probes atomic.Int32
			var fullEarlyBudget atomic.Bool
			fakeTn := &relayHealthFakeTunnel{probe: func(ctx context.Context) error {
				switch probes.Add(1) {
				case 1:
					return nil
				case 2:
					deadline, ok := ctx.Deadline()
					fullEarlyBudget.Store(ok && time.Until(deadline) > telegramCallProbeWait)
					close(probeStarted)
					select {
					case <-completeProbe:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				return tc.controlErr
			}}
			handle := newFakeTunnelHandle()
			gotGrace := make(chan struct{}, 1)
			logger := slog.New(slog.NewTextHandler(telegramRelayLogWriter(func(p []byte) (int, error) {
				if bytes.Contains(p, []byte("резерв WARP отвечает, ждём ответа звонка")) {
					gotGrace <- struct{}{}
				}
				return len(p), nil
			}), nil))
			tt := newTelegramCallTunnel(t.Context(), fakeTunnelOwner{}, logger)
			tt.supported = true
			tt.watchEvery = time.Millisecond
			tt.now = func() time.Time { return time.Unix(0, clock.Load()) }
			tt.openTunnel = func(context.Context, map[string]struct{}) (tgUDPTunnel, error) { return fakeTn, nil }
			tt.openHandle = func(string) (tgTunnelConn, error) { return handle, nil }
			defer tt.Close()

			waitFor := func(ready func() bool, message string) {
				t.Helper()
				deadline := time.Now().Add(time.Second)
				for !ready() {
					if time.Now().After(deadline) {
						t.Fatal(message)
					}
					time.Sleep(time.Millisecond)
				}
			}
			src := netip.MustParseAddrPort("192.168.1.50:54321")
			dst := netip.MustParseAddrPort("91.108.16.100:599")
			raw, _ := buildInboundUDPPacket(src, dst, []byte("call request"))
			pkt := capture.Packet{Data: raw, Dir: core.DirectionOutbound}
			reply := func() {
				fakeTn.mu.Lock()
				pc := fakeTn.conns[0]
				fakeTn.mu.Unlock()
				pc.inCh <- struct {
					data []byte
					addr net.Addr
				}{[]byte("call response"), net.UDPAddrFromAddrPort(dst)}
				select {
				case <-handle.sendCh:
				case <-time.After(time.Second):
					t.Fatal("expected a relayed reply")
				}
				waitFor(func() bool { return tt.Stats().Received == 1 }, "reply not recorded")
			}
			tt.NotifyUnanswered()
			var prior int64
			if tc.initialRx {
				handle.recvCh <- pkt
				waitFor(func() bool { return tt.Stats().Sent == 1 }, "initial send not recorded")
				reply()
				prior = 1
			}
			for range tc.sent {
				handle.recvCh <- pkt
			}
			waitFor(func() bool { return tt.Stats().Sent == prior+int64(tc.sent) }, "burst not recorded")
			// No more Telegram packets are sent while the watchdog runs.
			if !tc.initialRx && tc.sent >= telegramCallWARPDeadPackets {
				clock.Add(int64(telegramCallWARPEarlyProbeAfter + 100*time.Millisecond))
			} else {
				clock.Add(int64(telegramCallWARPDeadWindow + time.Second))
			}
			select {
			case <-probeStarted:
			case <-time.After(time.Second):
				t.Fatal("no runtime probe without further outgoing call packets")
			}
			if !tc.initialRx && !fullEarlyBudget.Load() {
				t.Fatal("first-reply probe used the shorter diagnostic timeout")
			}
			foreign, _ := buildInboundUDPPacket(src, netip.MustParseAddrPort("8.8.4.4:40000"), []byte("other UDP"))
			handle.recvCh <- capture.Packet{Data: foreign, Dir: core.DirectionOutbound}
			select {
			case out := <-handle.sendCh:
				if !bytes.Equal(out.Data, foreign) {
					t.Fatal("foreign UDP was changed")
				}
			case <-time.After(time.Second):
				t.Fatal("UDP stopped flowing during the health check")
			}
			if tc.lateRx {
				reply()
			}
			close(completeProbe)
			if tc.lateRx {
				select {
				case <-handle.closed:
					t.Fatal("a failed but obsolete probe closed a relay with a fresh reply")
				case <-time.After(25 * time.Millisecond):
				}
				return
			}
			if tc.controlErr == nil && tc.initialRx {
				select {
				case <-gotGrace:
				case <-time.After(time.Second):
					t.Fatal("expected one grace period for an earlier reply")
				}
				if st := tt.Stats(); !st.Active || st.Sockets != 1 {
					t.Fatalf("healthy relay discarded its socket: %+v", st)
				}
				for range telegramCallWARPDeadPackets {
					handle.recvCh <- pkt
				}
				waitFor(func() bool { return tt.Stats().Sent == prior+int64(tc.sent+telegramCallWARPDeadPackets) }, "new burst not recorded")
				clock.Add(int64(telegramCallWARPDeadWindow + time.Second))
			} else if tc.controlErr == nil {
				select {
				case <-handle.closed:
					t.Fatal("healthy control caused early failover")
				case <-time.After(25 * time.Millisecond):
				}
				clock.Store(start + int64(telegramCallWARPDeadWindow+time.Second))
			}
			waitFor(func() bool { return !tt.Stats().Active }, "relay not retired without further packets")
		})
	}
}

func TestWarpMultiHostEndpointsExclude(t *testing.T) {
	all := warpMultiHostEndpoints("162.159.195.1:2408", nil)
	if len(all) == 0 || all[0] != "162.159.195.1:2408" {
		t.Fatalf("expected saved endpoint first, got %v", all[:min(3, len(all))])
	}
	reordered := warpMultiHostEndpoints("162.159.195.1:2408", map[string]struct{}{
		"162.159.195.1:2408": {},
	})
	if len(reordered) != len(all) {
		t.Fatalf("expected deprioritized list to keep all %d endpoints, got %d", len(all), len(reordered))
	}
	if reordered[0] == "162.159.195.1:2408" {
		t.Fatal("deprioritized endpoint should not stay first")
	}
	if reordered[len(reordered)-1] != "162.159.195.1:2408" {
		t.Fatalf("expected deprioritized endpoint last as fallback, got %q", reordered[len(reordered)-1])
	}
}

func TestTelegramCallTunnelReleasesCaptureWhenCallEnds(t *testing.T) {
	t.Run("graceful receive shutdown", func(t *testing.T) {
		testTelegramCallTunnelReleasesCaptureWhenCallEnds(t, nil)
	})
	t.Run("failed receive shutdown", func(t *testing.T) {
		testTelegramCallTunnelReleasesCaptureWhenCallEnds(t, errors.New("receive shutdown failed"))
	})
}

func testTelegramCallTunnelReleasesCaptureWhenCallEnds(t *testing.T, shutdownErr error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fakeTn := &fakeUDPTunnel{}
	var handleMu sync.Mutex
	fakeHandle := newFakeTunnelHandle()
	fakeHandle.shutdownErr = shutdownErr

	var nowMu sync.Mutex
	curNow := time.Now()
	tt := newTelegramCallTunnel(ctx, fakeTunnelOwner{}, nil)
	tt.supported = true
	tt.watchEvery = 5 * time.Millisecond
	tt.now = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curNow
	}
	var openCalls atomic.Int32
	tt.openTunnel = func(context.Context, map[string]struct{}) (tgUDPTunnel, error) {
		openCalls.Add(1)
		return fakeTn, nil
	}
	tt.openHandle = func(string) (tgTunnelConn, error) {
		handleMu.Lock()
		defer handleMu.Unlock()
		return fakeHandle, nil
	}
	defer tt.Close()

	waitFor := func(cond func() bool, msg string) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for !cond() && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if !cond() {
			t.Fatal(msg)
		}
	}

	tt.NotifyUnanswered()
	waitFor(func() bool { return tt.Stats().Active }, "expected tunnel to become active")

	tgRaw, _ := buildInboundUDPPacket(
		netip.MustParseAddrPort("192.168.1.50:54321"),
		netip.MustParseAddrPort("91.108.16.100:599"),
		[]byte("stun-req"),
	)
	fakeHandle.recvCh <- capture.Packet{Data: tgRaw, Dir: core.DirectionOutbound}
	waitFor(func() bool { return tt.Stats().Sent == 1 }, "expected call packet to be relayed")

	nowMu.Lock()
	curNow = curNow.Add(telegramCallWARPIdle / 2)
	nowMu.Unlock()
	time.Sleep(30 * time.Millisecond)
	if !tt.Stats().Active {
		t.Fatal("tunnel released before the call went idle")
	}

	nowMu.Lock()
	curNow = curNow.Add(telegramCallWARPIdle)
	nowMu.Unlock()
	waitFor(func() bool { return !tt.Stats().Active }, "expected idle tunnel to release the UDP capture")
	fakeTn.mu.Lock()
	closed := fakeTn.closed
	fakeTn.mu.Unlock()
	if !closed {
		t.Fatal("expected idle WARP tunnel to be closed")
	}

	handleMu.Lock()
	fakeHandle = newFakeTunnelHandle()
	handleMu.Unlock()
	tt.NotifyUnanswered()
	waitFor(func() bool { return openCalls.Load() == 2 && tt.Stats().Active }, "expected the next call to reopen WARP without a retry delay")
}

func TestTelegramCallInternetTargetSkipsOverlayNetworks(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"91.108.9.89", true},
		{"104.28.232.200", true},
		{"149.154.167.50", true},
		{"26.235.135.76", false}, // Radmin VPN
		{"25.12.34.56", false},   // Hamachi
		{"100.64.1.2", false},    // CGNAT / Tailscale
		{"198.18.0.10", false},   // fake-ip TUN
		{"192.168.1.5", false},
		{"10.0.0.1", false},
		{"127.0.0.1", false},
		{"2001:67c:4e8::1", true},
		{"fd00::1", false},
	} {
		if got := isTelegramCallInternetTarget(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("isTelegramCallInternetTarget(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestTelegramTunnelPacketLeavesOverlayPeersDirect(t *testing.T) {
	src := netip.MustParseAddrPort("192.168.1.50:54321")
	owner := fakeTunnelOwner{ports: map[string]bool{src.String(): true}}
	for _, tc := range []struct {
		dst  string
		want bool
	}{
		{"26.235.135.76:57888", false},
		{"100.80.1.1:41641", false},
		{"104.28.232.200:14358", true},
	} {
		raw, ok := buildInboundUDPPacket(src, netip.MustParseAddrPort(tc.dst), []byte("stun-req"))
		if !ok {
			t.Fatal("build packet")
		}
		d, err := packet.Dissect(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, _, _, got := isTelegramTunnelPacket(d, raw, owner); got != tc.want {
			t.Errorf("relay %s via WARP = %v, want %v", tc.dst, got, tc.want)
		}
	}
}

func TestTelegramCallTunnelRotatesObfuscationWhenTunnelDiesAfterHandshake(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	var probes atomic.Int32
	fakeTn := &relayHealthFakeTunnel{probe: func(context.Context) error {
		// The probe right after the handshake passes; the runtime one does not,
		// as when DPI cuts the WireGuard flow a second after it starts.
		if probes.Add(1) == 1 {
			return nil
		}
		return errors.New("no control reply")
	}}
	handle := newFakeTunnelHandle()
	rotated := make(chan struct{}, 4)
	logger := slog.New(slog.NewTextHandler(telegramRelayLogWriter(func(p []byte) (int, error) {
		if bytes.Contains(p, []byte("смена маскировки WARP")) {
			rotated <- struct{}{}
		}
		return len(p), nil
	}), nil))
	tt := newTelegramCallTunnel(t.Context(), fakeTunnelOwner{}, logger)
	tt.stateDir = t.TempDir()
	tt.profile, tt.profileSaved = 0, ""
	tt.supported = true
	tt.watchEvery = time.Millisecond
	tt.now = func() time.Time { return time.Unix(0, clock.Load()) }
	tt.openTunnel = func(context.Context, map[string]struct{}) (tgUDPTunnel, error) { return fakeTn, nil }
	tt.openHandle = func(string) (tgTunnelConn, error) { return handle, nil }
	defer tt.Close()

	first := tt.currentObfuscation().Name
	tt.NotifyUnanswered()
	deadline := time.Now().Add(time.Second)
	for !tt.Stats().Active && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !tt.Stats().Active {
		t.Fatal("expected tunnel to become active")
	}
	raw, _ := buildInboundUDPPacket(netip.MustParseAddrPort("192.168.1.50:54321"), netip.MustParseAddrPort("91.108.16.100:599"), []byte("call request"))
	for range telegramCallWARPDeadPackets {
		handle.recvCh <- capture.Packet{Data: raw, Dir: core.DirectionOutbound}
	}
	for tt.Stats().Sent < telegramCallWARPDeadPackets && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	clock.Add(int64(telegramCallWARPEarlyProbeAfter + 100*time.Millisecond))
	select {
	case <-rotated:
	case <-time.After(2 * time.Second):
		t.Fatal("dead tunnel did not switch the WireGuard obfuscation")
	}
	if got := tt.currentObfuscation().Name; got == first {
		t.Fatalf("obfuscation stayed %q after a tunnel died", got)
	}

	// A reply through the tunnel makes the current profile the remembered one.
	tt.markProfileGood()
	if got := loadTelegramWARPProfile(tt.stateDir); got != tt.currentObfuscation().Name {
		t.Fatalf("saved profile %q, want %q", got, tt.currentObfuscation().Name)
	}
	tt.mu.Lock()
	fails := tt.profileFails
	tt.mu.Unlock()
	if fails != 0 {
		t.Fatalf("profileFails = %d after success, want 0", fails)
	}
}

func TestTelegramCallTunnelProfileRotationCycles(t *testing.T) {
	tt := newTelegramCallTunnel(t.Context(), nil, nil)
	tt.profile, tt.profileFails = 0, 0
	n := len(tunnel.WARPObfuscationProfiles)
	tt.mu.Lock()
	defer tt.mu.Unlock()
	for i := 1; i < n; i++ {
		if !tt.rotateProfileLocked("test") {
			t.Fatalf("rotation %d reported no untried profiles", i)
		}
	}
	if tt.rotateProfileLocked("test") {
		t.Fatal("full cycle must report that every profile was tried")
	}
	if tt.profile != 0 {
		t.Fatalf("rotation must wrap around, got profile %d", tt.profile)
	}
}
