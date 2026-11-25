package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/packet"
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
	mu      sync.Mutex
	closed  bool
	written []struct {
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

func (f *fakePacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4(172, 16, 0, 2), Port: 40000} }
func (f *fakePacketConn) SetDeadline(time.Time) error        { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error    { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error   { return nil }

type fakeUDPTunnel struct {
	mu     sync.Mutex
	conns  []*fakePacketConn
	closed bool
}

func (f *fakeUDPTunnel) ListenUDP(bool) (net.PacketConn, error) {
	pc := newFakePacketConn()
	f.mu.Lock()
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
	recvCh chan capture.Packet
	sendCh chan capture.Packet
	once   sync.Once
}

func newFakeTunnelHandle() *fakeTunnelHandle {
	return &fakeTunnelHandle{
		recvCh: make(chan capture.Packet, 16),
		sendCh: make(chan capture.Packet, 16),
	}
}

func (h *fakeTunnelHandle) Recv() (capture.Packet, error) {
	pkt, ok := <-h.recvCh
	if !ok {
		return capture.Packet{}, errors.New("closed")
	}
	return pkt, nil
}

func (h *fakeTunnelHandle) Send(pkt capture.Packet) error {
	h.sendCh <- pkt
	return nil
}

func (h *fakeTunnelHandle) ShutdownReceive() error {
	h.once.Do(func() { close(h.recvCh) })
	return nil
}

func (h *fakeTunnelHandle) Close() error {
	h.once.Do(func() { close(h.recvCh) })
	return nil
}

func TestTelegramCallTunnelRelaysAndPassesThrough(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fakeTn := &fakeUDPTunnel{}
	fakeHandle := newFakeTunnelHandle()

	tt := newTelegramCallTunnel(ctx, fakeTunnelOwner{}, nil)
	tt.supported = true
	tt.openTunnel = func(context.Context) (tgUDPTunnel, error) { return fakeTn, nil }
	tt.openHandle = func() (tgTunnelConn, error) { return fakeHandle, nil }
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

func TestTelegramCallTunnelRetryBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	now := time.Now()
	tt := newTelegramCallTunnel(ctx, nil, nil)
	tt.supported = true
	tt.now = func() time.Time { return now }
	tt.openTunnel = func(context.Context) (tgUDPTunnel, error) {
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
	tt.openTunnel = func(context.Context) (tgUDPTunnel, error) { return fakeTn, nil }
	tt.openHandle = func() (tgTunnelConn, error) { return fakeHandle, nil }
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
}
