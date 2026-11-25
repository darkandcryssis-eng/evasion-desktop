package main

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/packet"
)

const (
	telegramCallTunnelFilter   = "outbound and udp and udp.DstPort != 443 and udp.DstPort != 53 and not loopback and not impostor"
	telegramCallTunnelPriority = 150
	telegramCallWARPTrigger     = 4
	telegramCallWARPRetry       = 3 * time.Minute
	telegramCallWARPPortWait    = 1400 * time.Millisecond
	telegramCallWARPBatch       = 10
	telegramCallWARPJunk        = 4
	telegramCallWARPStateFile   = "warp-telegram.json"
	telegramCallWARPDeadPackets = 12
	telegramCallWARPDeadWindow  = 10 * time.Second
	telegramCallSocketIdle      = 90 * time.Second
	telegramCallMaxSockets      = 64
)

type tgUDPTunnel interface {
	ListenUDP(ipv6 bool) (net.PacketConn, error)
	Endpoint() string
	Close() error
}

type tgTunnelConn interface {
	Recv() (capture.Packet, error)
	Send(capture.Packet) error
	ShutdownReceive() error
	Close() error
}

type tgCallTunnelStats struct {
	Active   bool
	Opening  bool
	Peer     string
	Sent     int64
	Received int64
	Sockets  int
}

type tgLocalSocketKey struct {
	ip   netip.Addr
	port uint16
}

type tgSocketRelay struct {
	key      tgLocalSocketKey
	pc       net.PacketConn
	mu       sync.Mutex
	reinject any
	lastUsed time.Time
}

// telegramCallTunnel transparently relays Telegram call UDP packets (STUN,
// TURN, DTLS, and SRTP) through an in-process Cloudflare WARP tunnel when
// local UDP DPI desync receives zero replies (ISP IP/UDP-level block).
type telegramCallTunnel struct {
	supported  bool
	owner      telegramUDPOwner
	logger     *slog.Logger
	now        func() time.Time
	openTunnel func(context.Context) (tgUDPTunnel, error)
	openHandle func() (tgTunnelConn, error)

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	closed  bool
	opening bool
	active  bool
	retryAt time.Time
	peer    string
	tn      tgUDPTunnel
	handle  tgTunnelConn
	sockets map[tgLocalSocketKey]*tgSocketRelay

	sendMu sync.Mutex
	wg     sync.WaitGroup

	sent         atomic.Int64
	received     atomic.Int64
	unansweredTx atomic.Int64
}

func newTelegramCallTunnel(parent context.Context, owner telegramUDPOwner, logger *slog.Logger) *telegramCallTunnel {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(parent)
	return &telegramCallTunnel{
		supported: telegramCallTunnelSupported,
		owner:     owner,
		logger:    logger,
		now:       time.Now,
		openTunnel: func(c context.Context) (tgUDPTunnel, error) {
			return openWARPTunnelFile(c, defaultStateDir, telegramCallWARPStateFile, telegramCallWARPPortWait, telegramCallWARPBatch, telegramCallWARPJunk, true, logger)
		},
		openHandle: openTelegramCallTunnelHandle,
		ctx:        ctx,
		cancel:     cancel,
		sockets:    make(map[tgLocalSocketKey]*tgSocketRelay),
	}
}

// NotifyUnanswered starts the fallback WARP UDP relay once Telegram call
// signaling packets go unanswered locally. Safe to call repeatedly.
func (t *telegramCallTunnel) NotifyUnanswered() {
	if !t.supported {
		return
	}
	t.mu.Lock()
	if t.closed || t.active || t.opening || t.now().Before(t.retryAt) {
		t.mu.Unlock()
		return
	}
	t.opening = true
	t.wg.Add(1)
	t.mu.Unlock()

	go t.activate()
}

func (t *telegramCallTunnel) activate() {
	defer t.wg.Done()

	t.logger.Info("звонок Telegram: запуск резервного UDP-туннеля WARP")
	tn, err := t.openTunnel(t.ctx)
	if err != nil {
		t.mu.Lock()
		t.opening = false
		if !t.closed {
			t.retryAt = t.now().Add(telegramCallWARPRetry)
		}
		closed := t.closed
		t.mu.Unlock()
		if !closed && t.ctx.Err() == nil {
			t.logger.Warn("звонок Telegram: резервный UDP-туннель WARP не поднялся", "err", err, "повтор_через", telegramCallWARPRetry.String())
		}
		return
	}

	t.mu.Lock()
	if t.closed || t.ctx.Err() != nil {
		t.opening = false
		t.mu.Unlock()
		_ = tn.Close()
		return
	}
	t.mu.Unlock()

	handle, err := t.openHandle()
	if err != nil {
		_ = tn.Close()
		t.mu.Lock()
		t.opening = false
		if !t.closed {
			t.retryAt = t.now().Add(telegramCallWARPRetry)
		}
		closed := t.closed
		t.mu.Unlock()
		if !closed && t.ctx.Err() == nil {
			t.logger.Warn("звонок Telegram: резервный UDP-туннель WARP не поднялся", "err", err)
		}
		return
	}

	t.mu.Lock()
	if t.closed || t.ctx.Err() != nil {
		t.opening = false
		t.mu.Unlock()
		_ = handle.Close()
		_ = tn.Close()
		return
	}
	t.tn = tn
	t.handle = handle
	t.peer = tn.Endpoint()
	t.active = true
	t.opening = false
	t.wg.Add(1)
	t.mu.Unlock()

	t.logger.Info("звонок Telegram: резервный UDP-туннель WARP активен", "пир", tn.Endpoint())
	go t.serve(handle, tn)
}

func (t *telegramCallTunnel) serve(handle tgTunnelConn, tn tgUDPTunnel) {
	defer t.wg.Done()
	defer func() {
		t.closeSockets()
		_ = handle.Close()
		_ = tn.Close()
		t.mu.Lock()
		if t.handle == handle {
			t.handle = nil
		}
		if t.tn == tn {
			t.tn = nil
		}
		t.active = false
		t.mu.Unlock()
	}()

	t.unansweredTx.Store(0)
	var stalledSince time.Time

	for {
		pkt, err := handle.Recv()
		if err != nil {
			return
		}
		d, err := packet.Dissect(pkt.Data)
		if err != nil {
			t.sendPacket(handle, pkt)
			continue
		}
		srcIP, srcPort, dstIP, dstPort, payload, ok := isTelegramTunnelPacket(d, pkt.Data, t.owner)
		if !ok {
			t.sendPacket(handle, pkt)
			continue
		}
		relay := t.getOrCreateSocket(handle, tn, tgLocalSocketKey{ip: srcIP, port: srcPort}, pkt.Reinject)
		if relay == nil {
			t.sendPacket(handle, pkt)
			continue
		}
		dstAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(dstIP, dstPort))
		if _, err := relay.pc.WriteTo(payload, dstAddr); err != nil {
			t.removeSocket(relay)
			continue
		}
		t.sent.Add(1)
		n := t.unansweredTx.Add(1)
		if n == 1 {
			stalledSince = t.now()
		} else if n >= telegramCallWARPDeadPackets && !stalledSince.IsZero() && t.now().Sub(stalledSince) >= telegramCallWARPDeadWindow {
			t.mu.Lock()
			if !t.closed {
				t.retryAt = t.now().Add(telegramCallWARPRetry)
			}
			t.mu.Unlock()
			t.logger.Warn("звонок Telegram: резервный UDP-туннель WARP не отвечает, возврат на прямой путь",
				"отправлено_без_ответа", n)
			return
		}
	}
}

func (t *telegramCallTunnel) getOrCreateSocket(handle tgTunnelConn, tn tgUDPTunnel, key tgLocalSocketKey, reinject any) *tgSocketRelay {
	now := t.now()
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	if relay, ok := t.sockets[key]; ok {
		t.mu.Unlock()
		relay.mu.Lock()
		relay.reinject = reinject
		relay.lastUsed = now
		relay.mu.Unlock()
		return relay
	}
	var evicted *tgSocketRelay
	if len(t.sockets) >= telegramCallMaxSockets {
		var oldestKey tgLocalSocketKey
		var oldestTime time.Time
		for k, s := range t.sockets {
			s.mu.Lock()
			lu := s.lastUsed
			s.mu.Unlock()
			if evicted == nil || lu.Before(oldestTime) {
				oldestKey = k
				oldestTime = lu
				evicted = s
			}
		}
		if evicted != nil {
			delete(t.sockets, oldestKey)
		}
	}
	t.mu.Unlock()

	if evicted != nil {
		_ = evicted.pc.Close()
	}

	pc, err := tn.ListenUDP(key.ip.Is6())
	if err != nil {
		return nil
	}

	relay := &tgSocketRelay{
		key:      key,
		pc:       pc,
		reinject: reinject,
		lastUsed: now,
	}

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = pc.Close()
		return nil
	}
	if existing, ok := t.sockets[key]; ok {
		t.mu.Unlock()
		_ = pc.Close()
		existing.mu.Lock()
		existing.reinject = reinject
		existing.lastUsed = now
		existing.mu.Unlock()
		return existing
	}
	t.sockets[key] = relay
	t.wg.Add(1)
	t.mu.Unlock()

	go t.readSocket(handle, relay)
	return relay
}

func (t *telegramCallTunnel) readSocket(handle tgTunnelConn, relay *tgSocketRelay) {
	defer t.wg.Done()
	defer t.removeSocket(relay)

	buf := make([]byte, 65535)
	dst := netip.AddrPortFrom(relay.key.ip, relay.key.port)
	for {
		_ = relay.pc.SetReadDeadline(time.Now().Add(telegramCallSocketIdle))
		n, from, err := relay.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		src, ok := udpAddrToAddrPort(from)
		if !ok {
			continue
		}
		raw, ok := buildInboundUDPPacket(src, dst, buf[:n])
		if !ok {
			continue
		}
		relay.mu.Lock()
		reinject := relay.reinject
		relay.lastUsed = t.now()
		relay.mu.Unlock()

		t.sendPacket(handle, capture.Packet{
			Data:     raw,
			Dir:      core.DirectionInbound,
			Reinject: makeInboundReinject(reinject),
		})
		t.unansweredTx.Store(0)
		t.received.Add(1)
	}
}

func (t *telegramCallTunnel) removeSocket(relay *tgSocketRelay) {
	t.mu.Lock()
	if cur, ok := t.sockets[relay.key]; ok && cur == relay {
		delete(t.sockets, relay.key)
	}
	t.mu.Unlock()
	_ = relay.pc.Close()
}

func (t *telegramCallTunnel) closeSockets() {
	t.mu.Lock()
	list := make([]*tgSocketRelay, 0, len(t.sockets))
	for k, s := range t.sockets {
		list = append(list, s)
		delete(t.sockets, k)
	}
	t.mu.Unlock()
	for _, s := range list {
		_ = s.pc.Close()
	}
}

func (t *telegramCallTunnel) sendPacket(handle tgTunnelConn, pkt capture.Packet) {
	t.sendMu.Lock()
	_ = handle.Send(pkt)
	t.sendMu.Unlock()
}

func (t *telegramCallTunnel) Stats() tgCallTunnelStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return tgCallTunnelStats{
		Active:   t.active,
		Opening:  t.opening,
		Peer:     t.peer,
		Sent:     t.sent.Load(),
		Received: t.received.Load(),
		Sockets:  len(t.sockets),
	}
}

func (t *telegramCallTunnel) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	handle := t.handle
	tn := t.tn
	t.mu.Unlock()

	t.cancel()
	if handle != nil {
		if handle.ShutdownReceive() != nil {
			_ = handle.Close()
		}
	}
	t.closeSockets()
	if tn != nil {
		_ = tn.Close()
	}
	t.wg.Wait()
}

func isTelegramTunnelPacket(d packet.Dissection, buf []byte, owner telegramUDPOwner) (netip.Addr, uint16, netip.Addr, uint16, []byte, bool) {
	if d.Protocol != packet.ProtoUDP || d.PayloadLen <= 0 || d.L4Off+8 > len(buf) {
		return netip.Addr{}, 0, netip.Addr{}, 0, nil, false
	}
	srcPort := binary.BigEndian.Uint16(buf[d.L4Off:])
	dstPort := binary.BigEndian.Uint16(buf[d.L4Off+2:])
	if srcPort == 0 || dstPort == 0 || dstPort == 443 || dstPort == 53 {
		return netip.Addr{}, 0, netip.Addr{}, 0, nil, false
	}
	srcIP := packetSrcIP(buf, d)
	if !srcIP.IsValid() {
		return netip.Addr{}, 0, netip.Addr{}, 0, nil, false
	}
	dstIP := packetDstIP(buf, d)
	if !dstIP.IsValid() {
		return netip.Addr{}, 0, netip.Addr{}, 0, nil, false
	}
	if !isGlobalRoutableUDP(dstIP) {
		return netip.Addr{}, 0, netip.Addr{}, 0, nil, false
	}
	if !isTelegramCallIP(dstIP) && (owner == nil || !owner.OwnsUDP(srcIP, srcPort)) {
		return netip.Addr{}, 0, netip.Addr{}, 0, nil, false
	}
	payload := buf[d.PayloadOff : d.PayloadOff+d.PayloadLen]
	return srcIP, srcPort, dstIP, dstPort, payload, true
}

func isGlobalRoutableUDP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	return !ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified()
}

func udpAddrToAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	u, ok := addr.(*net.UDPAddr)
	if !ok || u == nil {
		return netip.AddrPort{}, false
	}
	ap := u.AddrPort()
	if !ap.IsValid() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

func buildInboundUDPPacket(src, dst netip.AddrPort, payload []byte) ([]byte, bool) {
	if !src.IsValid() || !dst.IsValid() {
		return nil, false
	}
	srcIP := src.Addr().Unmap()
	dstIP := dst.Addr().Unmap()
	if srcIP.Is4() != dstIP.Is4() {
		return nil, false
	}
	udpLen := 8 + len(payload)
	if udpLen > 65535 {
		return nil, false
	}

	var raw []byte
	var udpOff int
	if srcIP.Is4() {
		totalLen := 20 + udpLen
		if totalLen > 65535 {
			return nil, false
		}
		raw = make([]byte, totalLen)
		raw[0] = 0x45
		binary.BigEndian.PutUint16(raw[2:4], uint16(totalLen))
		raw[8] = 64
		raw[9] = byte(packet.ProtoUDP)
		s4 := srcIP.As4()
		d4 := dstIP.As4()
		copy(raw[12:16], s4[:])
		copy(raw[16:20], d4[:])
		udpOff = 20
	} else {
		raw = make([]byte, 40+udpLen)
		raw[0] = 0x60
		binary.BigEndian.PutUint16(raw[4:6], uint16(udpLen))
		raw[6] = byte(packet.ProtoUDP)
		raw[7] = 64
		s16 := srcIP.As16()
		d16 := dstIP.As16()
		copy(raw[8:24], s16[:])
		copy(raw[24:40], d16[:])
		udpOff = 40
	}

	binary.BigEndian.PutUint16(raw[udpOff:udpOff+2], src.Port())
	binary.BigEndian.PutUint16(raw[udpOff+2:udpOff+4], dst.Port())
	binary.BigEndian.PutUint16(raw[udpOff+4:udpOff+6], uint16(udpLen))
	copy(raw[udpOff+8:], payload)

	d, err := packet.Dissect(raw)
	if err != nil || !d.RecomputeChecksums(raw) {
		return nil, false
	}
	return raw, true
}
