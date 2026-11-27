package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/packet"
)

const (
	telegramCallTunnelFilter         = "outbound and udp and udp.DstPort != 443 and udp.DstPort != 53 and not loopback and not impostor"
	telegramCallTunnelPriority       = 150
	telegramCallWARPTrigger          = 4
	telegramCallWARPRetry            = 30 * time.Second
	telegramCallWARPStartupRetryWait = 3 * time.Second
	telegramCallWARPDeadRetry        = 1 * time.Second
	telegramCallWARPBadPeerTTL       = 10 * time.Minute
	telegramCallWARPPortWait         = 1800 * time.Millisecond
	telegramCallWARPBatch            = 10
	telegramCallWARPJunk             = 4
	telegramCallWARPStateFile        = "warp-telegram.json"
	telegramCallWARPDeadPackets      = 8
	telegramCallWARPDeadWindow       = 5 * time.Second
	telegramCallWARPEarlyProbeAfter  = 1 * time.Second
	telegramCallSocketIdle           = 90 * time.Second
	// telegramCallWARPIdle releases the capture of all outbound UDP once no call
	// packet has been relayed for this long, so games and Discord voice stop
	// passing through userspace after the call ends.
	telegramCallWARPIdle       = 2 * time.Minute
	telegramCallWARPWatchEvery = 100 * time.Millisecond
	telegramCallMaxSockets     = 64
	telegramCallReportEvery    = 5 * time.Second
	telegramCallProbeWait      = 900 * time.Millisecond
	telegramCallExitInfoWait   = 6 * time.Second
	telegramCallMaxTargets     = 12
)

// Необязательные возможности туннеля для диагностики звонка.
type tgTunnelProber interface {
	ProbeUDP(context.Context) error
}

type tgTunnelExitInfo interface {
	ExitInfo(context.Context) (string, error)
}

type tgRelayProgress struct {
	since   time.Time
	pending int64
	replies int64
}

type tgRelayHealth struct {
	mu       sync.Mutex
	progress tgRelayProgress
	retired  atomic.Bool
}

func (h *tgRelayHealth) sent(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.progress.pending == 0 {
		h.progress.since = now
	}
	h.progress.pending++
}

func (h *tgRelayHealth) received() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.progress = tgRelayProgress{replies: h.progress.replies + 1}
}

func (h *tgRelayHealth) snapshot() tgRelayProgress {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.progress
}

func (h *tgRelayHealth) finishGap(p tgRelayProgress, keep bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.progress.replies != p.replies || h.progress.since != p.since {
		return false
	}
	if keep {
		h.progress = tgRelayProgress{replies: p.replies}
	} else {
		h.retired.Store(true)
	}
	return true
}

type tgTargetCount struct {
	tx, rx int64
}

// tgTargetStats считает пакеты звонка по адресам назначения: по ним видно,
// молчат все реле Telegram или только часть.
type tgTargetStats struct {
	mu    sync.Mutex
	order []netip.AddrPort
	byDst map[netip.AddrPort]*tgTargetCount
}

func (s *tgTargetStats) add(dst netip.AddrPort, tx, rx int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.byDst[dst]
	if c == nil {
		if len(s.order) >= telegramCallMaxTargets {
			return
		}
		if s.byDst == nil {
			s.byDst = make(map[netip.AddrPort]*tgTargetCount)
		}
		c = &tgTargetCount{}
		s.byDst[dst] = c
		s.order = append(s.order, dst)
	}
	c.tx += tx
	c.rx += rx
}

func (s *tgTargetStats) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for i, dst := range s.order {
		if i > 0 {
			b.WriteByte(' ')
		}
		c := s.byDst[dst]
		fmt.Fprintf(&b, "%s:%d/%d", dst, c.tx, c.rx)
	}
	return b.String()
}

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
	Attempts int
	Failures int
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
	openTunnel func(context.Context, map[string]struct{}) (tgUDPTunnel, error)
	openHandle func(string) (tgTunnelConn, error)
	idleAfter  time.Duration
	watchEvery time.Duration

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	closed   bool
	opening  bool
	active   bool
	attempts int
	failures int
	retryAt  time.Time
	peer     string
	badPeers map[string]time.Time
	tn       tgUDPTunnel
	handle   tgTunnelConn
	sockets  map[tgLocalSocketKey]*tgSocketRelay

	sendMu sync.Mutex
	wg     sync.WaitGroup

	sent      atomic.Int64
	received  atomic.Int64
	lastRelay atomic.Int64
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
		openTunnel: func(c context.Context, exclude map[string]struct{}) (tgUDPTunnel, error) {
			return openWARPTunnelFile(c, defaultStateDir, telegramCallWARPStateFile, telegramCallWARPPortWait, telegramCallWARPBatch, telegramCallWARPJunk, true, exclude, logger)
		},
		openHandle: openTelegramCallTunnelHandle,
		idleAfter:  telegramCallWARPIdle,
		watchEvery: telegramCallWARPWatchEvery,
		ctx:        ctx,
		cancel:     cancel,
		badPeers:   make(map[string]time.Time),
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
	t.attempts++
	t.wg.Add(1)
	t.mu.Unlock()

	go t.activate()
}

func (t *telegramCallTunnel) activeBadPeersLocked(now time.Time) map[string]struct{} {
	if len(t.badPeers) == 0 {
		return nil
	}
	var out map[string]struct{}
	for ep, until := range t.badPeers {
		if now.After(until) {
			delete(t.badPeers, ep)
			continue
		}
		if out == nil {
			out = make(map[string]struct{}, len(t.badPeers))
		}
		out[ep] = struct{}{}
	}
	return out
}

func (t *telegramCallTunnel) openVerifiedTunnel(deprioritized map[string]struct{}) (tgUDPTunnel, error) {
	ctx := t.ctx
	var probeErr error
	for attempt := range 2 {
		if attempt == 1 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, telegramCallWARPStartupRetryWait)
			defer cancel()
		}
		tn, err := t.openTunnel(ctx, deprioritized)
		if err != nil {
			return nil, err
		}
		prober, ok := tn.(tgTunnelProber)
		if !ok {
			return tn, nil
		}
		// The initial probe ran while candidates were still being selected.
		probeErr = probeTelegramRelay(ctx, prober, telegramCallWARPPortWait)
		if probeErr == nil {
			return tn, nil
		}
		peer := tn.Endpoint()
		_ = tn.Close()
		if err := t.ctx.Err(); err != nil {
			return nil, err
		}
		t.logger.Warn("звонок Telegram: резерв WARP не прошёл повторную проверку UDP", "пир", peer, "err", probeErr)
		if peer != "" {
			t.mu.Lock()
			t.badPeers[peer] = t.now().Add(telegramCallWARPBadPeerTTL)
			t.mu.Unlock()
			if deprioritized == nil {
				deprioritized = make(map[string]struct{})
			}
			deprioritized[peer] = struct{}{}
		}
	}
	return nil, fmt.Errorf("повторная проверка UDP перед звонком: %w", probeErr)
}

func (t *telegramCallTunnel) activate() {
	defer t.wg.Done()

	t.mu.Lock()
	exclude := t.activeBadPeersLocked(t.now())
	t.mu.Unlock()

	t.logger.Info("звонок Telegram: запуск резервного UDP-туннеля WARP")
	tn, err := t.openVerifiedTunnel(exclude)
	if err != nil {
		t.mu.Lock()
		t.opening = false
		if !t.closed {
			t.failures++
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

	handle, err := t.openHandle(tn.Endpoint())
	if err != nil {
		_ = tn.Close()
		t.mu.Lock()
		t.opening = false
		if !t.closed {
			t.failures++
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

	health := &tgRelayHealth{}
	targets := &tgTargetStats{}
	watchCtx, cancelWatch := context.WithCancel(t.ctx)
	watchDone := make(chan struct{})
	t.markRelay()
	go func() {
		defer close(watchDone)
		t.watchRelay(watchCtx, handle, tn, health, targets)
	}()
	defer func() {
		cancelWatch()
		<-watchDone
		t.closeSockets()
		_ = handle.Close()
		_ = tn.Close()
		t.mu.Lock()
		t.handle, t.tn, t.active = nil, nil, false
		t.mu.Unlock()
	}()

	sentBase, recvBase := t.sent.Load(), t.received.Load()
	lastReport := t.now()
	var reportedTx int64
	report := func(msg string) {
		tx, rx := t.sent.Load()-sentBase, t.received.Load()-recvBase
		t.logger.Info(msg, "пир", tn.Endpoint(), "отправлено", tx, "получено", rx,
			"цели_отпр/получ", targets.String())
		reportedTx = tx
		lastReport = t.now()
	}
	defer func() {
		if t.sent.Load()-sentBase != reportedTx {
			report("звонок Telegram через WARP: итог")
		}
	}()
	t.wg.Add(1)
	go t.logExitInfo(tn)

	for {
		pkt, err := handle.Recv()
		if err != nil {
			return
		}
		if health.retired.Load() {
			// WinDivert can still return packets queued before ShutdownReceive.
			t.sendPacket(handle, pkt)
			continue
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
		relay := t.getOrCreateSocket(handle, tn, tgLocalSocketKey{ip: srcIP, port: srcPort}, pkt.Reinject, targets, health)
		if relay == nil || health.retired.Load() {
			t.sendPacket(handle, pkt)
			continue
		}
		dstAP := netip.AddrPortFrom(dstIP, dstPort)
		if n, err := relay.pc.WriteTo(payload, net.UDPAddrFromAddrPort(dstAP)); err != nil {
			t.removeSocket(relay)
			if n == 0 {
				t.sendPacket(handle, pkt)
			}
			continue
		}
		health.sent(t.now())
		t.sent.Add(1)
		t.markRelay()
		targets.add(dstAP, 1, 0)
		if t.now().Sub(lastReport) >= telegramCallReportEvery {
			report("звонок Telegram через WARP: сводка")
		}
	}
}

func (t *telegramCallTunnel) markRelay() { t.lastRelay.Store(t.now().UnixNano()) }

// The watchdog keeps running when Recv blocks between call packets.
func (t *telegramCallTunnel) watchRelay(ctx context.Context, handle tgTunnelConn, tn tgUDPTunnel, health *tgRelayHealth, targets *tgTargetStats) {
	tick := time.NewTicker(t.watchEvery)
	defer tick.Stop()
	prober, canProbe := tn.(tgTunnelProber)
	var lastReplies int64
	checkedGap := false
	diagnosis := "контрольный UDP не проверялся"
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		now := t.now()
		idle := now.Sub(time.Unix(0, t.lastRelay.Load()))
		if t.idleAfter > 0 && idle >= t.idleAfter {
			health.retired.Store(true)
			stopTelegramRelayCapture(handle)
			t.logger.Info("звонок Telegram: звонок завершён, резервный UDP-туннель WARP снят",
				"тишина", idle.Round(time.Second).String())
			return
		}

		p := health.snapshot()
		if p.replies != lastReplies {
			lastReplies, checkedGap = p.replies, false
			diagnosis = "контрольный UDP не проверялся"
		}
		if p.pending == 0 {
			continue
		}
		silence := now.Sub(p.since)
		oldEnough := silence >= telegramCallWARPDeadWindow
		enoughPackets := p.pending >= telegramCallWARPDeadPackets
		if canProbe && !checkedGap {
			ready := oldEnough && enoughPackets
			probeWait := telegramCallProbeWait
			if p.replies == 0 {
				// Even a short failed attempt must not leave a dead relay open
				// until the next call sends packets.
				ready = oldEnough || (enoughPackets && silence >= telegramCallWARPEarlyProbeAfter)
				probeWait = telegramCallWARPPortWait
			}
			if !ready {
				continue
			}
			err := probeTelegramRelay(ctx, prober, probeWait)
			if ctx.Err() != nil {
				return
			}
			checkedGap = true
			if err == nil {
				diagnosis = "контрольный UDP прошёл, ответа звонка нет"
				if p.replies > 0 && health.finishGap(p, true) {
					t.logger.Info("звонок Telegram: резерв WARP отвечает, ждём ответа звонка")
				}
				continue
			}
			diagnosis = "контрольный UDP без ответа"
		} else if !oldEnough || !enoughPackets {
			continue
		}
		if ctx.Err() != nil || !health.finishGap(p, false) {
			continue
		}
		peer := tn.Endpoint()
		t.mu.Lock()
		if !t.closed {
			now := t.now()
			if peer != "" {
				t.badPeers[peer] = now.Add(telegramCallWARPBadPeerTTL)
			}
			t.retryAt = now.Add(telegramCallWARPDeadRetry)
		}
		t.mu.Unlock()
		t.logger.Warn("звонок Telegram: резервный UDP-туннель WARP не отвечает, смена адреса",
			"пир", peer, "тишина_мс", t.now().Sub(p.since).Milliseconds(),
			"отправлено_без_ответа", p.pending, "получено_всего", p.replies,
			"цели_отпр/получ", targets.String(), "повтор_через", telegramCallWARPDeadRetry.String(),
			"диагноз", diagnosis)
		stopTelegramRelayCapture(handle)
		return
	}
}

func stopTelegramRelayCapture(handle tgTunnelConn) {
	if err := handle.ShutdownReceive(); err != nil {
		_ = handle.Close()
	}
}

func probeTelegramRelay(ctx context.Context, prober tgTunnelProber, wait time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	return prober.ProbeUDP(ctx)
}

func (t *telegramCallTunnel) logExitInfo(tn tgUDPTunnel) {
	defer t.wg.Done()
	src, ok := tn.(tgTunnelExitInfo)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(t.ctx, telegramCallExitInfoWait)
	defer cancel()
	info, err := src.ExitInfo(ctx)
	if t.ctx.Err() != nil {
		return
	}
	if err != nil {
		t.logger.Info("звонок Telegram: выход WARP не определён", "пир", tn.Endpoint(), "err", err)
		return
	}
	t.logger.Info("звонок Telegram: выход WARP", "пир", tn.Endpoint(), "узел", info)
}

func (t *telegramCallTunnel) getOrCreateSocket(handle tgTunnelConn, tn tgUDPTunnel, key tgLocalSocketKey, reinject any, targets *tgTargetStats, health *tgRelayHealth) *tgSocketRelay {
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

	go t.readSocket(handle, relay, targets, health)
	return relay
}

func (t *telegramCallTunnel) readSocket(handle tgTunnelConn, relay *tgSocketRelay, targets *tgTargetStats, health *tgRelayHealth) {
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
		health.received()
		t.received.Add(1)
		t.markRelay()
		targets.add(src, 0, 1)
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
		Attempts: t.attempts,
		Failures: t.failures,
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
