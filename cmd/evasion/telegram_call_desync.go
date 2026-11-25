package main

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/discordvoice"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/quic"
)

// isInboundCallReply reports whether an inbound UDP payload is a genuine
// server/peer reply (STUN/TURN response, non-ClientHello DTLS handshake, or
// legacy reflector traffic) rather than a peer's outbound probe (STUN request
// or DTLS ClientHello).
func isInboundCallReply(srcPort uint16, payload []byte) bool {
	if len(payload) >= 20 && binary.BigEndian.Uint32(payload[4:8]) == 0x2112A442 {
		// RFC 5389 class bit 8 (0x0100) is set only on Success/Error Responses,
		// not on Requests (0x0000) or Indications (0x0010).
		return binary.BigEndian.Uint16(payload[0:2])&0x0100 != 0
	}
	if len(payload) >= 14 && payload[0] == 0x16 && payload[1] == 0xfe {
		return payload[13] != 0x01
	}
	return isTelegramReflectorPort(srcPort) && len(payload) >= 16
}

// isDTLSClientHello reports whether payload is a DTLS 1.0/1.2/1.3 handshake
// record carrying a ClientHello (content type 0x16, version 0xFE 0x..,
// handshake type 0x01 at offset 13).
func isDTLSClientHello(payload []byte) bool {
	return len(payload) >= 25 &&
		payload[0] == 0x16 &&
		payload[1] == 0xfe &&
		payload[13] == 0x01
}

type tgCallKind uint8

const (
	tgCallNone tgCallKind = iota
	tgCallSTUN
	tgCallDTLS
	tgCallLegacy
)

type tgCallStrategy uint8

const (
	tgStratTTLSweepQUIC tgCallStrategy = iota
	tgStratBadsumCompact
	tgStratQUICYaSweep
	tgStratMinimalTTL
	tgStratCount
)

func (s tgCallStrategy) String() string {
	switch s {
	case tgStratTTLSweepQUIC:
		return "ttl-sweep-quic"
	case tgStratBadsumCompact:
		return "badsum-compact"
	case tgStratQUICYaSweep:
		return "quic-ya-sweep"
	case tgStratMinimalTTL:
		return "minimal-ttl"
	default:
		return "unknown"
	}
}

const (
	tgCallRotateEvery = 3
	tgCallFlowTTL     = 45 * time.Second
	tgCallFlowCap     = 256
)

type tgCallFlowState struct {
	sent       int
	replies    int
	stage      tgCallStrategy
	stageCount int
	last       time.Time
}

type telegramCallStats struct {
	STUN     int
	DTLS     int
	Legacy   int
	Replies  int
	Targets  int
	Strategy string
}

// telegramCallEngine is a dedicated UDP DPI desync engine for Telegram calls,
// independent of Discord's voice desync. It handles STUN/TURN, DTLS
// ClientHello, and legacy reflectors (596-599), tracks inbound replies on the
// reverse 5-tuple, and rotates compact decoy strategies per flow until replies
// arrive.
type telegramCallEngine struct {
	owner telegramUDPOwner
	legacy *telegramReflectorTracker
	now   func() time.Time

	mu      sync.Mutex
	flows   map[telegramFlowKey]*tgCallFlowState
	targets map[netip.Addr]struct{}
	stun    int
	dtls    int
	legacyN int
	replies int
	lastStr tgCallStrategy
}

func newTelegramCallEngine(owner telegramUDPOwner, legacy *telegramReflectorTracker) *telegramCallEngine {
	if legacy == nil {
		legacy = newTelegramReflectorTracker()
	}
	return &telegramCallEngine{
		owner:   owner,
		legacy:  legacy,
		now:     time.Now,
		flows:   make(map[telegramFlowKey]*tgCallFlowState),
		targets: make(map[netip.Addr]struct{}),
	}
}

// ObserveInbound checks an inbound UDP packet against tracked Telegram call
// flows and records a reply if it matches the reverse 5-tuple. Always returns
// immediately without modifying the packet.
func (e *telegramCallEngine) ObserveInbound(pkt capture.Packet) bool {
	if e == nil || pkt.Dir != core.DirectionInbound {
		return false
	}
	d, err := packet.Dissect(pkt.Data)
	if err != nil || d.Protocol != packet.ProtoUDP {
		return false
	}
	u, ok := d.UDP(pkt.Data)
	if !ok {
		return false
	}
	payload, ok := d.Payload(pkt.Data)
	if !ok || !isInboundCallReply(u.SrcPort(), payload) {
		return false
	}
	srcIP := packetSrcIP(pkt.Data, d)
	if !srcIP.IsValid() {
		return false
	}
	key := telegramFlowKey{srcPort: u.DstPort(), dstIP: srcIP.Unmap(), dstPort: u.SrcPort()}
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	st, ok := e.flows[key]
	if !ok || now.Sub(st.last) > tgCallFlowTTL {
		return false
	}
	st.replies++
	st.last = now
	e.replies++
	return true
}

// Classify reports whether an outbound UDP packet belongs to a Telegram call
// handshake (STUN/TURN, DTLS ClientHello, or legacy reflector 596-599).
func (e *telegramCallEngine) Classify(buf []byte, d packet.Dissection, payload []byte) tgCallKind {
	if e == nil {
		return tgCallNone
	}
	u, ok := d.UDP(buf)
	if !ok || u.DstPort() == 443 {
		return tgCallNone
	}
	dstIP := packetDstIP(buf, d)
	dstPort := u.DstPort()
	ownedByTG := func() bool {
		return isTelegramCallIP(dstIP) || (e.owner != nil && e.owner.OwnsUDP(packetSrcIP(buf, d), u.SrcPort()))
	}
	if discordvoice.IsSTUNOrTURNRequest(payload) {
		if ownedByTG() {
			if isTelegramReflectorPort(dstPort) {
				e.legacy.MarkHandled(u.SrcPort(), dstIP, dstPort)
			}
			return tgCallSTUN
		}
		return tgCallNone
	}
	if isDTLSClientHello(payload) {
		if ownedByTG() {
			if isTelegramReflectorPort(dstPort) {
				e.legacy.MarkHandled(u.SrcPort(), dstIP, dstPort)
			}
			return tgCallDTLS
		}
		return tgCallNone
	}
	if isTelegramReflectorPort(dstPort) && len(payload) >= 16 && isTelegramCallIP(dstIP) {
		if e.legacy == nil || e.legacy.Allow(u.SrcPort(), dstIP, dstPort) {
			return tgCallLegacy
		}
	}
	return tgCallNone
}

// BuildDecoys builds the Telegram-specific decoy sequence (followed by the
// original packet) for pkt, or returns (nil, false) if pkt is not a Telegram
// call handshake packet.
func (e *telegramCallEngine) BuildDecoys(pkt capture.Packet) ([]capture.Packet, bool) {
	if e == nil || pkt.Dir != core.DirectionOutbound {
		return nil, false
	}
	d, err := packet.Dissect(pkt.Data)
	if err != nil || d.Protocol != packet.ProtoUDP {
		return nil, false
	}
	payload, ok := d.Payload(pkt.Data)
	if !ok {
		return nil, false
	}
	kind := e.Classify(pkt.Data, d, payload)
	if kind == tgCallNone {
		return nil, false
	}
	u, _ := d.UDP(pkt.Data)
	dstIP := packetDstIP(pkt.Data, d)
	stage, sendCover := e.advanceFlow(u.SrcPort(), dstIP, u.DstPort(), kind)
	out := buildTelegramStagePackets(pkt, len(payload), stage, sendCover)
	return out, true
}

func (e *telegramCallEngine) advanceFlow(srcPort uint16, dstIP netip.Addr, dstPort uint16, kind tgCallKind) (tgCallStrategy, bool) {
	key := telegramFlowKey{srcPort: srcPort, dstIP: dstIP.Unmap(), dstPort: dstPort}
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()

	st, ok := e.flows[key]
	if ok && now.Sub(st.last) > tgCallFlowTTL {
		st = nil
		ok = false
	}
	if !ok {
		e.evictLocked(now)
		st = &tgCallFlowState{}
		e.flows[key] = st
	}
	rotateEvery := tgCallRotateEvery
	if kind == tgCallLegacy {
		rotateEvery = 1
	}
	if st.replies == 0 && st.stageCount >= rotateEvery {
		st.stage = (st.stage + 1) % tgStratCount
		st.stageCount = 0
	}
	sendCover := st.stageCount == 0
	st.sent++
	st.stageCount++
	st.last = now

	if dstIP.IsValid() {
		if len(e.targets) < tgCallFlowCap {
			e.targets[dstIP.Unmap()] = struct{}{}
		}
	}
	switch kind {
	case tgCallSTUN:
		e.stun++
	case tgCallDTLS:
		e.dtls++
	case tgCallLegacy:
		e.legacyN++
	}
	e.lastStr = st.stage
	return st.stage, sendCover
}

func (e *telegramCallEngine) evictLocked(now time.Time) {
	if len(e.flows) < tgCallFlowCap {
		return
	}
	for k, v := range e.flows {
		if now.Sub(v.last) > tgCallFlowTTL {
			delete(e.flows, k)
		}
	}
	if len(e.flows) >= tgCallFlowCap {
		var oldestKey telegramFlowKey
		var oldestTime time.Time
		for k, v := range e.flows {
			if oldestTime.IsZero() || v.last.Before(oldestTime) {
				oldestKey, oldestTime = k, v.last
			}
		}
		delete(e.flows, oldestKey)
	}
}

func (e *telegramCallEngine) Stats() telegramCallStats {
	if e == nil {
		return telegramCallStats{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return telegramCallStats{
		STUN:     e.stun,
		DTLS:     e.dtls,
		Legacy:   e.legacyN,
		Replies:  e.replies,
		Targets:  len(e.targets),
		Strategy: e.lastStr.String(),
	}
}

func buildTelegramStagePackets(pkt capture.Packet, payloadLen int, stage tgCallStrategy, sendCover bool) []capture.Packet {
	fake := voiceFakePayload(payloadLen, voicePayloadNeutral)
	out := make([]capture.Packet, 0, 8)
	addCover := func(sni string) {
		if !sendCover {
			return
		}
		if c, ok := buildSingleVoiceCover(pkt, sni); ok {
			out = append(out, c)
		}
	}
	addDecoy := func(fool discordvoice.Fooling, ttl uint8) {
		decoy, err := discordvoice.BuildDecoy(pkt.Data, fool, ttl, fake)
		if err != nil {
			return
		}
		out = append(out, capture.Packet{Data: decoy, Dir: pkt.Dir, Reinject: pkt.Reinject})
	}

	switch stage {
	case tgStratTTLSweepQUIC:
		addCover(voiceCoverSNI)
		for _, ttl := range []uint8{2, 4, 6} {
			addDecoy(discordvoice.FoolTTL, ttl)
		}
		addDecoy(discordvoice.FoolBadChecksum, voiceBadsumTTL)
	case tgStratBadsumCompact:
		addDecoy(discordvoice.FoolBadChecksum, voiceBadsumTTL)
		addDecoy(discordvoice.FoolBadChecksum, voiceBadsumTTL)
		addDecoy(discordvoice.FoolTTL, 3)
		addDecoy(discordvoice.FoolTTL, 5)
	case tgStratQUICYaSweep:
		addCover("ya.ru")
		for _, ttl := range []uint8{1, 3, 5, 7} {
			addDecoy(discordvoice.FoolTTL, ttl)
		}
	case tgStratMinimalTTL:
		for _, ttl := range []uint8{2, 4, 8} {
			addDecoy(discordvoice.FoolTTL, ttl)
		}
	}
	out = append(out, pkt)
	return out
}

func buildSingleVoiceCover(pkt capture.Packet, sni string) (capture.Packet, bool) {
	dcid := make([]byte, 8)
	if _, err := rand.Read(dcid); err != nil {
		return capture.Packet{}, false
	}
	initial, ok := quic.BuildClientInitial(sni, dcid)
	if !ok {
		return capture.Packet{}, false
	}
	cover, err := discordvoice.BuildCover(pkt.Data, initial, voiceBadsumTTL)
	if err != nil {
		return capture.Packet{}, false
	}
	return capture.Packet{Data: cover, Dir: pkt.Dir, Reinject: pkt.Reinject}, true
}
