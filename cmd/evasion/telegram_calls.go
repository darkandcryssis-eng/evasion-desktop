package main

import (
	"net/netip"
	"strings"
	"sync"
	"time"
)

// telegramCallPrefixes lists official Telegram DC and call reflector IP ranges
// (IPv4 and IPv6). Kept self-contained here so voice desync does not depend on
// TCP strategy packages.
var telegramCallPrefixes = mustParseCallPrefixes([]string{
	"149.154.160.0/20",
	"91.108.4.0/22",
	"91.108.8.0/22",
	"91.108.12.0/22",
	"91.108.16.0/22",
	"91.108.20.0/22",
	"91.108.56.0/22",
	"91.105.192.0/23",
	"185.76.151.0/24",
	"95.161.64.0/20",
	"2001:b28:f23d::/48",
	"2001:b28:f23f::/48",
	"2001:67c:4e8::/48",
	"2001:b28:f23c::/48",
	"2a0a:f280::/32",
})

func mustParseCallPrefixes(raw []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			panic("telegram calls: invalid CIDR " + s + ": " + err.Error())
		}
		out = append(out, p.Masked())
	}
	return out
}

// isTelegramCallIP reports whether addr belongs to Telegram's official DC or
// call reflector IP ranges.
func isTelegramCallIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, p := range telegramCallPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// isTelegramReflectorPort reports whether port is in Telegram's well-known
// legacy non-TURN reflector UDP range (596-599).
func isTelegramReflectorPort(port uint16) bool {
	return port >= 596 && port <= 599
}

// isTelegramProcessName reports whether a Windows process name is a desktop
// Telegram client whose outbound P2P STUN/TURN sockets should receive call
// desync.
func isTelegramProcessName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "telegram.exe", "ayugram.exe", "unigram.exe", "kotatogram.exe", "64gram.exe":
		return true
	default:
		return false
	}
}

// telegramUDPOwner checks whether a local UDP port belongs to a running
// Telegram desktop client.
type telegramUDPOwner interface {
	OwnsUDP(localPort uint16) bool
}

// telegramFlowKey identifies an outbound UDP 5-tuple for bounded legacy
// reflector desync so audio frames after the initial handshake are untouched.
type telegramFlowKey struct {
	srcPort uint16
	dstIP   netip.Addr
	dstPort uint16
}

const (
	telegramReflectorBurst = 3
	telegramReflectorTTL   = 30 * time.Second
	telegramReflectorCap   = 256
)

type telegramFlowState struct {
	count int
	last  time.Time
}

// telegramReflectorTracker limits UDP desync on legacy Telegram reflector
// flows (ports 596-599) to the first telegramReflectorBurst outbound packets
// per 5-tuple, re-arming after telegramReflectorTTL of inactivity.
type telegramReflectorTracker struct {
	mu    sync.Mutex
	flows map[telegramFlowKey]telegramFlowState
	now   func() time.Time
}

func newTelegramReflectorTracker() *telegramReflectorTracker {
	return &telegramReflectorTracker{
		flows: make(map[telegramFlowKey]telegramFlowState),
		now:   time.Now,
	}
}

func (t *telegramReflectorTracker) evictLocked(now time.Time) {
	if len(t.flows) < telegramReflectorCap {
		return
	}
	for k, v := range t.flows {
		if now.Sub(v.last) > telegramReflectorTTL {
			delete(t.flows, k)
		}
	}
	if len(t.flows) >= telegramReflectorCap {
		var oldestKey telegramFlowKey
		var oldestTime time.Time
		for k, v := range t.flows {
			if oldestTime.IsZero() || v.last.Before(oldestTime) {
				oldestKey, oldestTime = k, v.last
			}
		}
		delete(t.flows, oldestKey)
	}
}

// MarkHandled records that a 5-tuple already received STUN/TURN desync so
// subsequent non-STUN TURN ChannelData/media frames on reflector ports 596-599
// do not trigger legacy reflector decoys.
func (t *telegramReflectorTracker) MarkHandled(srcPort uint16, dstIP netip.Addr, dstPort uint16) {
	if t == nil || !dstIP.IsValid() {
		return
	}
	key := telegramFlowKey{srcPort: srcPort, dstIP: dstIP.Unmap(), dstPort: dstPort}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.flows[key]; !ok {
		t.evictLocked(now)
	}
	t.flows[key] = telegramFlowState{count: telegramReflectorBurst, last: now}
}

func (t *telegramReflectorTracker) Allow(srcPort uint16, dstIP netip.Addr, dstPort uint16) bool {
	if t == nil || !dstIP.IsValid() {
		return false
	}
	key := telegramFlowKey{srcPort: srcPort, dstIP: dstIP.Unmap(), dstPort: dstPort}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.flows[key]
	if ok && now.Sub(st.last) > telegramReflectorTTL {
		st = telegramFlowState{}
		ok = false
	}
	if !ok {
		t.evictLocked(now)
	}
	st.last = now
	if st.count >= telegramReflectorBurst {
		t.flows[key] = st
		return false
	}
	st.count++
	t.flows[key] = st
	return true
}
