package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/discordvoice"
	"github.com/fitting-1c/evasion/internal/packet"
)

type stubTelegramOwner struct {
	ports map[uint16]bool
}

func (s stubTelegramOwner) OwnsUDP(_ netip.Addr, port uint16) bool { return s.ports[port] }

func buildUDPPacketIPv4(t *testing.T, dstIP string, srcPort, dstPort uint16, payload []byte) capture.Packet {
	t.Helper()
	buf := make([]byte, 20+8+len(payload))
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = 17
	copy(buf[12:16], net.ParseIP("10.0.0.1").To4())
	copy(buf[16:20], net.ParseIP(dstIP).To4())
	binary.BigEndian.PutUint16(buf[20:22], srcPort)
	binary.BigEndian.PutUint16(buf[22:24], dstPort)
	binary.BigEndian.PutUint16(buf[24:26], uint16(8+len(payload)))
	copy(buf[28:], payload)
	d, err := packet.Dissect(buf)
	if err != nil || !d.RecomputeChecksums(buf) {
		t.Fatalf("buildUDPPacketIPv4 dissect/checksum failed: %v", err)
	}
	return capture.Packet{Data: buf, Dir: core.DirectionOutbound}
}

func buildUDPPacketIPv6(t *testing.T, dstIP string, srcPort, dstPort uint16, payload []byte) capture.Packet {
	t.Helper()
	buf := make([]byte, 40+8+len(payload))
	buf[0] = 0x60
	binary.BigEndian.PutUint16(buf[4:6], uint16(8+len(payload)))
	buf[6] = 17
	buf[7] = 64
	copy(buf[8:24], net.ParseIP("2001:db8::1").To16())
	copy(buf[24:40], net.ParseIP(dstIP).To16())
	binary.BigEndian.PutUint16(buf[40:42], srcPort)
	binary.BigEndian.PutUint16(buf[42:44], dstPort)
	binary.BigEndian.PutUint16(buf[44:46], uint16(8+len(payload)))
	copy(buf[48:], payload)
	d, err := packet.Dissect(buf)
	if err != nil || !d.RecomputeChecksums(buf) {
		t.Fatalf("buildUDPPacketIPv6 dissect/checksum failed: %v", err)
	}
	return capture.Packet{Data: buf, Dir: core.DirectionOutbound}
}

func stunPayload(kind uint16, attrLen int) []byte {
	b := make([]byte, 20+attrLen)
	binary.BigEndian.PutUint16(b[0:], kind)
	binary.BigEndian.PutUint16(b[2:], uint16(attrLen))
	binary.BigEndian.PutUint32(b[4:], 0x2112A442)
	return b
}

func TestTelegramCallSTUNAndTURNToTelegramCIDR(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkt  capture.Packet
	}{
		{"stun-binding-dc2", buildUDPPacketIPv4(t, "149.154.167.50", 51000, 1400, stunPayload(0x0001, 40))},
		{"turn-allocate-dc4", buildUDPPacketIPv4(t, "91.108.56.100", 51001, 599, stunPayload(0x0003, 64))},
		{"turn-refresh", buildUDPPacketIPv4(t, "91.108.4.12", 51002, 3478, stunPayload(0x0004, 24))},
		{"turn-create-perm", buildUDPPacketIPv4(t, "95.161.76.100", 51003, 596, stunPayload(0x0008, 32))},
		{"turn-channel-bind", buildUDPPacketIPv4(t, "185.76.151.10", 51004, 32000, stunPayload(0x0009, 36))},
		{"stun-ipv6-dc", buildUDPPacketIPv6(t, "2001:b28:f23d:f001::a", 51005, 1400, stunPayload(0x0003, 40))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, target := buildVoiceDecoysFor(tc.pkt, discordvoice.FoolTTL, 6, 3, voicePayloadNeutral, nil, nil)
			if target != voiceTargetTelegram {
				t.Fatalf("target=%v, want voiceTargetTelegram", target)
			}
			if len(out) != 7 {
				t.Fatalf("len=%d, want 7 (6 decoys + original)", len(out))
			}
			for i, decoy := range out[:6] {
				d, err := packet.Dissect(decoy.Data)
				if err != nil {
					t.Fatalf("decoy %d dissect: %v", i, err)
				}
				pl, _ := d.Payload(decoy.Data)
				if discordvoice.IsSTUNOrTURNRequest(pl) {
					t.Fatalf("decoy %d must not carry STUN/TURN signature", i)
				}
			}
			if string(out[6].Data) != string(tc.pkt.Data) {
				t.Fatal("original packet must be sent last unchanged")
			}
		})
	}
}

func TestTelegramCallP2PByProcessOwner(t *testing.T) {
	owner := stubTelegramOwner{ports: map[uint16]bool{54321: true}}
	// Peer residential IP on an arbitrary ephemeral port.
	pktFromTG := buildUDPPacketIPv4(t, "203.0.113.42", 54321, 49152, stunPayload(0x0001, 48))
	out, target := buildVoiceDecoysFor(pktFromTG, discordvoice.FoolTTL, 6, 2, voicePayloadNeutral, owner, nil)
	if target != voiceTargetTelegram || len(out) != 5 {
		t.Fatalf("Telegram P2P STUN: target=%v len=%d, want Telegram/5", target, len(out))
	}

	// Same destination from a different process must be left untouched.
	pktFromOther := buildUDPPacketIPv4(t, "203.0.113.42", 54322, 49152, stunPayload(0x0001, 48))
	if _, target := buildVoiceDecoysFor(pktFromOther, discordvoice.FoolTTL, 6, 2, voicePayloadNeutral, owner, nil); target != voiceTargetNone {
		t.Fatalf("non-Telegram STUN on foreign port must be skipped, got target=%v", target)
	}

	// QUIC port 443 is never touched even from Telegram.exe.
	pkt443 := buildUDPPacketIPv4(t, "149.154.167.50", 54321, 443, stunPayload(0x0001, 48))
	if _, target := buildVoiceDecoysFor(pkt443, discordvoice.FoolTTL, 6, 2, voicePayloadNeutral, owner, nil); target != voiceTargetNone {
		t.Fatalf("port 443 must not be handled by voice desync, got target=%v", target)
	}
}

func TestTelegramLegacyReflectorBurstLimit(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	tracker := newTelegramReflectorTracker()
	tracker.now = func() time.Time { return now }

	legacyPayload := make([]byte, 32)
	for i := range legacyPayload {
		legacyPayload[i] = byte(0xaa + i)
	}
	pkt := buildUDPPacketIPv4(t, "149.154.167.50", 52000, 597, legacyPayload)

	for i := range telegramReflectorBurst {
		_, target := buildVoiceDecoysFor(pkt, discordvoice.FoolTTL, 6, 2, voicePayloadNeutral, nil, tracker)
		if target != voiceTargetTelegram {
			t.Fatalf("packet %d: target=%v, want voiceTargetTelegram", i, target)
		}
	}
	// Subsequent audio frames on the same flow must pass through untouched.
	if _, target := buildVoiceDecoysFor(pkt, discordvoice.FoolTTL, 6, 2, voicePayloadNeutral, nil, tracker); target != voiceTargetNone {
		t.Fatalf("packet after burst limit must be skipped, got %v", target)
	}
	// After idle TTL, a fresh call on the same 5-tuple re-arms.
	now = now.Add(telegramReflectorTTL + time.Second)
	if _, target := buildVoiceDecoysFor(pkt, discordvoice.FoolTTL, 6, 2, voicePayloadNeutral, nil, tracker); target != voiceTargetTelegram {
		t.Fatalf("packet after idle TTL should re-arm, got %v", target)
	}

	// Non-Telegram IP on port 597 must never be touched.
	foreign := buildUDPPacketIPv4(t, "203.0.113.9", 52000, 597, legacyPayload)
	if _, target := buildVoiceDecoysFor(foreign, discordvoice.FoolTTL, 6, 2, voicePayloadNeutral, nil, tracker); target != voiceTargetNone {
		t.Fatalf("non-Telegram IP on port 597 must be skipped, got %v", target)
	}
}

func TestTelegramTURNOnReflectorPortSuppressesLegacyDecoys(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	tracker := newTelegramReflectorTracker()
	tracker.now = func() time.Time { return now }

	turnAlloc := buildUDPPacketIPv4(t, "91.108.56.100", 52100, 599, stunPayload(0x0003, 64))
	if _, target := buildVoiceDecoysFor(turnAlloc, discordvoice.FoolTTL, 6, 2, voicePayloadNeutral, nil, tracker); target != voiceTargetTelegram {
		t.Fatalf("TURN Allocate on 599: target=%v, want voiceTargetTelegram", target)
	}

	// Subsequent TURN ChannelData / media packets on the same 5-tuple must not
	// trigger legacy reflector decoys.
	mediaPayload := make([]byte, 120)
	mediaPayload[0] = 0x40 // TURN ChannelData channel 0x4000
	mediaPkt := buildUDPPacketIPv4(t, "91.108.56.100", 52100, 599, mediaPayload)
	for i := range 5 {
		now = now.Add(20 * time.Millisecond)
		if _, target := buildVoiceDecoysFor(mediaPkt, discordvoice.FoolTTL, 6, 2, voicePayloadNeutral, nil, tracker); target != voiceTargetNone {
			t.Fatalf("TURN media packet %d must not trigger legacy decoys, got %v", i, target)
		}
	}
}

func TestIsTelegramProcessName(t *testing.T) {
	for _, name := range []string{"Telegram.exe", "telegram.exe", "AyuGram.exe", "Unigram.exe", "Kotatogram.exe", "64Gram.exe"} {
		if !isTelegramProcessName(name) {
			t.Fatalf("%q should be recognized as Telegram client", name)
		}
	}
	for _, name := range []string{"chrome.exe", "Discord.exe", "svchost.exe", ""} {
		if isTelegramProcessName(name) {
			t.Fatalf("%q must not be recognized as Telegram client", name)
		}
	}
}

func TestIsTelegramCallIP(t *testing.T) {
	for _, s := range []string{"149.154.167.50", "91.108.56.100", "91.105.192.1", "185.76.151.1", "95.161.76.100", "2001:b28:f23d::1"} {
		if !isTelegramCallIP(netip.MustParseAddr(s)) {
			t.Fatalf("%s should match Telegram call IP", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "66.22.200.1", "2001:4860:4860::8888"} {
		if isTelegramCallIP(netip.MustParseAddr(s)) {
			t.Fatalf("%s must not match Telegram call IP", s)
		}
	}
}

func TestUDPOwnerSnapshotMatchesLocalAddress(t *testing.T) {
	ip1 := netip.MustParseAddr("10.0.0.1")
	ip2 := netip.MustParseAddr("192.168.1.5")
	ip6 := netip.MustParseAddr("2001:db8::1")

	// Specific local IP bind must not match another app on the same port with a different IP or family.
	specific := udpOwnerSnapshot{
		tg:    map[udpEndpoint]bool{{addr: ip1, port: 50000}: true},
		other: map[udpEndpoint]bool{{addr: ip2, port: 50000}: true},
	}
	if !specific.Owns(ip1, 50000) {
		t.Fatal("exact Telegram endpoint should match")
	}
	if specific.Owns(ip2, 50000) {
		t.Fatal("different local IPv4 on shared port must not match")
	}
	if specific.Owns(ip6, 50000) {
		t.Fatal("IPv6 on shared port must not match specific IPv4 Telegram bind")
	}

	// Wildcard IPv4 bind matches IPv4 unless another process owns the exact IP, and never matches IPv6.
	wildcard4 := udpOwnerSnapshot{
		tg:    map[udpEndpoint]bool{{addr: netip.IPv4Unspecified(), port: 50001}: true},
		other: map[udpEndpoint]bool{{addr: ip2, port: 50001}: true},
	}
	if !wildcard4.Owns(ip1, 50001) {
		t.Fatal("IPv4 wildcard should match unbound local IPv4")
	}
	if wildcard4.Owns(ip2, 50001) {
		t.Fatal("other process exact IPv4 bind must take precedence over Telegram wildcard")
	}
	if wildcard4.Owns(ip6, 50001) {
		t.Fatal("IPv4 wildcard must not match IPv6")
	}

	// Dual-stack [::] bind matches IPv4 only when no other process owns IPv4 on that port.
	dualStack := udpOwnerSnapshot{
		tg:    map[udpEndpoint]bool{{addr: netip.IPv6Unspecified(), port: 50002}: true},
		other: map[udpEndpoint]bool{{addr: netip.IPv4Unspecified(), port: 50003}: true},
	}
	dualStack.tg[udpEndpoint{addr: netip.IPv6Unspecified(), port: 50003}] = true
	if !dualStack.Owns(ip1, 50002) || !dualStack.Owns(ip6, 50002) {
		t.Fatal("dual-stack [::] should match both IPv4 and IPv6 when IPv4 is uncontested")
	}
	if dualStack.Owns(ip1, 50003) {
		t.Fatal("other process 0.0.0.0 bind must prevent [::] from claiming IPv4")
	}
	if !dualStack.Owns(ip6, 50003) {
		t.Fatal("[::] should still match IPv6 when other process only holds 0.0.0.0")
	}
}

func dtlsClientHelloPayload() []byte {
	b := make([]byte, 80)
	b[0] = 0x16 // handshake
	b[1] = 0xfe // DTLS 1.2
	b[2] = 0xfd
	b[13] = 0x01 // ClientHello
	return b
}

func buildInboundUDPPacketIPv4(t *testing.T, srcIP string, srcPort, dstPort uint16, payload []byte) capture.Packet {
	t.Helper()
	buf := make([]byte, 20+8+len(payload))
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8] = 64
	buf[9] = 17
	copy(buf[12:16], net.ParseIP(srcIP).To4())
	copy(buf[16:20], net.ParseIP("10.0.0.1").To4())
	binary.BigEndian.PutUint16(buf[20:22], srcPort)
	binary.BigEndian.PutUint16(buf[22:24], dstPort)
	binary.BigEndian.PutUint16(buf[24:26], uint16(8+len(payload)))
	copy(buf[28:], payload)
	d, err := packet.Dissect(buf)
	if err != nil || !d.RecomputeChecksums(buf) {
		t.Fatalf("buildInboundUDPPacketIPv4 dissect/checksum failed: %v", err)
	}
	return capture.Packet{Data: buf, Dir: core.DirectionInbound}
}

func TestTelegramCallEngineDTLSAndAdaptiveRotation(t *testing.T) {
	now := time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC)
	eng := newTelegramCallEngine(nil, nil)
	eng.now = func() time.Time { return now }

	stunPkt := buildUDPPacketIPv4(t, "149.154.167.50", 53000, 1400, stunPayload(0x0003, 48))

	// First 3 unanswered STUN packets stay on stage 0 (ttl-sweep-quic);
	// cover is only sent on the first packet of the stage.
	first, ok := eng.BuildDecoys(stunPkt)
	if !ok || len(first) != 6 {
		t.Fatalf("stage 0 first packet: ok=%v len=%d, want true/6 (1 cover + 3 ttl + 1 badsum + orig)", ok, len(first))
	}
	second, ok := eng.BuildDecoys(stunPkt)
	if !ok || len(second) != 5 {
		t.Fatalf("stage 0 retry packet: ok=%v len=%d, want true/5 (no repeated cover)", ok, len(second))
	}
	if _, ok := eng.BuildDecoys(stunPkt); !ok {
		t.Fatal("third packet should match")
	}
	if got := eng.Stats().Strategy; got != "ttl-sweep-quic" {
		t.Fatalf("strategy after 3 packets = %q, want ttl-sweep-quic", got)
	}

	// 4th unanswered packet rotates to stage 1 (badsum-compact).
	fourth, ok := eng.BuildDecoys(stunPkt)
	if !ok || len(fourth) != 5 {
		t.Fatalf("stage 1 first packet: ok=%v len=%d, want true/5", ok, len(fourth))
	}
	if got := eng.Stats().Strategy; got != "badsum-compact" {
		t.Fatalf("strategy after rotation = %q, want badsum-compact", got)
	}

	// Peer's own inbound STUN Binding request (0x0001) must NOT count as a reply.
	peerProbe := buildInboundUDPPacketIPv4(t, "149.154.167.50", 1400, 53000, stunPayload(0x0001, 32))
	if eng.ObserveInbound(peerProbe) {
		t.Fatal("inbound peer STUN request must not count as a reply")
	}

	// Inbound STUN reply (0x0103) on reverse 5-tuple locks the winning strategy.
	reply := buildInboundUDPPacketIPv4(t, "149.154.167.50", 1400, 53000, stunPayload(0x0103, 32))
	if !eng.ObserveInbound(reply) {
		t.Fatal("expected inbound reply on reverse 5-tuple to be recorded")
	}
	for range 5 {
		if _, ok := eng.BuildDecoys(stunPkt); !ok {
			t.Fatal("subsequent packet should match")
		}
	}
	if got := eng.Stats().Strategy; got != "badsum-compact" {
		t.Fatalf("strategy must stay locked after inbound reply, got %q", got)
	}

	// DTLS ClientHello to Telegram CIDR is desynced and counted separately.
	dtlsPkt := buildUDPPacketIPv4(t, "149.154.167.50", 53000, 1400, dtlsClientHelloPayload())
	if pkts, ok := eng.BuildDecoys(dtlsPkt); !ok || len(pkts) < 2 {
		t.Fatalf("DTLS ClientHello should be desynced, ok=%v len=%d", ok, len(pkts))
	}
	st := eng.Stats()
	if st.DTLS != 1 || st.Replies != 1 || st.Targets != 1 {
		t.Fatalf("unexpected stats: %+v", st)
	}

	// Foreign DTLS ClientHello (non-Telegram IP, non-Telegram socket) is ignored.
	foreignDTLS := buildUDPPacketIPv4(t, "203.0.113.77", 53001, 1400, dtlsClientHelloPayload())
	if _, ok := eng.BuildDecoys(foreignDTLS); ok {
		t.Fatal("foreign DTLS ClientHello must not be touched")
	}
}
