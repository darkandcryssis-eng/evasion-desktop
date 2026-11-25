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

func (s stubTelegramOwner) OwnsUDP(port uint16) bool { return s.ports[port] }

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
