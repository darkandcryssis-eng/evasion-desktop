package tunnel

import (
	"crypto/rand"
	"encoding/binary"

	"golang.zx2c4.com/wireguard/conn"
)

const (
	wgHandshakeInitiationLen  = 148
	wgHandshakeInitiationType = 1
	wgJunkMinLen              = 40
	wgJunkMaxLen              = 90
)

// junkBind wraps a WireGuard conn.Bind and emits AmneziaWG-style random UDP
// junk packets from the same bound socket right before each WireGuard
// Handshake Initiation. Cloudflare WARP endpoints silently drop non-WG packets,
// while stateful DPI filters that match the 148-byte 01 00 00 00 flow opening
// lose the signature.
type junkBind struct {
	conn.Bind
	junkCount int
}

func newJunkBind(inner conn.Bind, junkCount int) conn.Bind {
	if junkCount <= 0 {
		return inner
	}
	return &junkBind{Bind: inner, junkCount: junkCount}
}

func isWGHandshakeInitiation(pkt []byte) bool {
	return len(pkt) == wgHandshakeInitiationLen &&
		pkt[0] == wgHandshakeInitiationType &&
		pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0
}

func (b *junkBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	hasInit := false
	for _, pkt := range bufs {
		if isWGHandshakeInitiation(pkt) {
			hasInit = true
			break
		}
	}
	if hasInit {
		for range b.junkCount {
			junk := buildWGJunkPacket()
			if err := b.Bind.Send([][]byte{junk}, ep); err != nil {
				break
			}
		}
	}
	return b.Bind.Send(bufs, ep)
}

func buildWGJunkPacket() []byte {
	var lenBuf [2]byte
	_, _ = rand.Read(lenBuf[:])
	span := wgJunkMaxLen - wgJunkMinLen + 1
	n := wgJunkMinLen + int(binary.LittleEndian.Uint16(lenBuf[:]))%span
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	// Avoid WireGuard message types 0x01..0x04 so the peer discards it cleanly.
	buf[0] = 0x10 + (buf[0] % 0xE0)
	return buf
}
