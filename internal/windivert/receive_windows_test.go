//go:build windows

package windivert

import (
	"encoding/binary"
	"testing"

	"github.com/fitting-1c/evasion/internal/packet"
)

func TestReceiveBufferFitsMaximumIPv6Packet(t *testing.T) {
	// IPv6 payload length excludes its 40-byte header (RFC 8200).
	frame := make([]byte, 40+65535)
	frame[0], frame[6], frame[7] = 0x60, 6, 64
	binary.BigEndian.PutUint16(frame[4:6], 65535)
	frame[40+12] = 5 << 4
	buffer := make([]byte, maxPacketLen)
	n := copy(buffer, frame)
	if n != len(frame) {
		t.Fatalf("valid IPv6 packet truncated: %d of %d bytes", n, len(frame))
	}
	if _, err := packet.Dissect(buffer[:n]); err != nil {
		t.Fatal(err)
	}
}
