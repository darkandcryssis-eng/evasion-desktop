package intercept

import (
	"encoding/binary"
	"testing"

	"github.com/fitting-1c/evasion/internal/capture"
)

func TestPacketTargetMetadataIsOptIn(t *testing.T) {
	b := make([]byte, 40)
	b[0] = 0x45
	b[8] = 64
	b[9] = 6
	b[32] = 0x50
	binary.BigEndian.PutUint16(b[2:4], 40)
	binary.BigEndian.PutUint16(b[22:24], 443)
	copy(b[16:20], []byte{1, 1, 1, 1})
	p := capture.Packet{Data: b}
	plain := (&Engine{}).packetConnMeta(p, "game.example", 45000, 1200)
	if plain.Host != "" || plain.Port != 0 || plain.PayloadLength != 0 || plain.LocalPort != 45000 {
		t.Fatal("default metadata changed", plain)
	}
	game := (&Engine{includePacketMetadata: true}).packetConnMeta(p, "game.example", 45000, 1200)
	if game.Host != "1.1.1.1" || game.Port != 443 || game.PayloadLength != 1200 || game.SNI != "game.example" {
		t.Fatal("game metadata missing", game)
	}
}
