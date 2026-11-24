package inbound

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/hops"
	"github.com/fitting-1c/evasion/internal/packet"
)

func inboundPacket(version uint8, flags, ttl uint8, dir core.Direction) capture.Packet {
	ipLen := 20
	if version == 6 {
		ipLen = 40
	}
	buf := make([]byte, ipLen+20)
	if version == 4 {
		buf[0] = 0x45
		binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
		buf[8], buf[9] = ttl, byte(packet.ProtoTCP)
		copy(buf[12:16], []byte{203, 0, 113, 9})
		copy(buf[16:20], []byte{192, 0, 2, 10})
	} else {
		buf[0] = 0x60
		binary.BigEndian.PutUint16(buf[4:6], 20)
		buf[6], buf[7] = byte(packet.ProtoTCP), ttl
		copy(buf[8:24], netip.MustParseAddr("2001:db8::9").AsSlice())
		copy(buf[24:40], netip.MustParseAddr("2001:db8::10").AsSlice())
	}
	binary.BigEndian.PutUint16(buf[ipLen:ipLen+2], 443)
	binary.BigEndian.PutUint16(buf[ipLen+2:ipLen+4], 50000)
	buf[ipLen+12], buf[ipLen+13] = 0x50, flags
	return capture.Packet{Data: buf, Dir: dir}
}

func TestRunObservesSYNACKAndRST(t *testing.T) {
	table := hops.NewTable(8, time.Minute)
	var gotRemote netip.AddrPort
	var gotLocal uint16
	rstCount := 0
	source := capture.NewSyntheticSource(
		inboundPacket(4, packet.FlagSYN|packet.FlagACK, 56, core.DirectionInbound),
		inboundPacket(6, packet.FlagSYN|packet.FlagACK, 60, core.DirectionInbound),
		inboundPacket(4, packet.FlagRST|packet.FlagACK, 40, core.DirectionInbound),
		inboundPacket(4, packet.FlagACK, 40, core.DirectionInbound),
		inboundPacket(4, packet.FlagRST, 40, core.DirectionOutbound),
	)
	if err := Run(context.Background(), source, table, func(remote netip.AddrPort, localPort uint16) {
		rstCount++
		gotRemote, gotLocal = remote, localPort
	}); err != nil {
		t.Fatal(err)
	}
	if got, ok := table.Hops(netip.MustParseAddr("203.0.113.9")); !ok || got != 8 {
		t.Fatalf("IPv4 SYN-ACK observation = %d, %v; want 8, true", got, ok)
	}
	if got, ok := table.Hops(netip.MustParseAddr("2001:db8::9")); !ok || got != 4 {
		t.Fatalf("IPv6 SYN-ACK observation = %d, %v; want 4, true", got, ok)
	}
	if rstCount != 1 || gotRemote != netip.MustParseAddrPort("203.0.113.9:443") || gotLocal != 50000 {
		t.Fatalf("RST callback = (%s, %d), count %d", gotRemote, gotLocal, rstCount)
	}
}

func TestRunNilSafeAndReturnsSourceError(t *testing.T) {
	if err := Run(context.Background(), capture.NewSyntheticSource(inboundPacket(4, packet.FlagSYN|packet.FlagACK, 56, core.DirectionInbound)), nil, nil); err != nil {
		t.Fatalf("nil table/callback: %v", err)
	}
}
