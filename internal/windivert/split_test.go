package windivert

import (
	"encoding/binary"
	"testing"
)

func TestSplitPacketBatchIPv4IPv6(t *testing.T) {
	ipv4 := make([]byte, 24)
	ipv4[0] = 0x45
	binary.BigEndian.PutUint16(ipv4[2:4], uint16(len(ipv4)))
	ipv6 := make([]byte, 43)
	ipv6[0] = 0x60
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(len(ipv6)-40))
	batch := append(append([]byte(nil), ipv4...), ipv6...)

	packets, err := splitPacketBatch(batch)
	if err != nil {
		t.Fatalf("splitPacketBatch: %v", err)
	}
	if len(packets) != 2 || len(packets[0]) != len(ipv4) || len(packets[1]) != len(ipv6) {
		t.Fatalf("split lengths = %v, want [%d %d]", packetLengths(packets), len(ipv4), len(ipv6))
	}
}

func TestSplitPacketBatchKeepsValidPacketsBeforeTruncatedTail(t *testing.T) {
	ipv4 := make([]byte, 20)
	ipv4[0] = 0x45
	binary.BigEndian.PutUint16(ipv4[2:4], uint16(len(ipv4)))
	truncatedIPv6 := make([]byte, 41)
	truncatedIPv6[0] = 0x60
	binary.BigEndian.PutUint16(truncatedIPv6[4:6], 10)

	packets, err := splitPacketBatch(append(ipv4, truncatedIPv6...))
	if err == nil {
		t.Fatal("splitPacketBatch accepted a truncated tail")
	}
	if len(packets) != 1 || len(packets[0]) != len(ipv4) {
		t.Fatalf("valid packets before tail = %v, want one %d-byte packet", packetLengths(packets), len(ipv4))
	}
}

func TestSplitPacketBatchZeroLength(t *testing.T) {
	packets, err := splitPacketBatch(nil)
	if err != nil {
		t.Fatalf("splitPacketBatch(nil): %v", err)
	}
	if len(packets) != 0 {
		t.Fatalf("packets = %v, want none", packetLengths(packets))
	}
}

func packetLengths(packets [][]byte) []int {
	lengths := make([]int, len(packets))
	for i, packet := range packets {
		lengths[i] = len(packet)
	}
	return lengths
}
