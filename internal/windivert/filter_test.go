package windivert

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func tcpPacket(dport uint16, flags byte, payload []byte) []byte {
	b := make([]byte, 40+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[9] = 6
	copy(b[12:], []byte{10, 0, 0, 2, 1, 2, 3, 4})
	binary.BigEndian.PutUint16(b[20:], 50000)
	binary.BigEndian.PutUint16(b[22:], dport)
	b[32] = 5 << 4
	b[33] = flags
	copy(b[40:], payload)
	return b
}

func udpPacket(dport uint16, payload []byte) []byte {
	b := make([]byte, 28+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[9] = 17
	copy(b[12:], []byte{10, 0, 0, 2, 1, 2, 3, 4})
	binary.BigEndian.PutUint16(b[20:], 50000)
	binary.BigEndian.PutUint16(b[22:], dport)
	copy(b[28:], payload)
	return b
}

const tcpFilter = "outbound and tcp and (tcp.DstPort == 443 or tcp.DstPort == 8443) and (tcp.PayloadLength > 0 or tcp.Syn or tcp.Fin or tcp.Rst) and not impostor"

func TestFilterMatch(t *testing.T) {
	f, err := ParseFilter(tcpFilter)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"syn", tcpPacket(443, 0x02, nil), true},
		{"data", tcpPacket(8443, 0x18, []byte("x")), true},
		{"bare ack", tcpPacket(443, 0x10, nil), false},
		{"other port", tcpPacket(80, 0x02, nil), false},
		{"udp", udpPacket(443, []byte("x")), false},
	}
	for _, c := range cases {
		if got := f.Match(c.pkt, true); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if f.Match(tcpPacket(443, 0x02, nil), false) {
		t.Error("inbound packet matched an outbound filter")
	}
}

func TestFilterPayloadAndAddr(t *testing.T) {
	f, err := ParseFilter("udp and udp.PayloadLength == 4 and udp.Payload16[0] == 1 and udp.Payload[3] == 70 and ip.DstAddr == 1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	if !f.Match(udpPacket(5000, []byte{0, 1, 0, 70}), true) {
		t.Error("expected match")
	}
	if f.Match(udpPacket(5000, []byte{0, 2, 0, 70}), true) {
		t.Error("unexpected match")
	}
}

func TestFilterOutboundPorts(t *testing.T) {
	f, _ := ParseFilter(tcpFilter)
	if got, want := f.OutboundPorts(true), []PortRange{{443, 443}, {8443, 8443}}; !reflect.DeepEqual(got, want) {
		t.Errorf("tcp: got %v, want %v", got, want)
	}
	if got := f.OutboundPorts(false); len(got) != 0 {
		t.Errorf("udp: got %v", got)
	}
	f, _ = ParseFilter("outbound and udp and udp.DstPort != 443 and udp.PayloadLength == 74 and not impostor")
	if got, want := f.OutboundPorts(false), []PortRange{{0, 442}, {444, 65535}}; !reflect.DeepEqual(got, want) {
		t.Errorf("udp: got %v, want %v", got, want)
	}
	f, _ = ParseFilter("false")
	if got := f.OutboundPorts(true); len(got) != 0 {
		t.Errorf("false: got %v", got)
	}
}

func TestFilterRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "tcp and", "(tcp", "tcp.Nope == 1", "tcp.DstPort", "ip.DstAddr == x"} {
		if _, err := ParseFilter(s); err == nil {
			t.Errorf("%q: expected an error", s)
		}
	}
}
