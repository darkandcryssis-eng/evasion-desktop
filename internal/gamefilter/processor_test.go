package gamefilter

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/windivert"
)

type testOwner bool

func (o testOwner) Owns(string, uint16) bool { return bool(o) }

type testSink struct {
	sent []capture.Packet
	err  error
}

func (s *testSink) Send(p capture.Packet) error {
	s.sent = append(s.sent, capture.Packet{Data: append([]byte(nil), p.Data...), Dir: p.Dir, Reinject: p.Reinject})
	return s.err
}
func testPacket(t *testing.T, tcp, ipv6 bool) capture.Packet {
	t.Helper()
	ip, transport := 20, 8
	if ipv6 {
		ip = 40
	}
	if tcp {
		transport = 20
	}
	b := make([]byte, ip+transport+80)
	if ipv6 {
		b[0] = 0x60
		binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40))
		b[6] = 17
		b[7] = 64
		copy(b[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
		copy(b[24:40], netip.MustParseAddr("2606:4700:4700::1111").AsSlice())
		if tcp {
			b[6] = 6
		}
	} else {
		b[0] = 0x45
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		b[8] = 64
		b[9] = 17
		copy(b[12:16], []byte{10, 0, 0, 1})
		copy(b[16:20], []byte{1, 1, 1, 1})
		if tcp {
			b[9] = 6
		}
	}
	binary.BigEndian.PutUint16(b[ip:ip+2], 45000)
	binary.BigEndian.PutUint16(b[ip+2:ip+4], 5055)
	if tcp {
		binary.BigEndian.PutUint32(b[ip+4:ip+8], 100000)
		b[ip+12] = 0x50
		b[ip+13] = packet.FlagACK | packet.FlagPSH
	} else {
		binary.BigEndian.PutUint16(b[ip+4:ip+6], uint16(8+80))
	}
	for i := ip + transport; i < len(b); i++ {
		b[i] = 0x5a
	}
	d, err := packet.Dissect(b)
	if err != nil || !d.RecomputeChecksums(b) {
		t.Fatal("invalid fixture", err)
	}
	var address windivert.Address
	return capture.Packet{Data: b, Dir: core.DirectionOutbound, Reinject: address}
}

func TestSelectedGameDecoysPreserveOriginal(t *testing.T) {
	for _, mode := range []string{"gentle", "balanced", "strong"} {
		for _, tcp := range []bool{false, true} {
			for _, ipv6 := range []bool{false, true} {
				t.Run(mode+map[bool]string{true: "/tcp", false: "/udp"}[tcp]+map[bool]string{true: "/v6", false: "/v4"}[ipv6], func(t *testing.T) {
					o := Default()
					o.Mode = mode
					p := New(o, testOwner(true))
					pkt := testPacket(t, tcp, ipv6)
					original := append([]byte(nil), pkt.Data...)
					metadata := pkt.Reinject
					sink := &testSink{}
					p.Before(pkt, sink)
					_, repeats := o.Limits()
					if len(sink.sent) != repeats {
						t.Fatalf("sent=%d want=%d", len(sink.sent), repeats)
					}
					if !bytes.Equal(pkt.Data, original) || pkt.Reinject != metadata {
						t.Fatal("original mutated")
					}
					d, _ := packet.Dissect(pkt.Data)
					if !d.VerifyChecksums(pkt.Data) {
						t.Fatal("original checksum invalid")
					}
					for _, fake := range sink.sent {
						fd, _ := packet.Dissect(fake.Data)
						if tcp {
							h, _ := fd.TCP(fake.Data)
							if h.Seq() != 90000 || !fd.VerifyChecksums(fake.Data) {
								t.Fatal("unsafe TCP fake")
							}
						} else {
							h, _ := fd.UDP(fake.Data)
							if h.Checksum() == 0 || fd.VerifyChecksums(fake.Data) {
								t.Fatal("UDP fake can be accepted")
							}
						}
						payload, _ := fd.Payload(fake.Data)
						real, _ := d.Payload(pkt.Data)
						if bytes.Equal(payload, real) {
							t.Fatal("client data copied into fake")
						}
						addr := fake.Reinject.(windivert.Address)
						if tcp && addr[10]&0x60 != 0x60 || !tcp && addr[10]&0xa0 != 0xa0 {
							t.Fatal("checksum metadata missing")
						}
					}
				})
			}
		}
	}
}

func TestOffUnselectedAndPrivateTrafficPassThrough(t *testing.T) {
	for _, name := range []string{"off", "unselected", "inbound", "private", "cgnat", "quic", "truncated", "fragment", "protocol", "metadata", "tls", "syn"} {
		t.Run(name, func(t *testing.T) {
			o := Default()
			o.Mode = "balanced"
			owner := true
			tcp := name == "tls" || name == "syn"
			pkt := testPacket(t, tcp, false)
			d, _ := packet.Dissect(pkt.Data)
			switch name {
			case "off":
				o.Mode = "off"
			case "unselected":
				owner = false
			case "inbound":
				pkt.Dir = core.DirectionInbound
			case "private":
				copy(pkt.Data[16:20], []byte{192, 168, 1, 1})
			case "cgnat":
				copy(pkt.Data[16:20], []byte{100, 64, 0, 1})
			case "quic":
				binary.BigEndian.PutUint16(pkt.Data[d.L4Off+2:d.L4Off+4], 443)
			case "truncated":
				pkt.Data = pkt.Data[:len(pkt.Data)-2]
			case "fragment":
				h, _ := d.IPv4(pkt.Data)
				h.SetFlags(1)
			case "protocol":
				o.Protocol = "tcp"
			case "metadata":
				pkt.Reinject = nil
			case "tls":
				pkt.Data[d.PayloadOff] = 22
			case "syn":
				pkt.Data[d.L4Off+13] = packet.FlagSYN
			}
			original := append([]byte(nil), pkt.Data...)
			sink := &testSink{}
			New(o, testOwner(owner)).Before(pkt, sink)
			if len(sink.sent) != 0 || !bytes.Equal(pkt.Data, original) {
				t.Fatal("out-of-scope packet modified")
			}
		})
	}
}

func TestCutoffRateLimitAndExpiry(t *testing.T) {
	o := Default()
	o.Mode = "balanced"
	p := New(o, testOwner(true))
	now := time.Now()
	p.Now = func() time.Time { return now }
	p.refilled = now
	pkt := testPacket(t, false, false)
	sink := &testSink{}
	for range 100 {
		p.Before(pkt, sink)
	}
	if len(sink.sent) != 6 {
		t.Fatal("cutoff failed", len(sink.sent))
	}
	now = now.Add(6 * time.Minute)
	p.Before(pkt, sink)
	if len(sink.sent) != 9 {
		t.Fatal("idle flow not reset")
	}
	for i := 0; i < 100; i++ {
		binary.BigEndian.PutUint16(pkt.Data[20:22], uint16(30000+i))
		p.Before(pkt, sink)
	}
	if len(sink.sent) > 69 || p.Stats().Limited == 0 {
		t.Fatal("global budget exceeded", len(sink.sent))
	}
	for i := 0; i < 8192; i++ {
		p.flows[flowKey{local: netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), uint16(i))}] = entry{last: now}
	}
	count := len(p.flows)
	binary.BigEndian.PutUint16(pkt.Data[20:22], 65000)
	p.Before(pkt, sink)
	if len(p.flows) != count {
		t.Fatal("flow bound exceeded")
	}
}

func TestTLSBudgetDecisionIsStableForReassembly(t *testing.T) {
	o := Default()
	o.Mode = "balanced"
	p := New(o, testOwner(true))
	now := time.Now()
	p.Now = func() time.Time { return now }
	p.refilled = now
	for range 100 {
		if !p.AllowTLS(45000, "1.1.1.1", 443) {
			t.Fatal("same ClientHello charged twice")
		}
	}
	if p.Stats().Connections != 1 || p.Stats().TCP != 1 {
		t.Fatal("TLS counted twice")
	}
	allowed := 0
	for i := 1; i < 100; i++ {
		if p.AllowTLS(uint16(45000+i), "1.1.1.1", 443) {
			allowed++
		}
	}
	if allowed > 31 || p.AllowTLS(45000, "192.168.1.1", 443) {
		t.Fatal("TLS budget or private scope failed")
	}
}

func TestSendFailureDoesNotMutateOriginal(t *testing.T) {
	o := Default()
	o.Mode = "strong"
	p := New(o, testOwner(true))
	pkt := testPacket(t, false, false)
	before := append([]byte(nil), pkt.Data...)
	p.Before(pkt, &testSink{err: errors.New("send failed")})
	if !bytes.Equal(before, pkt.Data) || p.Stats().Errors != 6 {
		t.Fatal("send failure altered original or counters")
	}
}

func TestOwnerAmbiguityAndTableBounds(t *testing.T) {
	rows := []socketRow{{"udp", 5055, 1}, {"udp", 5055, 2}, {"tcp", 45000, 1}, {"tcp", 45000, 1}}
	owners := resolveRows(rows, map[uint32]string{1: "albion"})
	if owners[ownerKey("udp", 5055)].selected || !owners[ownerKey("tcp", 45000)].selected {
		t.Fatal("ambiguous process accepted")
	}
	for _, b := range [][]byte{nil, {1, 0, 0, 0}, {255, 255, 255, 255}} {
		if _, err := decodeRows(b, "udp", false); err == nil {
			t.Fatal("corrupt table accepted")
		}
	}
}

func TestOptionsAndTargetMatching(t *testing.T) {
	o := Default()
	o.Mode = "balanced"
	for image, want := range map[string]string{`C:\Games\Albion\Albion-Online.exe`: "albion", `C:\Games\Albion\launch_albion_online.exe`: "albion", `C:\Ubisoft\upc.exe`: "ubisoft", `C:\Windows\AlbionLauncher.exe`: "", `C:\Apps\chrome.exe`: "", `C:\Games\not-albion-online.exe`: ""} {
		if got := o.Match(image); got != want {
			t.Fatalf("%s=%s want=%s", image, got, want)
		}
	}
	for _, mode := range []string{"off", "gentle", "balanced", "strong"} {
		o.Mode = mode
		if err := o.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	o.Mode = "invalid"
	if o.Validate() == nil {
		t.Fatal("bad mode accepted")
	}
	o = Default()
	o.Mode = "balanced"
	o.Albion = false
	o.Ubisoft = false
	if o.Validate() == nil {
		t.Fatal("empty target scope accepted")
	}
	for _, ip := range []string{"127.0.0.1", "192.168.1.1", "100.64.0.1", "::1", "fe80::1", "fc00::1", "224.0.0.1"} {
		if Public(netip.MustParseAddr(ip)) {
			t.Fatal("non-public destination accepted", ip)
		}
	}
}
