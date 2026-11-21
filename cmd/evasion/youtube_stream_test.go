package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/flow"
	"github.com/fitting-1c/evasion/internal/intercept"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/packetexec"
	"github.com/fitting-1c/evasion/internal/proxy"
	"github.com/fitting-1c/evasion/internal/youtubetune"
)

func streamHello(name string, lead, trail int) []byte {
	ext := func(typ uint16, data []byte) []byte {
		b := binary.BigEndian.AppendUint16(nil, typ)
		b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
		return append(b, data...)
	}
	entry := []byte{0}
	entry = binary.BigEndian.AppendUint16(entry, uint16(len(name)))
	entry = append(entry, name...)
	sni := append(binary.BigEndian.AppendUint16(nil, uint16(len(entry))), entry...)
	mk := func(n int, seed byte) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = seed + byte(i*7)
		}
		return b
	}
	var exts []byte
	if lead > 0 {
		exts = append(exts, ext(21, mk(lead, 3))...)
	}
	exts = append(exts, ext(0, sni)...)
	if trail > 0 {
		exts = append(exts, ext(0xfe0d, mk(trail, 9))...)
	}
	body := binary.BigEndian.AppendUint16(nil, 0x0303)
	body = append(body, mk(32, 1)...)
	body = append(body, 32)
	body = append(body, mk(32, 2)...)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, 0x13, 0x01, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func streamPacket(t *testing.T, payload []byte, seq uint32) capture.Packet {
	buf := make([]byte, 40+len(payload))
	buf[0] = 0x45
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(buf)))
	buf[8], buf[9] = 64, 6
	copy(buf[12:16], net.ParseIP("10.0.0.1").To4())
	copy(buf[16:20], net.ParseIP("142.250.1.1").To4())
	binary.BigEndian.PutUint16(buf[20:22], 50000)
	binary.BigEndian.PutUint16(buf[22:24], 443)
	binary.BigEndian.PutUint32(buf[24:28], seq)
	buf[32], buf[33] = 0x50, 0x18
	binary.BigEndian.PutUint16(buf[34:36], 65535)
	copy(buf[40:], payload)
	d, err := packet.Dissect(buf)
	if err != nil || !d.RecomputeChecksums(buf) {
		t.Fatal("pkt")
	}
	return capture.Packet{Data: buf, Dir: core.DirectionOutbound}
}

type sel struct{ s proxy.Selection }

func (p sel) Select(m proxy.ConnMeta) proxy.Selection { return p.s }

// streamReceive — модель серверного TCP: байты по порядку принимаются сразу,
// сегмент с опережением ждёт в очереди и принимается, как только поток до него
// дошёл; уже принятые байты не перезаписываются. Фейки с seq вне окна и с
// неверной суммой отбрасываются, как на настоящем сервере.
func streamReceive(sent []capture.Packet, start uint32, total int) (out []byte, maxPay int, note string) {
	type seg struct {
		off int
		b   []byte
	}
	var ofo []seg
	deliver := func(off int, b []byte) bool {
		if off > len(out) || off+len(b) <= len(out) {
			return off <= len(out)
		}
		out = append(out, b[len(out)-off:]...)
		return true
	}
	for i, p := range sent {
		d, err := packet.Dissect(p.Data)
		if err != nil {
			note += fmt.Sprintf(" bad#%d", i)
			continue
		}
		if !d.VerifyChecksums(p.Data) {
			note += " badsum"
			continue
		}
		th, _ := d.TCP(p.Data)
		pay, _ := d.Payload(p.Data)
		if len(pay) > maxPay {
			maxPay = len(pay)
		}
		off := int(int32(th.Seq() - start))
		if off < 0 && off+len(pay) > 0 {
			note += " headtrim"
			pay, off = pay[-off:], 0
		}
		if off < 0 || off >= total+2000 {
			note += " oow"
			continue
		}
		if p.Data[8] < 20 {
			note += fmt.Sprintf(" ttl%d", p.Data[8])
			continue
		}
		if !deliver(off, pay) {
			ofo = append(ofo, seg{off, append([]byte{}, pay...)})
		}
		for again := true; again; {
			again = false
			for j, s := range ofo {
				if s.off <= len(out) {
					deliver(s.off, s.b)
					ofo = append(ofo[:j], ofo[j+1:]...)
					again = true
					break
				}
			}
		}
	}
	note += fmt.Sprintf(" pkts=%d maxpay=%d", len(sent), maxPay)
	return
}

// TestYouTubeProfilesKeepStreamAndMTU прогоняет каждый профиль YouTube через
// движок на ClientHello разной формы (короткий, одиночный, 2–3 сегмента как у
// Chrome с постквантовым обменом) и проверяет две вещи: сервер собирает ровно
// исходный ClientHello, и ни один пакет не крупнее исходного сегмента — иначе
// он не пролез бы в MTU и рукопожатие зависло бы.
func TestYouTubeProfilesKeepStreamAndMTU(t *testing.T) {
	names := append([]string{}, youtubetune.Profiles[1:]...)
	type hc struct {
		label       string
		lead, trail int
		cuts        []int
	}
	cases := []hc{
		{"short300", 0, 180, nil},
		{"single1200", 300, 760, nil},
		{"2seg-sni-in-1st", 400, 1300, []int{1460}},
		{"2seg-sni-in-2nd", 1500, 200, []int{1460}},
		{"2seg-sni-straddle", 1395, 300, []int{1460}},
		{"3seg-sni-in-3rd", 3000, 100, []int{1460, 2920}},
		{"3seg-sni-in-1st", 100, 3100, []int{1460, 2920}},
	}
	for _, host := range []string{"www.youtube.com", "rr3---sn-4g5e6nsz.googlevideo.com", "i.ytimg.com"} {
		for _, c := range cases {
			full := streamHello(host, c.lead, c.trail)
			for _, name := range names {
				s, err := youtubetune.Profile(name, nil)
				if err != nil {
					t.Fatal(err)
				}
				st, _ := proxy.NewStaticProvider(s)
				const start = uint32(4294966000) // переход seq через 2^32
				var pk []capture.Packet
				prev, prevMax := 0, 0
				for _, cut := range append(append([]int{}, c.cuts...), len(full)) {
					pk = append(pk, streamPacket(t, full[prev:cut], start+uint32(prev)))
					prevMax = max(prevMax, cut-prev)
					prev = cut
				}
				sink := &capture.SyntheticSink{}
				e, err := intercept.New(intercept.Options{Source: capture.NewSyntheticSource(pk...), Sink: sink,
					Flows: flow.NewTable(16, time.Minute, intercept.TLSHelloDetector), Provider: sel{st.Select(proxy.ConnMeta{})},
					Exec: packetexec.New(), Parse: intercept.TLSHelloParser})
				if err != nil {
					t.Fatal(err)
				}
				if err := e.Run(context.Background()); err != nil {
					t.Fatal(err)
				}
				got, maxPay, note := streamReceive(sink.Sent(), start, len(full))
				if !bytes.Equal(got, full) {
					t.Errorf("%s %s %s: сервер собрал не тот ClientHello (%d из %d байт):%s", host, c.label, name, len(got), len(full), note)
				}
				if limit := max(prevMax, 682); maxPay > limit {
					t.Errorf("%s %s %s: пакет %d байт крупнее исходного сегмента %d:%s", host, c.label, name, maxPay, limit, note)
				}
			}
		}
	}
}
