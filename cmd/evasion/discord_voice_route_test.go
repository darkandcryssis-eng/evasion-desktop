package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/fitting-1c/evasion/internal/capture"
	"github.com/fitting-1c/evasion/internal/core"
	"github.com/fitting-1c/evasion/internal/netbind"
	"github.com/fitting-1c/evasion/internal/packet"
	"github.com/fitting-1c/evasion/internal/windivert"
)

func TestVoiceRouterAddsOnceSkipsFakeAndCleansUp(t *testing.T) {
	adapter := netbind.Adapter{Index: 7, Name: "Ethernet", GatewayIP: netip.MustParseAddr("192.168.0.1"), Metric: 25}
	router := newVoiceRouter(adapter, slog.New(slog.NewTextHandler(io.Discard, nil)))
	router.journal = filepath.Join(t.TempDir(), "voice-routes.txt")
	var added, removed []netbind.HostRoute
	router.add = func(r netbind.HostRoute) error { added = append(added, r); return nil }
	router.remove = func(r netbind.HostRoute) error { removed = append(removed, r); return nil }

	server := netip.MustParseAddr("66.22.197.10")
	if !router.Route(server) || !router.Route(server) {
		t.Fatal("маршрут до голосового сервера должен стоять")
	}
	for _, bad := range []string{"198.18.0.42", "10.0.0.5", "127.0.0.1"} {
		if router.Route(netip.MustParseAddr(bad)) {
			t.Fatalf("маршрут на служебный адрес %s", bad)
		}
	}
	want := netbind.HostRoute{Dest: server, Gateway: adapter.GatewayIP, IfIndex: 7, Metric: 25}
	if len(added) != 1 || added[0] != want {
		t.Fatalf("поставлено %v, ожидался один маршрут %v", added, want)
	}
	// Движок убит: следующий запуск снимает маршрут по журналу.
	removed = nil
	router.removeStale()
	if len(removed) != 1 || removed[0] != want {
		t.Fatalf("по журналу снято %v", removed)
	}
	if _, err := os.Stat(router.journal); !os.IsNotExist(err) {
		t.Fatalf("журнал маршрутов должен быть удалён: %v", err)
	}
	removed = nil
	router.Close()
	if len(removed) != 1 || removed[0] != want {
		t.Fatalf("снято %v", removed)
	}
}

func TestParseVoiceDiscovery(t *testing.T) {
	payload := make([]byte, 74)
	payload[1], payload[3] = 1, 70
	pkt := udpPacketV4(netip.MustParseAddrPort("172.19.0.1:50555"), netip.MustParseAddrPort("66.22.197.10:50004"), payload)
	event, ok := parseVoiceDiscovery(pkt)
	if !ok || event.response || event.src.String() != "172.19.0.1:50555" || event.dst.String() != "66.22.197.10:50004" {
		t.Fatalf("запрос: %+v ok=%v", event, ok)
	}
	payload[1] = 2
	pkt = udpPacketV4(netip.MustParseAddrPort("66.22.197.10:50004"), netip.MustParseAddrPort("192.168.0.180:50555"), payload)
	if event, ok = parseVoiceDiscovery(pkt); !ok || !event.response {
		t.Fatalf("ответ: %+v ok=%v", event, ok)
	}
	if _, ok = parseVoiceDiscovery(udpPacketV4(netip.MustParseAddrPort("1.1.1.1:1"), netip.MustParseAddrPort("2.2.2.2:2"), []byte("short"))); ok {
		t.Fatal("посторонний UDP принят за IP discovery")
	}
}

func udpPacketV4(src, dst netip.AddrPort, payload []byte) []byte {
	buf := make([]byte, 28+len(payload))
	buf[0] = 0x45
	buf[2], buf[3] = byte(len(buf)>>8), byte(len(buf))
	buf[8], buf[9] = 64, 17
	s, d := src.Addr().As4(), dst.Addr().As4()
	copy(buf[12:16], s[:])
	copy(buf[16:20], d[:])
	buf[20], buf[21] = byte(src.Port()>>8), byte(src.Port())
	buf[22], buf[23] = byte(dst.Port()>>8), byte(dst.Port())
	udpLen := 8 + len(payload)
	buf[24], buf[25] = byte(udpLen>>8), byte(udpLen)
	copy(buf[28:], payload)
	return buf
}

func TestIsDiscordVoiceHost(t *testing.T) {
	for host, want := range map[string]bool{
		"c-arn09-513e6835.discord.media": true,
		"LATENCY.discord.media.":         true,
		"discord.media":                  false,
		"gateway.discord.gg":             false,
		"discord.media.example.com":      false,
	} {
		if got := isDiscordVoiceHost(host); got != want {
			t.Errorf("%s: %v", host, got)
		}
	}
}

func TestRedirectVoiceDiscoveryRewritesSourceAndKeepsRequestLast(t *testing.T) {
	payload := make([]byte, 74)
	payload[1], payload[3] = 1, 70
	raw := udpPacketV4(netip.MustParseAddrPort("172.19.0.1:50555"), netip.MustParseAddrPort("104.29.153.203:19304"), payload)
	d, err := packet.Dissect(raw)
	if err != nil || !d.RecomputeChecksums(raw) {
		t.Fatalf("шаблон: %v", err)
	}
	var tunnel windivert.Address
	tunnel = tunnel.WithInterface(31)
	physical := netbind.Adapter{Index: 7, Addr: netip.MustParseAddr("192.168.0.180")}
	out := redirectVoiceDiscovery(capture.Packet{Data: raw, Dir: core.DirectionOutbound, Reinject: tunnel}, physical)
	if len(out) != 3*voiceDecoyRepeats+1 {
		t.Fatalf("пакетов %d, ожидалось %d", len(out), 3*voiceDecoyRepeats+1)
	}
	last := out[len(out)-1]
	event, ok := parseVoiceDiscovery(last.Data)
	if !ok || event.response || event.src.String() != "192.168.0.180:50555" || event.dst.String() != "104.29.153.203:19304" {
		t.Fatalf("настоящий запрос должен идти последним от адреса адаптера: %+v ok=%v", event, ok)
	}
	fixed := append([]byte(nil), last.Data...)
	ld, _ := packet.Dissect(last.Data)
	if !ld.RecomputeChecksums(fixed) || !bytes.Equal(fixed, last.Data) {
		t.Fatal("суммы перенаправленного запроса неверны")
	}
	for i, p := range out {
		if addr := p.Reinject.(windivert.Address); addr.IfIdx() != 7 {
			t.Fatalf("пакет %d уйдёт не через физический адаптер: ifIdx=%d", i, addr.IfIdx())
		}
	}
	if got := redirectVoiceDiscovery(capture.Packet{Data: raw, Dir: core.DirectionOutbound, Reinject: tunnel}, netbind.Adapter{Index: 7}); got != nil {
		t.Fatal("без адреса адаптера перенаправлять нельзя")
	}
}
