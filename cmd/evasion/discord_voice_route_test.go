package main

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/fitting-1c/evasion/internal/netbind"
)

func TestVoiceRouterRoutesNetworkOnceLearnsAndCleansUp(t *testing.T) {
	adapter := netbind.Adapter{Index: 7, Name: "Ethernet", GatewayIP: netip.MustParseAddr("192.168.0.1"), Metric: 25}
	dir := t.TempDir()
	newRouter := func() (*voiceRouter, *[]netbind.HostRoute, *[]netbind.HostRoute) {
		router := newVoiceRouter(adapter, slog.New(slog.NewTextHandler(io.Discard, nil)))
		router.journal = filepath.Join(dir, "voice-routes.txt")
		router.learned = filepath.Join(dir, "voice-networks.txt")
		var added, removed []netbind.HostRoute
		router.add = func(r netbind.HostRoute) error { added = append(added, r); return nil }
		router.remove = func(r netbind.HostRoute) error { removed = append(removed, r); return nil }
		return router, &added, &removed
	}
	router, added, removed := newRouter()

	// Два сервера одной сети — один маршрут на всю /24.
	if !router.Route(netip.MustParseAddr("104.29.136.176")) || !router.Route(netip.MustParseAddr("104.29.136.216")) {
		t.Fatal("маршрут до голосового сервера должен стоять")
	}
	for _, bad := range []string{"198.18.0.42", "10.0.0.5", "127.0.0.1"} {
		if router.Route(netip.MustParseAddr(bad)) {
			t.Fatalf("маршрут на служебный адрес %s", bad)
		}
	}
	want := netbind.HostRoute{Dest: netip.MustParsePrefix("104.29.136.0/24"), Gateway: adapter.GatewayIP, IfIndex: 7, Metric: 25}
	if len(*added) != 1 || (*added)[0] != want {
		t.Fatalf("поставлено %v, ожидался один маршрут %v", *added, want)
	}
	if got := want.Mask().String(); got != "255.255.255.0" {
		t.Fatalf("маска %s", got)
	}

	// Движок убит: следующий запуск снимает маршрут по журналу, а известную
	// сеть ставит заранее, до первого пакета голоса.
	next, nextAdded, nextRemoved := newRouter()
	next.removeStale()
	if len(*nextRemoved) != 1 || (*nextRemoved)[0] != want {
		t.Fatalf("по журналу снято %v", *nextRemoved)
	}
	next.Preload()
	if len(*nextAdded) != 1 || (*nextAdded)[0] != want {
		t.Fatalf("заранее поставлено %v", *nextAdded)
	}
	*nextRemoved = nil
	next.Close()
	if len(*nextRemoved) != 1 || (*nextRemoved)[0] != want {
		t.Fatalf("при остановке снято %v", *nextRemoved)
	}
	if _, err := os.Stat(next.journal); !os.IsNotExist(err) {
		t.Fatalf("журнал маршрутов должен быть удалён: %v", err)
	}
	_ = removed
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
