package main

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/fitting-1c/evasion/internal/netbind"
)

func TestVoiceRouterAddsOnceSkipsFakeAndCleansUp(t *testing.T) {
	adapter := netbind.Adapter{Index: 7, Name: "Ethernet", GatewayIP: netip.MustParseAddr("192.168.0.1"), Metric: 25}
	router := newVoiceRouter(adapter, slog.New(slog.NewTextHandler(io.Discard, nil)))
	answers := map[string][]netip.Addr{
		"c-ams19-ef84a7d7.discord.media": {netip.MustParseAddr("66.22.197.10")},
		"c-fake.discord.media":           {netip.MustParseAddr("198.18.0.42"), netip.MustParseAddr("10.0.0.5")},
	}
	router.resolve = func(_ context.Context, host string) ([]netip.Addr, error) { return answers[host], nil }
	var added, removed []netbind.HostRoute
	router.add = func(r netbind.HostRoute) error { added = append(added, r); return nil }
	router.remove = func(r netbind.HostRoute) error { removed = append(removed, r); return nil }

	router.Ensure(context.Background(), "c-ams19-ef84a7d7.discord.media")
	router.Ensure(context.Background(), "c-ams19-ef84a7d7.discord.media")
	router.Ensure(context.Background(), "c-fake.discord.media")
	want := netbind.HostRoute{Dest: netip.MustParseAddr("66.22.197.10"), Gateway: adapter.GatewayIP, IfIndex: 7, Metric: 25}
	if len(added) != 1 || added[0] != want {
		t.Fatalf("поставлено %v, ожидался один маршрут %v", added, want)
	}
	router.Close()
	if len(removed) != 1 || removed[0] != want {
		t.Fatalf("снято %v", removed)
	}
}

func TestIsDiscordVoiceHost(t *testing.T) {
	for host, want := range map[string]bool{
		"c-arn02-4b385db9.discord.media": true,
		"LATENCY.discord.media.":         true,
		"discord.media":                  false,
		"gateway.discord.gg":             false,
		"evil-discord.media.example.com": false,
	} {
		if got := isDiscordVoiceHost(host); got != want {
			t.Errorf("%s: %v", host, got)
		}
	}
}
