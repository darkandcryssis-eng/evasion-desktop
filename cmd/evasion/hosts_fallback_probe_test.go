package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fitting-1c/evasion/internal/config"
)

func TestSelectHealthyTransportFallbackUsesFirstSuccessfulInConfiguredOrder(t *testing.T) {
	fallback := config.TransportFallback{Enabled: true, Entries: []config.TransportFallbackEntry{{
		SafeIP:  "192.0.2.1",
		SafeIPs: []string{"192.0.2.2", "192.0.2.3", "192.0.2.1"},
		Domains: []string{"gateway.example.org", "media.example.org"},
	}}}
	started := make(chan string, 3)
	release := make(chan struct{})
	done := make(chan config.TransportFallback, 1)
	go func() {
		selected, _ := selectHealthyTransportFallback(context.Background(), fallback, func(_ context.Context, ip, sni string) error {
			if sni != fallback.Entries[0].Domains[0] {
				t.Errorf("TLS ServerName = %q", sni)
			}
			started <- ip
			<-release
			if ip == "192.0.2.1" {
				return errors.New("unreachable")
			}
			return nil
		})
		done <- selected
	}()

	seen := make(map[string]bool)
	for range 3 {
		select {
		case ip := <-started:
			seen[ip] = true
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("candidates were not probed concurrently")
		}
	}
	close(release)
	selected := <-done
	if len(seen) != 3 {
		t.Fatalf("probed candidates = %v", seen)
	}
	if len(selected.Entries) != 1 || selected.Entries[0].SafeIP != "192.0.2.2" {
		t.Fatalf("selected entries = %+v", selected.Entries)
	}
	if len(selected.Entries[0].SafeIPs) != 0 {
		t.Fatal("selected hosts entry should contain only the chosen IP")
	}
}

func TestSelectHealthyTransportFallbackKeepsFirstWhenAllUnhealthy(t *testing.T) {
	fallback := config.TransportFallback{Enabled: true, Entries: []config.TransportFallbackEntry{{
		SafeIP:  "192.0.2.1",
		SafeIPs: []string{"192.0.2.2"},
		Domains: []string{"gateway.example.org"},
	}}}
	selected, unavailable := selectHealthyTransportFallback(context.Background(), fallback, func(context.Context, string, string) error {
		return errors.New("unreachable")
	})
	if len(selected.Entries) != 1 || selected.Entries[0].SafeIP != "192.0.2.1" {
		t.Fatalf("first candidate must be kept: %+v", selected.Entries)
	}
	if len(unavailable) != 1 || unavailable[0].Domains[0] != "gateway.example.org" {
		t.Fatalf("unavailable entries = %+v", unavailable)
	}
}
