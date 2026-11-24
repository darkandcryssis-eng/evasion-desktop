package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakePAC struct {
	mu       sync.Mutex
	settings internetSettings
	notified int
}

func (f *fakePAC) Snapshot() (internetSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.settings, nil
}
func (f *fakePAC) SetAutoConfigURL(url string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.settings.AutoConfigURL = url
	return nil
}
func (f *fakePAC) Notify() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notified++
	return nil
}
func (f *fakePAC) url() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.settings.AutoConfigURL
}

func newTestSiteReserve(t *testing.T, pac *fakePAC) (*siteReserve, *fakeWARP) {
	t.Helper()
	var opened atomic.Int32
	tn := &fakeWARP{}
	route := newTestWARPRoute(func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}, tn, &opened)
	s := newSiteReserve(context.Background(), route, pac, "127.0.0.1:17657", slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(s.Close)
	return s, tn
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for range 400 {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(what)
}

func TestSiteReserveMovesFrozenSiteToTunnel(t *testing.T) {
	pac := &fakePAC{}
	s, tn := newTestSiteReserve(t, pac)
	s.Stall("frozen.example.com", false)
	s.Stall("frozen.example.com", false)
	if pac.url() != "" {
		t.Fatal("сценарий прописан до порога зависаний")
	}
	// Не считаются: Discord и YouTube, российские сайты, адреса, мусор.
	for range 5 {
		s.Stall("discord.com", true)
		s.Stall("www.youtube.com", false)
		s.Stall("yandex.ru", false)
		s.Stall("10.0.0.1", false)
		s.Stall("bad\"host.com", false)
	}
	s.Stall("Frozen.Example.com.", false)
	waitFor(t, "сценарий не прописан", func() bool { return strings.HasPrefix(pac.url(), "http://127.0.0.1:17657/proxy.pac?v=") })
	body := s.PAC()
	if !strings.Contains(body, `host == "frozen.example.com"`) || !strings.Contains(body, `"PROXY 127.0.0.1:17657; DIRECT"`) {
		t.Fatalf("сценарий без сайта или без прямого запаса:\n%s", body)
	}
	for _, alien := range []string{"discord.com", "yandex.ru", "10.0.0.1", "bad"} {
		if strings.Contains(body, alien) {
			t.Fatalf("в сценарий попал %q:\n%s", alien, body)
		}
	}
	conn, err := s.route.Dial(context.Background(), "tcp", "frozen.example.com:443")
	if err != nil || tn.dials.Load() != 1 {
		t.Fatalf("сайт не пошёл через туннель: %v", err)
	}
	_ = conn.Close()
	first := pac.url()
	for range siteStallLimit {
		s.Stall("second.example.org", false)
	}
	waitFor(t, "адрес сценария не сменился для второго сайта", func() bool { return pac.url() != first && pac.url() != "" })
	s.Close()
	if pac.url() != "" {
		t.Fatalf("сценарий не убран при выходе: %q", pac.url())
	}
}

func TestSiteReserveKeepsForeignProxy(t *testing.T) {
	pac := &fakePAC{settings: internetSettings{AutoConfigURL: "http://corp.example/proxy.pac"}}
	s, _ := newTestSiteReserve(t, pac)
	for range siteStallLimit {
		s.Stall("frozen.example.com", false)
	}
	waitFor(t, "сайт не обработан", func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.refused
	})
	s.Close()
	if pac.url() != "http://corp.example/proxy.pac" {
		t.Fatalf("чужой сценарий изменён: %q", pac.url())
	}
}

func TestSiteReserveRemovesStaleScript(t *testing.T) {
	pac := &fakePAC{settings: internetSettings{AutoConfigURL: "http://127.0.0.1:17657/proxy.pac?v=7"}}
	newTestSiteReserve(t, pac)
	if pac.url() != "" {
		t.Fatalf("запись прошлого запуска не снята: %q", pac.url())
	}
}

func TestEmptySitePACIsDirect(t *testing.T) {
	s, _ := newTestSiteReserve(t, &fakePAC{})
	if body := s.PAC(); strings.Contains(body, "PROXY") || !strings.Contains(body, `return "DIRECT"`) {
		t.Fatalf("пустой сценарий:\n%s", body)
	}
}

func TestSiteReserveWaitsLongerUnderDesync(t *testing.T) {
	pac := &fakePAC{}
	s, _ := newTestSiteReserve(t, pac)
	for range siteDesyncLimit - 1 {
		s.Stall("wide.example.com", true)
	}
	time.Sleep(50 * time.Millisecond)
	if pac.url() != "" {
		t.Fatal("сайт под приёмом ушёл в туннель раньше, чем отработала ротация")
	}
	s.Stall("wide.example.com", true)
	waitFor(t, "сайт под приёмом не ушёл в туннель", func() bool { return pac.url() != "" })
}
