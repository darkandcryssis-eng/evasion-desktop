package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type fakeWARP struct {
	dials atomic.Int32
	fail  atomic.Bool
}

func (f *fakeWARP) DialContext(context.Context, string, string) (net.Conn, error) {
	f.dials.Add(1)
	if f.fail.Load() {
		return nil, errors.New("tunnel down")
	}
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}
func (f *fakeWARP) Close() error { return nil }

func newTestWARPRoute(direct func(context.Context, string, string) (net.Conn, error), tn *fakeWARP, opened *atomic.Int32) *warpRoute {
	r := newWARPRoute("", direct, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.open = func(context.Context) (warpDialer, error) {
		opened.Add(1)
		return tn, nil
	}
	return r
}

func waitTunnel(t *testing.T, r *warpRoute) {
	t.Helper()
	for range 200 {
		r.mu.Lock()
		ready := r.tunnel != nil
		r.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("туннель не поднят")
}

func TestWARPRouteTakesUnreachableHost(t *testing.T) {
	var direct, opened atomic.Int32
	tn := &fakeWARP{}
	r := newTestWARPRoute(func(context.Context, string, string) (net.Conn, error) {
		direct.Add(1)
		return nil, &net.OpError{Op: "dial", Err: errors.New("i/o timeout")}
	}, tn, &opened)
	ctx := context.Background()
	if _, err := r.Dial(ctx, "tcp", "images-ext-1.discordapp.net:443"); err == nil {
		t.Fatal("первый отказ не должен уводить узел в туннель")
	}
	if opened.Load() != 0 {
		t.Fatal("туннель поднят после одного отказа")
	}
	_, _ = r.Dial(ctx, "tcp", "images-ext-1.discordapp.net:443")
	waitTunnel(t, r)
	conn, err := r.Dial(ctx, "tcp", "images-ext-1.discordapp.net:443")
	if err != nil {
		t.Fatalf("узел не пошёл через туннель: %v", err)
	}
	_ = conn.Close()
	if direct.Load() != 2 || tn.dials.Load() != 1 {
		t.Fatalf("прямых соединений %d, через туннель %d", direct.Load(), tn.dials.Load())
	}
	// Другой узел туннель не трогает.
	_, _ = r.Dial(ctx, "tcp", "discord.com:443")
	if tn.dials.Load() != 1 {
		t.Fatal("в туннель ушёл узел без срывов")
	}
}

func TestWARPRouteIgnoresDNSAndReturnsAfterTTL(t *testing.T) {
	var opened atomic.Int32
	tn := &fakeWARP{}
	failing := atomic.Bool{}
	r := newTestWARPRoute(func(context.Context, string, string) (net.Conn, error) {
		if failing.Load() {
			return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
		}
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}, tn, &opened)
	now := time.Now()
	r.now = func() time.Time { return now }
	ctx := context.Background()
	failing.Store(true)
	for range 5 {
		_, _ = r.Dial(ctx, "tcp", "telemetry.discord.com:443")
	}
	if opened.Load() != 0 {
		t.Fatal("ошибка DNS увела узел в туннель")
	}
	failing.Store(false)
	for i := range warpFailLimit {
		now = now.Add(warpStallGap + time.Second)
		r.Stall(ctx, "cdn.discordapp.com")
		if i < warpFailLimit-1 && opened.Load() != 0 {
			t.Fatalf("туннель поднят после %d зависаний", i+1)
		}
	}
	waitTunnel(t, r)
	if conn, err := r.Dial(ctx, "tcp", "cdn.discordapp.com:443"); err != nil || tn.dials.Load() != 1 {
		t.Fatalf("узел после зависаний не пошёл через туннель: %v", err)
	} else {
		_ = conn.Close()
	}
	now = now.Add(warpHostTTL + time.Second)
	if conn, err := r.Dial(ctx, "tcp", "cdn.discordapp.com:443"); err != nil || tn.dials.Load() != 1 {
		t.Fatalf("после срока узел не вернулся на прямой путь: %v", err)
	} else {
		_ = conn.Close()
	}
}

func TestWARPRouteFallsBackWhenTunnelBroken(t *testing.T) {
	var opened atomic.Int32
	tn := &fakeWARP{}
	r := newTestWARPRoute(func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}, tn, &opened)
	now := time.Now()
	r.now = func() time.Time { return now }
	ctx := context.Background()
	for range warpFailLimit {
		now = now.Add(warpStallGap + time.Second)
		r.Stall(ctx, "gateway.discord.gg")
	}
	waitTunnel(t, r)
	tn.fail.Store(true)
	for range warpBrokenDials {
		conn, err := r.Dial(ctx, "tcp", "gateway.discord.gg:443")
		if err != nil {
			t.Fatalf("при отказе туннеля соединение должно идти напрямую: %v", err)
		}
		_ = conn.Close()
	}
	r.mu.Lock()
	dropped := r.tunnel == nil
	r.mu.Unlock()
	if !dropped {
		t.Fatal("сломанный туннель не сброшен")
	}
}

func TestWARPPortsPutSavedFirst(t *testing.T) {
	ports := warpPorts("162.159.192.1:4500")
	if ports[0] != 4500 || len(ports) != len(warpPorts("engage.cloudflareclient.com:2408")) {
		t.Fatalf("порядок портов: %v", ports[:3])
	}
}
