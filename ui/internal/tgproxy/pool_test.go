package tgproxy

import (
	"context"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestLiveWarmTelegramTransport(t *testing.T) {
	if os.Getenv("EVASION_TELEGRAM_LIVE") != "1" {
		t.Skip("opt-in unauthenticated public transport check")
	}
	r := newRouter(nil, true)
	defer r.pool.close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r.checkRoutes(ctx)
	start := time.Now()
	p, c, _, err := r.connect(ctx, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	cold := time.Since(start)
	probeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	err = probePeer(probeCtx, p, c)
	stop()
	p.Close()
	if err != nil {
		t.Fatal("cold protocol probe:", err)
	}
	r.success(c.id, cold)
	r.warm(2, false, c)
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		r.pool.mu.Lock()
		ready := len(r.pool.idle[poolKey{2, false}]) > 0
		r.pool.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	start = time.Now()
	p, c, _, err = r.connect(ctx, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	warm := time.Since(start)
	if !c.fromPool {
		t.Fatal("no ready connection was available")
	}
	probeCtx, stop = context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if err := probePeer(probeCtx, p, c); err != nil {
		t.Fatal("warm protocol probe:", err)
	}
	t.Logf("Verified resPQ. New TCP/TLS/WSS connection: %v; warm checkout: %v", cold, warm)
}

type trackedPeer struct{ closed atomic.Bool }

func (p *trackedPeer) Read([]byte) (int, error)           { return 0, io.EOF }
func (p *trackedPeer) WritePacket(io.Reader, int64) error { return nil }
func (p *trackedPeer) Close() error                       { p.closed.Store(true); return nil }
func (p *trackedPeer) Alive() bool                        { return !p.closed.Load() }

func waitWarm(t *testing.T, r *router) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.pool.mu.Lock()
		filling := false
		for _, v := range r.pool.filling {
			if v {
				filling = true
				break
			}
		}
		r.pool.mu.Unlock()
		if !filling {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("warm refill did not finish")
}

func TestWarmSocketsAreSingleUseAndCloseReleasesIdle(t *testing.T) {
	r := newRouter(func(context.Context, route) (peer, error) { return &trackedPeer{}, nil })
	c := routesFor(2, false)[0]
	r.success(c.id, time.Millisecond)
	r.warm(2, false, c)
	waitWarm(t, r)
	p, got, ok := r.takeWarm(context.Background(), 2, false)
	if !ok || !got.fromPool {
		t.Fatal("warm socket not used")
	}
	q, _, ok := r.takeWarm(context.Background(), 2, false)
	if !ok || p == q {
		t.Fatal("socket reused by two clients")
	}
	r.pool.close()
	if !p.(*trackedPeer).Alive() || !q.(*trackedPeer).Alive() {
		t.Fatal("pool closed a checked-out socket")
	}
	p.Close()
	q.Close()
	r.pool.mu.Lock()
	defer r.pool.mu.Unlock()
	if r.pool.count != 0 {
		t.Fatalf("pool leaked %d sockets", r.pool.count)
	}
}

func TestWarmPoolRejectsClosedExpiredAndFailedRoutes(t *testing.T) {
	for _, mode := range []string{"closed", "expired", "failed"} {
		t.Run(mode, func(t *testing.T) {
			r := newRouter(func(context.Context, route) (peer, error) { return &trackedPeer{}, nil })
			defer r.pool.close()
			c := routesFor(2, false)[0]
			r.success(c.id, time.Millisecond)
			r.warm(2, false, c)
			waitWarm(t, r)
			r.pool.mu.Lock()
			for _, v := range r.pool.idle[poolKey{2, false}] {
				if mode == "closed" {
					v.p.Close()
				}
				if mode == "expired" {
					v.created = time.Now().Add(-2 * warmTTL)
				}
			}
			r.pool.mu.Unlock()
			if mode == "failed" {
				r.failure(c.id)
			}
			if p, _, ok := r.takeWarm(context.Background(), 2, false); ok {
				p.Close()
				t.Fatal("stale warm connection handed out")
			}
		})
	}
}

func TestWarmRefillCancellationDoesNotHangShutdown(t *testing.T) {
	started := make(chan struct{}, 1)
	r := newRouter(func(ctx context.Context, _ route) (peer, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	c := routesFor(2, false)[0]
	r.warm(2, false, c)
	<-started
	done := make(chan struct{})
	go func() { r.pool.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("warm dial blocked shutdown")
	}
}

func TestWarmPoolCapacityIsBoundedAcrossDataCenters(t *testing.T) {
	r := newRouter(func(ctx context.Context, _ route) (peer, error) { <-ctx.Done(); return nil, ctx.Err() })
	for _, dc := range []int{1, 2, 3, 4, 5, 203} {
		for _, media := range []bool{false, true} {
			r.warm(dc, media, routesFor(dc, media)[0])
		}
	}
	r.pool.mu.Lock()
	count := r.pool.count
	r.pool.mu.Unlock()
	if count > warmLimit {
		t.Fatalf("too many reserved sockets: %d", count)
	}
	r.pool.close()
	r.pool.mu.Lock()
	defer r.pool.mu.Unlock()
	if r.pool.count != 0 {
		t.Fatal("refill reservation leaked")
	}
}
