package tgproxy

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func TestReplyTimeoutAdaptsToRouteLatency(t *testing.T) {
	base := 8 * time.Second
	if got := replyTimeoutFor(base, 0); got != base {
		t.Fatalf("no hint: got %v", got)
	}
	if got := replyTimeoutFor(base, 300*time.Millisecond); got != 2500*time.Millisecond {
		t.Fatalf("floor: got %v", got)
	}
	if got := replyTimeoutFor(base, time.Second); got != 4*time.Second {
		t.Fatalf("scaled: got %v", got)
	}
	if got := replyTimeoutFor(base, 10*time.Second); got != base {
		t.Fatalf("ceiling: got %v", got)
	}
}

func TestGuardianPassProbesUsedKeysAndWarmsPool(t *testing.T) {
	var dials atomic.Int64
	r := newRouter(func(context.Context, route) (peer, error) {
		dials.Add(1)
		return &noncePeer{}, nil
	})
	defer r.pool.close()
	s := &Server{router: r, usedKeys: map[poolKey]struct{}{{2, false}: {}}}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	defer s.cancel()
	s.guardianPass()
	// Проверка: маршруты прошли probe (nonce-рукопожатие) и подтверждены.
	verified := false
	r.mu.Lock()
	for id, h := range r.health {
		if h.success {
			verified = true
			_ = id
		}
	}
	r.mu.Unlock()
	if !verified {
		t.Fatal("guardian did not verify any route")
	}
	// Тёплый пул пополнен лучшим маршрутом.
	waitWarm(t, r)
	r.pool.mu.Lock()
	warm := len(r.pool.idle[poolKey{2, false}])
	r.pool.mu.Unlock()
	if warm == 0 {
		t.Fatal("guardian did not warm the pool")
	}
}

func TestGuardianSkipsUnusedDataCenters(t *testing.T) {
	var dials atomic.Int64
	r := newRouter(func(context.Context, route) (peer, error) {
		dials.Add(1)
		return &noncePeer{}, nil
	})
	defer r.pool.close()
	s := &Server{router: r, usedKeys: map[poolKey]struct{}{}}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	defer s.cancel()
	s.guardianPass()
	if dials.Load() != 0 {
		t.Fatal("guardian probed routes without traffic")
	}
}

func TestWarmBestPrefersVerifiedRoute(t *testing.T) {
	var dialed []string
	r := newRouter(func(_ context.Context, candidate route) (peer, error) {
		dialed = append(dialed, candidate.id)
		return &trackedPeer{}, nil
	})
	defer r.pool.close()
	candidates := routesFor(2, false)
	r.success(candidates[1].id, 50*time.Millisecond)
	r.success(candidates[0].id, 900*time.Millisecond)
	r.warmBest(2, false)
	waitWarm(t, r)
	r.pool.mu.Lock()
	items := r.pool.idle[poolKey{2, false}]
	r.pool.mu.Unlock()
	if len(items) == 0 {
		t.Fatal("no warm sockets")
	}
	if items[0].route.id != candidates[1].id {
		t.Fatalf("warmed %s, want faster %s", items[0].route.id, candidates[1].id)
	}
}

func TestWarmBestSkipsUnverifiedRoutes(t *testing.T) {
	r := newRouter(func(context.Context, route) (peer, error) { return &trackedPeer{}, nil })
	defer r.pool.close()
	r.warmBest(2, false)
	waitWarm(t, r)
	r.pool.mu.Lock()
	warm := len(r.pool.idle[poolKey{2, false}])
	r.pool.mu.Unlock()
	if warm != 0 {
		t.Fatal("warmed unverified route")
	}
}

func TestWarmBestKeepsVerifiedMediaBackupWithinPoolBudget(t *testing.T) {
	r := newRouter(func(context.Context, route) (peer, error) { return &trackedPeer{}, nil })
	defer r.pool.close()
	candidates := routesFor(4, true)
	r.success(candidates[0].id, time.Millisecond)
	r.success(candidates[1].id, 500*time.Millisecond)
	r.warmBest(4, true)
	waitWarm(t, r)
	r.pool.mu.Lock()
	defer r.pool.mu.Unlock()
	counts := map[string]int{}
	for _, item := range r.pool.idle[poolKey{4, true}] {
		counts[item.route.id]++
	}
	if len(counts) != 2 || counts[candidates[0].id] != 2 || counts[candidates[1].id] != 2 || r.pool.count != warmPerRoute {
		t.Fatalf("expected two routes within existing media pool budget, got %v", counts)
	}
}

type silentPeer struct {
	done   chan struct{}
	closed atomic.Bool
}

func newSilentPeer() *silentPeer { return &silentPeer{done: make(chan struct{})} }

// Read молчит до закрытия: канал-«чёрная дыра».
func (p *silentPeer) Read([]byte) (int, error)           { <-p.done; return 0, io.EOF }
func (p *silentPeer) WritePacket(io.Reader, int64) error { return nil }
func (p *silentPeer) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		close(p.done)
	}
	return nil
}

func TestProbeRoutesMarksBlackholeRouteFailed(t *testing.T) {
	r := newRouter(func(context.Context, route) (peer, error) { return newSilentPeer(), nil })
	defer r.pool.close()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	r.probeRoutes(ctx, 2, false, 1)
	r.mu.Lock()
	h := r.health[routesFor(2, false)[0].id]
	r.mu.Unlock()
	if h.failures == 0 || !time.Now().Before(h.retryAt) {
		t.Fatal("blackhole route did not enter cooldown", h)
	}
}
