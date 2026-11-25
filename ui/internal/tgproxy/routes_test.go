package tgproxy

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type inertPeer struct{}

func (inertPeer) Read([]byte) (int, error)           { return 0, io.EOF }
func (inertPeer) WritePacket(io.Reader, int64) error { return nil }
func (inertPeer) Close() error                       { return nil }

func TestHedgedRouteCancelsStalledAlternative(t *testing.T) {
	canceled := make(chan struct{})
	r := newRouter(func(ctx context.Context, candidate route) (peer, error) {
		if candidate.address == "" {
			<-ctx.Done()
			close(canceled)
			return nil, ctx.Err()
		}
		return inertPeer{}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	p, candidate, _, err := r.connect(ctx, 2, false)
	if err != nil || p == nil || candidate.address == "" || time.Since(started) > time.Second {
		t.Fatalf("fast route not selected: %+v %v", candidate, err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("slow route was not canceled")
	}
}

func TestCommunityFallbackIsOptionalAndUsesRequestedDC(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var seen atomic.Bool
		r := newRouter(func(_ context.Context, candidate route) (peer, error) {
			if candidate.community {
				seen.Store(true)
				if !strings.HasPrefix(candidate.host, "kws203.") {
					return nil, errors.New("wrong community data center")
				}
				return inertPeer{}, nil
			}
			return nil, errors.New("direct route unavailable")
		}, enabled)
		p, candidate, _, err := r.connect(context.Background(), 203, false)
		if seen.Load() != enabled || (enabled && (err != nil || p == nil || !candidate.community)) || (!enabled && err == nil) {
			t.Fatalf("community=%v route=%+v error=%v", enabled, candidate, err)
		}
		if p != nil {
			_ = p.Close()
		}
	}
}

func TestRouteHealthSeparatesRegularMediaAndSharedDC(t *testing.T) {
	for _, pair := range [][2]route{
		{routesFor(4, false)[0], routesFor(4, true)[3]},
		{relayRoute(4, false, communityDomains[0]), relayRoute(4, true, communityDomains[0])},
		{tcpRoute(4, false), tcpRoute(4, true)},
		{routesFor(2, false)[0], routesFor(203, false)[0]},
	} {
		r := newRouter(nil)
		r.success(pair[0].id, time.Millisecond)
		r.failure(pair[1].id)
		if !r.health[pair[0].id].success || r.health[pair[1].id].failures != 1 {
			t.Fatalf("failure on %s changed health of %s", pair[1].id, pair[0].id)
		}
	}
}

func TestLocalDialQueueDoesNotCoolDownRoute(t *testing.T) {
	var dials atomic.Int32
	r := newRouter(func(context.Context, route) (peer, error) {
		dials.Add(1)
		return &noncePeer{}, nil
	})
	candidate := routesFor(4, true)[0]
	r.success(candidate.id, time.Millisecond)
	for range cap(r.background) {
		r.background <- struct{}{}
	}
	r.probeRoute(t.Context(), candidate, 20*time.Millisecond)
	h := r.health[candidate.id]
	if dials.Load() != 0 || !h.success || h.failures != 0 || !h.retryAt.IsZero() {
		t.Fatal("a local queue timeout was treated as a remote failure", h)
	}
}

func TestForegroundDialBudgetStartsAfterQueue(t *testing.T) {
	const budget = 100 * time.Millisecond
	candidate := routesFor(2, true)[0]
	r := newRouter(func(ctx context.Context, _ route) (peer, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) < budget/2 {
			return nil, errors.New("queue consumed the network dial budget")
		}
		return inertPeer{}, nil
	})
	for range cap(r.slots) {
		r.slots <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	timer := time.AfterFunc(2*budget, func() { <-r.slots })
	defer timer.Stop()
	p, _, err := r.dialRouteTimed(ctx, candidate, budget)
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Close()
}

func TestBackgroundDialsLeaveRoomForNewConnections(t *testing.T) {
	started := make(chan struct{}, 8)
	r := newRouter(func(ctx context.Context, candidate route) (peer, error) {
		if candidate.dc == 4 {
			started <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return inertPeer{}, nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	done := make(chan struct{}, cap(r.slots))
	defer func() {
		cancel()
		for range cap(done) {
			<-done
		}
	}()
	for range cap(done) {
		go func() {
			_, _ = r.dialBackground(ctx, routesFor(4, false)[0])
			done <- struct{}{}
		}()
	}
	for range cap(r.background) {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("background dials did not start")
		}
	}
	if got := len(r.slots); got != 0 {
		t.Fatalf("background dials occupied %d foreground slots", got)
	}
	p, err := r.dialRoute(ctx, routesFor(2, false)[0])
	if err != nil {
		t.Fatal("background dials blocked a client connection", err)
	}
	_ = p.Close()
}

func TestCooldownIsBoundedAndRecoveredRouteResetsFailures(t *testing.T) {
	var calls atomic.Int32
	r := newRouter(func(context.Context, route) (peer, error) { calls.Add(1); return nil, errors.New("offline") })
	_, _, _, _ = r.connect(context.Background(), 2, false)
	first := calls.Load()
	_, _, _, _ = r.connect(context.Background(), 2, false)
	if calls.Load() != first {
		t.Fatal("cooldown did not suppress repeated network attempts")
	}
	for range 20 {
		r.failure("test")
	}
	if time.Until(r.health["test"].retryAt) > 16*time.Second {
		t.Fatal("backoff exceeds recovery bound")
	}
	r.success("test", time.Millisecond)
	if r.health["test"].failures != 0 || !r.health["test"].retryAt.IsZero() {
		t.Fatal("successful route did not recover")
	}
}
