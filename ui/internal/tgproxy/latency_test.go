package tgproxy

import (
	"context"
	"testing"
	"time"
)

func TestColdRelayStartsWithoutWaitingForBlockedDirectRoutes(t *testing.T) {
	r := newRouter(func(ctx context.Context, c route) (peer, error) {
		if c.community {
			return inertPeer{}, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}, true)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	p, c, _, err := r.connect(ctx, 2, false)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	t.Logf("First relay connection: %v", elapsed)
	if !c.community || elapsed > 250*time.Millisecond {
		t.Fatalf("healthy relay delayed by blocked paths: %v", elapsed)
	}
}

func TestTCPFallbackRunsWhileWSSHandshakeIsStalled(t *testing.T) {
	r := newRouter(func(ctx context.Context, c route) (peer, error) {
		if c.tcp {
			return inertPeer{}, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	p, c, _, err := r.connect(ctx, 2, false)
	if err != nil {
		t.Fatalf("TCP never got a chance: %v", err)
	}
	defer p.Close()
	if !c.tcp || time.Since(start) > 750*time.Millisecond {
		t.Fatal("TCP fallback was delayed")
	}
}
