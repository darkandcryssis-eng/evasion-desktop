package tgproxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestSlowInitialDialDoesNotStartDuplicateRouteRace(t *testing.T) {
	v := vectors(t)[0]
	h, err := readHandshake(bytes.NewReader(unhex(t, v.ClientInit)), unhex(t, v.Secret))
	if err != nil {
		t.Fatal(err)
	}
	frame := unhex(t, v.Plain)
	healthy := fakeTelegram(t, frame)
	firstRoute := routesFor(h.dc, h.media)[0]
	started, duplicates := make(chan struct{}), make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	s, err := New(Options{Secret: unhex(t, v.Secret), Dial: func(ctx context.Context, candidate route) (peer, error) {
		if candidate.id != firstRoute.id {
			return nil, context.DeadlineExceeded
		}
		if calls.Add(1) == 1 {
			close(started)
		} else {
			select {
			case duplicates <- struct{}{}:
			default:
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return healthy(ctx, candidate)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		channel, err := s.openChannel(ctx, h, frame)
		if channel != nil {
			_ = channel.upstream.Close()
		}
		result <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("first route did not start")
	}
	select {
	case <-duplicates:
		t.Fatal("the pending transport dial started a duplicate race")
	case <-time.After(hedgeDelayFor(0) + 200*time.Millisecond):
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestBlackholeRouteIsHedgedBeforeReplyTimeout(t *testing.T) {
	v := vectors(t)[0]
	frame := unhex(t, v.Plain)
	healthy := fakeTelegram(t, frame)
	var calls atomic.Int32
	s, err := New(Options{Secret: unhex(t, v.Secret), FirstReplyTimeout: 5 * time.Second, Dial: func(ctx context.Context, candidate route) (peer, error) {
		if calls.Add(1) == 1 {
			return newSilentPeer(), nil
		}
		return healthy(ctx, candidate)
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	client, err := net.DialTimeout("tcp", s.Snapshot().Address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(4 * time.Second))
	started := time.Now()
	if _, err := writeAll(client, append(unhex(t, v.ClientInit), unhex(t, v.ClientCipher)...)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(frame))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal("blackhole route was not hedged:", err)
	}
	elapsed := time.Since(started)
	if !bytes.Equal(response, unhex(t, v.ClientReply)) {
		t.Fatal("hedge changed the MTProto response")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("first reply took %v; hedge should fire after ~%v, not the %v reply timeout", elapsed, hedgeDelayFor(0), 5*time.Second)
	}
	t.Logf("first reply via hedge after %v (reply timeout 5s)", elapsed)
	outrun := false
	for _, r := range s.Routes() {
		if r.Failures > 0 {
			outrun = true
		}
	}
	if !outrun {
		t.Fatal("outrun blackhole route was not demoted")
	}
}

func TestHedgeDelayBounds(t *testing.T) {
	for _, tc := range []struct{ hint, want time.Duration }{
		{0, time.Second},
		{50 * time.Millisecond, 500 * time.Millisecond},
		{300 * time.Millisecond, 900 * time.Millisecond},
		{2 * time.Second, 1500 * time.Millisecond},
	} {
		if got := hedgeDelayFor(tc.hint); got != tc.want {
			t.Fatalf("hedgeDelayFor(%v) = %v, want %v", tc.hint, got, tc.want)
		}
	}
}
