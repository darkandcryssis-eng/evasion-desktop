package tgproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

type noncePeer struct {
	init     []byte
	response *bytes.Reader
	bad      bool
}

func (p *noncePeer) Close() error               { return nil }
func (p *noncePeer) Read(b []byte) (int, error) { return p.response.Read(b) }
func (p *noncePeer) WritePacket(reader io.Reader, size int64) error {
	b, err := io.ReadAll(io.LimitReader(reader, size))
	if err != nil {
		return err
	}
	if p.init == nil {
		p.init = b
		return nil
	}
	dec := ctr(p.init[8:40], p.init[40:56])
	dec.XORKeyStream(make([]byte, 64), make([]byte, 64))
	dec.XORKeyStream(b, b)
	response := make([]byte, 41)
	response[0] = 10
	binary.LittleEndian.PutUint32(response[21:25], 0x05162463)
	copy(response[25:41], b[25:41])
	if p.bad {
		response[25] ^= 1
	}
	reversed := reverse(p.init[8:56])
	enc := ctr(reversed[:32], reversed[32:])
	enc.XORKeyStream(response, response)
	p.response = bytes.NewReader(response)
	return nil
}

func TestProbeChecksNonce(t *testing.T) {
	for _, bad := range []bool{false, true} {
		err := probePeer(context.Background(), &noncePeer{bad: bad}, route{dc: 2})
		if (err != nil) != bad {
			t.Fatalf("bad=%v: %v", bad, err)
		}
	}
}

func TestProbeUsesRequestedDataCenter(t *testing.T) {
	for _, key := range []poolKey{{4, false}, {4, true}, {203, true}} {
		p := &noncePeer{}
		r := newRouter(func(context.Context, route) (peer, error) { return p, nil })
		r.probeRoutes(t.Context(), key.dc, key.media, 1)
		if len(p.init) != 64 {
			t.Fatalf("no handshake for %+v", key)
		}
		decoded := make([]byte, 64)
		ctr(p.init[8:40], p.init[40:56]).XORKeyStream(decoded, p.init)
		want := int16(key.dc)
		if key.media {
			want = -want
		}
		if got := int16(binary.LittleEndian.Uint16(decoded[60:62])); got != want {
			t.Fatalf("probe used DC %d, want %d", got, want)
		}
		if !r.health[routesFor(key.dc, key.media)[0].id].success {
			t.Fatalf("verified reply was not recorded for %+v", key)
		}
	}
}

func TestRouteFailureExplainsFailedStage(t *testing.T) {
	for _, tt := range []struct {
		err  error
		code string
	}{
		{&net.DNSError{Err: "private-host"}, "dns_error"},
		{context.DeadlineExceeded, "channel_timeout"},
		{protocolProbeError{context.DeadlineExceeded}, "mtproto_timeout"},
		{protocolProbeError{io.EOF}, "mtproto_error"},
	} {
		code, _ := routeFailure(tt.err)
		if code != tt.code {
			t.Fatalf("got %s, want %s", code, tt.code)
		}
	}
}

func TestProbeCancellationClosesBlockedPeer(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := probePeer(ctx, &tcpPeer{Conn: client}, tcpRoute(2, false))
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("probe did not stop: %v", err)
	}
}

func TestRouteStateDistinguishesOpenAndVerified(t *testing.T) {
	r := newRouter(func(context.Context, route) (peer, error) { return &noncePeer{}, nil })
	candidate := routesFor(2, false)[0]
	_, err := r.dialRoute(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	find := func() RouteStatus {
		for _, v := range r.snapshot() {
			if v.ID == candidate.id {
				return v
			}
		}
		t.Fatal("missing route")
		return RouteStatus{}
	}
	if find().Status != "opened" {
		t.Fatal("opened route was considered verified")
	}
	r.success(candidate.id, time.Millisecond)
	if find().Status != "verified" {
		t.Fatal("missing verification")
	}
	r.failure(candidate.id)
	if find().Status != "cooldown" {
		t.Fatal("missing cooldown")
	}
}

func TestReopenedRouteClearsStaleErrorWithoutClaimingVerification(t *testing.T) {
	r := newRouter(func(context.Context, route) (peer, error) { return &noncePeer{}, nil })
	candidate := routesFor(2, false)[0]
	r.failure(candidate.id, context.DeadlineExceeded)
	if h := r.health[candidate.id]; h.code != "channel_timeout" || h.failures != 1 {
		t.Fatal("failure not recorded", h)
	}
	if _, err := r.dialRoute(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	for _, state := range r.snapshot() {
		if state.ID == candidate.id {
			if state.Status != "opened" || state.Code != "" || state.Reason != "" || state.Failures != 1 {
				t.Fatal("stale error or false verification", state)
			}
			return
		}
	}
	t.Fatal("reopened route missing")
}

func TestLiveRouteDiagnostics(t *testing.T) {
	if os.Getenv("EVASION_SERVICES_LIVE") != "1" {
		t.Skip("opt-in public route probes")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 16*time.Second)
	defer cancel()
	for _, r := range CheckRoutes(ctx, true) {
		t.Logf("%s: %s (%d ms)", r.ID, r.Status, r.LatencyMS)
	}
}
