package tgproxy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func fakeTelegram(t *testing.T, expected []byte) dialFunc {
	t.Helper()
	return func(ctx context.Context, _ route) (peer, error) {
		local, remote := net.Pipe()
		go func() {
			defer remote.Close()
			_ = remote.SetDeadline(time.Now().Add(4 * time.Second))
			init := make([]byte, 64)
			if _, err := io.ReadFull(remote, init); err != nil {
				return
			}
			dec := ctr(init[8:40], init[40:56])
			plainInit := make([]byte, 64)
			dec.XORKeyStream(plainInit, init)
			reader := &cipher.StreamReader{S: dec, R: remote}
			header, size, err := readPacketHeader(reader, plainInit[56])
			if err != nil {
				return
			}
			payload := make([]byte, size)
			if _, err := io.ReadFull(reader, payload); err != nil {
				return
			}
			frame := append(header, payload...)
			if !bytes.Equal(frame, expected) {
				return
			}
			reversed := reverse(init[8:56])
			enc := ctr(reversed[:32], reversed[32:])
			enc.XORKeyStream(frame, frame)
			if _, err := writeAll(remote, frame); err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, remote)
		}()
		return &tcpPeer{local}, nil
	}
}

func TestLocalProxyRoundTripAndShutdown(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run(string([]byte{v.Protocol}), func(t *testing.T) {
			frame := unhex(t, v.Plain)
			s, err := New(Options{Secret: unhex(t, v.Secret), Dial: fakeTelegram(t, frame)})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Start(context.Background(), 0); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			c, err := net.DialTimeout("tcp", s.Snapshot().Address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = writeAll(c, append(unhex(t, v.ClientInit), unhex(t, v.ClientCipher)...))
			response := make([]byte, len(frame))
			if _, err := io.ReadFull(c, response); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(response, unhex(t, v.ClientReply)) {
				t.Fatal("end-to-end re-encryption failed")
			}
			// Wait for the writer's counters, which follow delivery to the local socket.
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				state := s.Snapshot()
				if state.BytesUp == uint64(len(frame)) && state.BytesDown == uint64(len(frame)) {
					break
				}
				time.Sleep(time.Millisecond)
			}
			state := s.Snapshot()
			if state.BytesUp != uint64(len(frame)) || state.BytesDown != uint64(len(frame)) || state.Active != 1 || state.Phase != "online" {
				t.Fatalf("incorrect live telemetry: %+v", state)
			}
			done := make(chan struct{})
			go func() { _ = s.Close(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("shutdown left a blocked relay")
			}
			if s.Snapshot().Active != 0 || s.Snapshot().Running {
				t.Fatal("shutdown left active clients")
			}
		})
	}
}

func TestRejectWrongSecretWithoutDialAndCancelListener(t *testing.T) {
	var called atomic.Int32
	s, _ := New(Options{Secret: make([]byte, 16), MaxClients: 1, Dial: func(context.Context, route) (peer, error) { called.Add(1); return nil, errors.New("unexpected dial") }})
	if err := s.Start(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := net.Dial("tcp", s.Snapshot().Address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	v := vectors(t)[0]
	_, _ = writeAll(c, unhex(t, v.ClientInit))
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("wrong secret kept open")
	}
	if called.Load() != 0 {
		t.Fatal("unauthenticated request reached Telegram")
	}
	ctx, cancel := context.WithCancel(context.Background())
	other, _ := New(Options{Secret: make([]byte, 16)})
	if err := other.Start(ctx, 0); err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for other.Snapshot().Running && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if other.Snapshot().Running {
		t.Fatal("context cancellation did not close listener")
	}
}

func TestConnectionLimitRejectsExtraClient(t *testing.T) {
	s, err := New(Options{Secret: make([]byte, 16), MaxClients: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	first, err := net.Dial("tcp", s.Snapshot().Address)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	deadline := time.Now().Add(time.Second)
	for len(s.slots) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.slots) != 1 {
		t.Fatal("first client was not accepted")
	}
	second, err := net.Dial("tcp", s.Snapshot().Address)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("extra client was not closed")
	}
	if s.Snapshot().Rejected != 1 || len(s.slots) != 1 {
		t.Fatal("connection limit or rejection telemetry failed")
	}
}

func TestNoFirstReplyClosesClientAndMarksRoute(t *testing.T) {
	s, _ := New(Options{Secret: unhex(t, vectors(t)[0].Secret), FirstReplyTimeout: 30 * time.Millisecond, Dial: func(ctx context.Context, _ route) (peer, error) {
		a, b := net.Pipe()
		go func() { defer b.Close(); _, _ = io.Copy(io.Discard, b) }()
		return &tcpPeer{a}, nil
	}})
	if err := s.Start(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := net.Dial("tcp", s.Snapshot().Address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	v := vectors(t)[0]
	_, _ = writeAll(c, append(unhex(t, v.ClientInit), unhex(t, v.ClientCipher)...))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("silent upstream kept open")
	}
	deadline := time.Now().Add(time.Second)
	for s.Snapshot().Failures == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.Snapshot().Failures != 1 {
		t.Fatal("silent route failure not counted")
	}
	found := false
	for _, route := range s.Routes() {
		if route.Failures > 0 {
			found = true
			if route.Code != "mtproto_timeout" {
				t.Fatalf("first reply timeout reported as %s", route.Code)
			}
		}
	}
	if !found {
		t.Fatal("failed route missing")
	}
}

type initFailurePeer struct{ err error }

func (p initFailurePeer) Read([]byte) (int, error)           { return 0, io.EOF }
func (p initFailurePeer) WritePacket(io.Reader, int64) error { return p.err }
func (p initFailurePeer) Close() error                       { return nil }

func TestRelayHandshakeFailureRetainsCause(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code string
	}{
		{"timeout", context.DeadlineExceeded, "channel_timeout"},
		{"closed", io.ErrClosedPipe, "channel_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := vectors(t)[0]
			s, err := New(Options{Secret: unhex(t, v.Secret), Dial: func(context.Context, route) (peer, error) { return initFailurePeer{err: tc.err}, nil }})
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Start(context.Background(), 0); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			c, err := net.DialTimeout("tcp", s.Snapshot().Address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			if _, err = writeAll(c, append(unhex(t, v.ClientInit), unhex(t, v.ClientCipher)...)); err != nil {
				t.Fatal(err)
			}
			if _, err = c.Read(make([]byte, 1)); err == nil {
				t.Fatal("failed relay kept client open")
			}
			deadline := time.Now().Add(time.Second)
			for s.Snapshot().Failures == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if s.Snapshot().Failures != 1 {
				t.Fatal("failure count missing")
			}
			for _, state := range s.Routes() {
				if state.Failures > 0 {
					if state.Code != tc.code {
						t.Fatalf("got %s, want %s", state.Code, tc.code)
					}
					return
				}
			}
			t.Fatal("failed route missing")
		})
	}
}

func TestSilentRouteRetriesWithoutClientReconnect(t *testing.T) {
	v := vectors(t)[0]
	frame := unhex(t, v.Plain)
	healthy := fakeTelegram(t, frame)
	var calls atomic.Int32
	s, err := New(Options{Secret: unhex(t, v.Secret), FirstReplyTimeout: 30 * time.Millisecond, Dial: func(ctx context.Context, candidate route) (peer, error) {
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
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := writeAll(client, append(unhex(t, v.ClientInit), unhex(t, v.ClientCipher)...)); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(frame))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal("silent route was not replaced:", err)
	}
	if !bytes.Equal(response, unhex(t, v.ClientReply)) {
		t.Fatal("retry changed the MTProto response")
	}
	if calls.Load() < 2 {
		t.Fatal("only one upstream route was attempted")
	}
	if s.Snapshot().Failures != 0 {
		t.Fatal("a recovered route failure was visible as a client failure")
	}
}
