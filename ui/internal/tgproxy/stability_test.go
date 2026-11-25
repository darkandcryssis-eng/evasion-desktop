package tgproxy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestStabilitySelectionBeatsLatency(t *testing.T) {
	r := newRouter(nil)
	candidates := routesFor(2, false)
	flaky := candidates[0]
	stable := candidates[1]
	r.known[flaky.id] = flaky
	r.known[stable.id] = stable

	// Flaky route is much faster (20ms) but dropped mid-stream twice.
	r.success(flaky.id, 20*time.Millisecond)
	r.recordDrop(flaky, 10*time.Second, syscall.ECONNRESET)
	r.success(flaky.id, 20*time.Millisecond)
	r.recordDrop(flaky, 12*time.Second, syscall.ECONNRESET)
	// Even after recovering with a fast probe, its history still shows drops.
	r.success(flaky.id, 20*time.Millisecond)

	// Stable route is slower (250ms) but has held clean sessions without drops.
	r.success(stable.id, 250*time.Millisecond)
	r.recordCleanSession(stable.id, 2*time.Minute)

	best := r.bestCandidates(2, false, 2)
	if len(best) < 2 {
		t.Fatalf("expected at least 2 candidates, got %d", len(best))
	}
	if best[0].id != stable.id {
		t.Fatalf("expected stable route %s ahead of flaky route %s, got %s", stable.id, flaky.id, best[0].id)
	}
}

func TestNonTLSBreakTriggersWSSOverTLSFallback(t *testing.T) {
	r := newRouter(nil, true)
	rawTCP := tcpRoute(2, false)
	wss := routesFor(2, false)[0]
	r.known[rawTCP.id] = rawTCP
	r.known[wss.id] = wss

	r.success(rawTCP.id, 15*time.Millisecond)
	r.success(wss.id, 180*time.Millisecond)
	r.recordDrop(rawTCP, 8*time.Second, syscall.ECONNRESET)
	// Even if rawTCP recovers immediately, preferTLS keeps WSS-over-TLS first.
	r.success(rawTCP.id, 15*time.Millisecond)

	best := r.bestCandidates(2, false, 3)
	if len(best) == 0 || !best[0].isEncryptedWSS() {
		t.Fatalf("expected WSS-over-TLS fallback route first, got %+v", best)
	}
}

func TestSeamlessSwitchKeepsClientAliveAcrossUpstreamBreak(t *testing.T) {
	v := vectors(t)[0]
	frame := unhex(t, v.Plain)
	var dials atomic.Int32
	droppedFirst := make(chan struct{})

	// First upstream echoes the first frame, then abruptly closes (simulating a
	// DPI reset). Second upstream handles subsequent frames cleanly.
	dial := func(ctx context.Context, _ route) (peer, error) {
		n := dials.Add(1)
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
			reversed := reverse(init[8:56])
			enc := ctr(reversed[:32], reversed[32:])
			reader := &cipher.StreamReader{S: dec, R: remote}
			for {
				hdr, sz, err := readPacketHeader(reader, plainInit[56])
				if err != nil {
					return
				}
				payload := make([]byte, sz)
				if _, err := io.ReadFull(reader, payload); err != nil {
					return
				}
				reply := append(hdr, payload...)
				enc.XORKeyStream(reply, reply)
				if _, err := writeAll(remote, reply); err != nil {
					return
				}
				if n == 1 {
					// Simulate abrupt disconnect after the first reply.
					select {
					case <-droppedFirst:
					default:
						close(droppedFirst)
					}
					return
				}
			}
		}()
		return &tcpPeer{local}, nil
	}

	s, err := New(Options{Secret: unhex(t, v.Secret), Dial: dial})
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
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))

	clientInit := unhex(t, v.ClientInit)
	secret := unhex(t, v.Secret)
	keyEnc := sha256.Sum256(append(append([]byte(nil), clientInit[8:40]...), secret...))
	clientEnc := ctr(keyEnc[:], clientInit[40:56])
	// Advance clientEnc past the 64-byte init header (matching protocol.go).
	clientEnc.XORKeyStream(make([]byte, 64), clientInit)
	reversed := reverse(clientInit[8:56])
	keyDec := sha256.Sum256(append(append([]byte(nil), reversed[:32]...), secret...))
	clientDec := ctr(keyDec[:], reversed[32:])

	// Send init + first frame.
	if _, err := writeAll(c, append(clientInit, unhex(t, v.ClientCipher)...)); err != nil {
		t.Fatal(err)
	}
	// Advance clientEnc past first frame too.
	clientEnc.XORKeyStream(make([]byte, len(frame)), frame)

	reply1 := make([]byte, len(frame))
	if _, err := io.ReadFull(c, reply1); err != nil {
		t.Fatalf("first reply failed: %v", err)
	}
	plain1 := make([]byte, len(reply1))
	clientDec.XORKeyStream(plain1, reply1)
	if !bytes.Equal(plain1, frame) {
		t.Fatal("first reply mismatch")
	}

	// Wait for first upstream to drop and proxy to seamlessly switch routes.
	select {
	case <-droppedFirst:
	case <-time.After(2 * time.Second):
		t.Fatal("first upstream did not drop")
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.Snapshot().Switches == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.Snapshot().Switches == 0 {
		t.Fatalf("expected seamless switch, snapshot=%+v", s.Snapshot())
	}

	// Send a second MTProto frame over the SAME client TCP connection!
	secondCipher := make([]byte, len(frame))
	clientEnc.XORKeyStream(secondCipher, frame)
	if _, err := writeAll(c, secondCipher); err != nil {
		t.Fatalf("second write failed after switch: %v", err)
	}
	reply2 := make([]byte, len(frame))
	if _, err := io.ReadFull(c, reply2); err != nil {
		t.Fatalf("second reply failed after switch: %v", err)
	}
	plain2 := make([]byte, len(reply2))
	clientDec.XORKeyStream(plain2, reply2)
	if !bytes.Equal(plain2, frame) {
		t.Fatal("second reply mismatch after seamless switch")
	}

	snap := s.Snapshot()
	if snap.Failures != 0 {
		t.Fatalf("recovered disconnect should not count as client failure, got %d", snap.Failures)
	}
	if len(snap.Disconnects) == 0 || !snap.Disconnects[0].Recovered {
		t.Fatalf("expected recovered disconnect journal entry, got %+v", snap.Disconnects)
	}
}

func TestSeamlessSwitchOnWriteErrorReplaysFrame(t *testing.T) {
	v := vectors(t)[0]
	frame := unhex(t, v.Plain)
	var dials atomic.Int32
	var writes atomic.Int32

	dial := func(ctx context.Context, _ route) (peer, error) {
		n := dials.Add(1)
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
			reversed := reverse(init[8:56])
			enc := ctr(reversed[:32], reversed[32:])
			reader := &cipher.StreamReader{S: dec, R: remote}
			for {
				hdr, sz, err := readPacketHeader(reader, plainInit[56])
				if err != nil {
					return
				}
				payload := make([]byte, sz)
				if _, err := io.ReadFull(reader, payload); err != nil {
					return
				}
				reply := append(hdr, payload...)
				enc.XORKeyStream(reply, reply)
				if _, err := writeAll(remote, reply); err != nil {
					return
				}
			}
		}()
		p := &tcpPeer{local}
		if n == 1 {
			return &failOnSecondWritePeer{peer: p, writes: &writes}, nil
		}
		return p, nil
	}

	s, err := New(Options{Secret: unhex(t, v.Secret), Dial: dial})
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
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))

	clientInit := unhex(t, v.ClientInit)
	secret := unhex(t, v.Secret)
	keyEnc := sha256.Sum256(append(append([]byte(nil), clientInit[8:40]...), secret...))
	clientEnc := ctr(keyEnc[:], clientInit[40:56])
	clientEnc.XORKeyStream(make([]byte, 64), clientInit)
	reversed := reverse(clientInit[8:56])
	keyDec := sha256.Sum256(append(append([]byte(nil), reversed[:32]...), secret...))
	clientDec := ctr(keyDec[:], reversed[32:])

	if _, err := writeAll(c, append(clientInit, unhex(t, v.ClientCipher)...)); err != nil {
		t.Fatal(err)
	}
	clientEnc.XORKeyStream(make([]byte, len(frame)), frame)
	reply1 := make([]byte, len(frame))
	if _, err := io.ReadFull(c, reply1); err != nil {
		t.Fatal(err)
	}
	clientDec.XORKeyStream(reply1, reply1)

	// Second write hits ECONNRESET on route 1 -> proxy replays it on route 2!
	secondCipher := make([]byte, len(frame))
	clientEnc.XORKeyStream(secondCipher, frame)
	if _, err := writeAll(c, secondCipher); err != nil {
		t.Fatal(err)
	}
	reply2 := make([]byte, len(frame))
	if _, err := io.ReadFull(c, reply2); err != nil {
		t.Fatalf("expected replayed second reply, got %v", err)
	}
	clientDec.XORKeyStream(reply2, reply2)
	if !bytes.Equal(reply2, frame) {
		t.Fatal("replayed frame mismatch")
	}
	if s.Snapshot().Switches == 0 {
		t.Fatal("expected write-error seamless switch")
	}
}

type failOnSecondWritePeer struct {
	peer
	writes *atomic.Int32
}

func (f *failOnSecondWritePeer) WritePacket(r io.Reader, size int64) error {
	// Write 1 = 64-byte init, Write 2 = firstFrame, Write 3 = second client frame.
	if f.writes.Add(1) >= 3 {
		return errors.New("write: connection reset by peer")
	}
	return f.peer.WritePacket(r, size)
}
