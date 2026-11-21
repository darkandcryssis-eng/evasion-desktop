package tgproxy

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// Opt-in unauthenticated req_pq_multi; never opens a Telegram account/session.
func TestLiveTelegramMTProto(t *testing.T) {
	if os.Getenv("EVASION_TELEGRAM_LIVE") != "1" {
		t.Skip("set EVASION_TELEGRAM_LIVE=1 for a public Telegram transport check")
	}
	for _, protocol := range []byte{0xef, 0xee, 0xdd} {
		t.Run(fmt.Sprintf("%02x", protocol), func(t *testing.T) {
			started := time.Now()
			secret := make([]byte, 16)
			_, _ = rand.Read(secret)
			opts := Options{Secret: secret, Community: true}
			if endpoint := os.Getenv("EVASION_TELEGRAM_SOCKS"); endpoint != "" {
				opts.Tunnel = SOCKSDialer(endpoint)
			}
			if endpoint := os.Getenv("EVASION_TELEGRAM_CONNECT"); endpoint != "" {
				opts.Tunnel = CONNECTDialer(endpoint)
			}
			s, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Start(context.Background(), 0); err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			client, err := net.Dial("tcp", s.Snapshot().Address)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(40 * time.Second))
			init := make([]byte, 64)
			_, _ = rand.Read(init)
			for i := 56; i < 60; i++ {
				init[i] = protocol
			}
			binary.LittleEndian.PutUint16(init[60:62], 2)
			key := sha256.Sum256(append(append([]byte(nil), init[8:40]...), secret...))
			enc := ctr(key[:], init[40:56])
			encrypted := make([]byte, 64)
			enc.XORKeyStream(encrypted, init)
			wire := append([]byte(nil), init...)
			copy(wire[56:], encrypted[56:])
			reversed := reverse(init[8:56])
			key = sha256.Sum256(append(append([]byte(nil), reversed[:32]...), secret...))
			dec := ctr(key[:], reversed[32:])
			request := make([]byte, 40)
			binary.LittleEndian.PutUint64(request[8:16], uint64(time.Now().Unix())<<32|uint64(time.Now().Nanosecond())&^3)
			binary.LittleEndian.PutUint32(request[16:20], 20)
			binary.LittleEndian.PutUint32(request[20:24], 0xbe7e8ef1)
			_, _ = rand.Read(request[24:40])
			var frame []byte
			if protocol == 0xef {
				frame = append([]byte{10}, request...)
			} else {
				frame = make([]byte, 4)
				binary.LittleEndian.PutUint32(frame, uint32(len(request)))
				frame = append(frame, request...)
			}
			enc.XORKeyStream(frame, frame)
			if _, err := writeAll(client, append(wire, frame...)); err != nil {
				t.Fatal(err)
			}
			reader := &cipher.StreamReader{S: dec, R: client}
			_, size, err := readPacketHeader(reader, protocol)
			if err != nil {
				t.Fatalf("read reply: %v; telemetry: %+v", err, s.Snapshot())
			}
			response := make([]byte, size)
			if _, err := io.ReadFull(reader, response); err != nil {
				t.Fatal(err)
			}
			if len(response) < 40 || binary.LittleEndian.Uint32(response[20:24]) != 0x05162463 || !bytes.Equal(response[24:40], request[24:40]) {
				t.Fatalf("unexpected unauthenticated Telegram response: %x", response)
			}
			state := s.Snapshot()
			t.Logf("Verified Telegram resPQ via %s; total=%v channel=%dms", state.Route, time.Since(started).Round(time.Millisecond), state.DialMS)
			for _, route := range s.Routes() {
				if route.Kind == "VLESS" {
					t.Logf("VLESS route: %+v", route)
					if route.Failures > 0 {
						t.Logf("Proxy logs: %+v", state.Logs)
					}
				}
			}
		})
	}
}
